package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type paramCheck struct {
	url   string
	param string
}

type Result struct {
	URL          string   `json:"url"`
	Param        string   `json:"param"`
	Unfiltered   []string `json:"unfiltered"`
	SQLInjection bool     `json:"sql_injection"`
}

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
}

var dbErrorPatterns = map[string][]string{
	"PostgreSQL": {"PSQLException", "ERROR:", "unterminated quoted string", "syntax error at or near"},
	"Oracle":     {"ORA-", "PLS-", "ORA-00933", "ORA-01756"},
	"MSSQL":      {"SQLException", "Incorrect syntax near", "Unclosed quotation mark"},
	"Generic":    {"SQL syntax"},
}

func main() {
	var inputFile string
	var outputFile string
	var numWorkers int
	var jsonOutput bool
	flag.StringVar(&inputFile, "f", "", "file containing URLs to process")
	flag.StringVar(&outputFile, "o", "", "file to write output to")
	flag.IntVar(&numWorkers, "w", 40, "number of worker goroutines")
	flag.BoolVar(&jsonOutput, "j", false, "output results in JSON format")
	flag.Parse()

	if numWorkers < 1 {
		fmt.Fprintf(os.Stderr, "number of workers must be at least 1\n")
		os.Exit(1)
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var scanner *bufio.Scanner
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening input file %s: %s\n", inputFile, err)
			os.Exit(1)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var out *os.File
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file %s: %s\n", outputFile, err)
			os.Exit(1)
		}
		defer file.Close()
		out = file
	} else {
		out = os.Stdout
	}

	results := []Result{}
	initialChecks := make(chan paramCheck, numWorkers)

	appendChecks := makePool(initialChecks, numWorkers, func(c paramCheck, output chan paramCheck) {
		reflected, err := checkReflected(c.url)
		if err != nil {
			return
		}
		if len(reflected) == 0 {
			return
		}
		for _, param := range reflected {
			output <- paramCheck{c.url, param}
		}
	})

	charChecks := makePool(appendChecks, numWorkers, func(c paramCheck, output chan paramCheck) {
		wasReflected, isError, err := checkAppend(c.url, c.param, "iy3j4h234hjb23234")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s: %s\n", c.url, c.param, err)
			return
		}
		if wasReflected || isError {
			output <- paramCheck{c.url, c.param}
		}
	})

	done := makePool(charChecks, numWorkers, func(c paramCheck, output chan paramCheck) {
		output_of_url := []string{c.url, c.param}
		sqlInjection := false
		for _, char := range []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}"} {
			wasReflected, isError, err := checkAppend(c.url, c.param, char)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s with %s: %s\n", c.url, c.param, char, err)
				continue
			}
			if wasReflected {
				output_of_url = append(output_of_url, char)
			}
			if isError {
				sqlInjection = true
			}
		}
		if len(output_of_url) > 2 || sqlInjection {
			result := Result{
				URL:          output_of_url[0],
				Param:        output_of_url[1],
				Unfiltered:   output_of_url[2:],
				SQLInjection: sqlInjection,
			}
			// Real-time output
			if jsonOutput {
				jsonData, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					fmt.Fprintf(os.Stderr, "error marshaling JSON for %s: %s\n", c.url, err)
				} else {
					fmt.Fprintln(out, string(jsonData))
				}
			} else {
				if result.SQLInjection {
					fmt.Fprintf(out, "URL: %s Param: %s [Possible SQL Injection] Unfiltered: %v\n", result.URL, result.Param, result.Unfiltered)
				} else {
					fmt.Fprintf(out, "URL: %s Param: %s Unfiltered: %v\n", result.URL, result.Param, result.Unfiltered)
				}
			}
			results = append(results, result)
		}
	})

	for scanner.Scan() {
		initialChecks <- paramCheck{url: scanner.Text()}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %s\n", err)
		os.Exit(1)
	}

	close(initialChecks)
	<-done

	// Optional: Print a message if no vulnerabilities were found
	if len(results) == 0 {
		fmt.Fprintln(out, "No vulnerabilities found.")
	}
}

func checkReflected(targetURL string) ([]string, error) {
	out := make([]string, 0)
	resp, err := doRequestWithRetries("GET", targetURL, nil, 3)
	if err != nil {
		return out, err
	}
	if resp.Body == nil {
		return out, fmt.Errorf("nil response body")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
	if err != nil {
		return out, err
	}
	if strings.HasPrefix(resp.Status, "3") {
		return out, nil
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return out, nil
	}

	body := string(b)
	u, err := url.Parse(targetURL)
	if err != nil {
		return out, err
	}

	for key, vv := range u.Query() {
		for _, v := range vv {
			if !strings.Contains(body, v) {
				continue
			}
			out = append(out, key)
		}
	}
	return out, nil
}

func checkAppend(targetURL, param, suffix string) (bool, bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, false, err
	}
	qs := u.Query()
	val := qs.Get(param)
	qs.Set(param, val+suffix)
	u.RawQuery = qs.Encode()

	// Perform base request for comparison
	baseResp, err := doRequestWithRetries("GET", targetURL, nil, 3)
	if err != nil {
		return false, false, err
	}
	if baseResp.Body == nil {
		return false, false, fmt.Errorf("nil base response body")
	}
	defer baseResp.Body.Close()
	baseStatusCode := baseResp.StatusCode

	// Perform test request with suffix
	resp, err := doRequestWithRetries("GET", u.String(), nil, 3)
	if err != nil {
		return false, false, err
	}
	if resp.Body == nil {
		return false, false, fmt.Errorf("nil response body")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, false, err
	}

	bodyStr := string(b)
	isError := false
	for _, patterns := range dbErrorPatterns {
		for _, pattern := range patterns {
			if strings.Contains(bodyStr, pattern) {
				isError = true
				break
			}
		}
	}
	// Check if server error is false positive (if base request also returns 500)
	if resp.StatusCode >= 500 && baseStatusCode >= 500 {
		isError = false
	}

	if strings.HasPrefix(resp.Status, "3") {
		return false, isError, nil
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return false, isError, nil
	}

	if strings.Contains(bodyStr, suffix) {
		return true, isError, nil
	}

	return false, isError, nil
}

func doRequestWithRetries(method, urlStr string, body io.Reader, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error
	for retries := 0; retries < maxRetries; retries++ {
		req, err := http.NewRequest(method, urlStr, body)
		if err != nil {
			return nil, err
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		resp, err = httpClient.Do(req)
		if err == nil && resp != nil {
			return resp, nil
		}
		time.Sleep(time.Second * time.Duration(retries+1))
	}
	return nil, fmt.Errorf("failed after %d retries: %v", maxRetries, err)
}

type workerFunc func(paramCheck, chan paramCheck)

func makePool(input chan paramCheck, numWorkers int, fn workerFunc) chan paramCheck {
	var wg sync.WaitGroup
	output := make(chan paramCheck)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			for c := range input {
				fn(c, output)
			}
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	return output
}

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
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

func main() {
	var inputFile string
	var outputFile string
	var numWorkers int
	flag.StringVar(&inputFile, "f", "", "file containing URLs to process")
	flag.StringVar(&outputFile, "o", "", "file to write output to")
	flag.IntVar(&numWorkers, "w", 40, "number of worker goroutines")
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
			if sqlInjection {
				fmt.Fprintf(out, "URL: %s Param: %s [Possible SQL Injection] Unfiltered: %v \n", output_of_url[0], output_of_url[1], output_of_url[2:])
			} else {
				fmt.Fprintf(out, "URL: %s Param: %s Unfiltered: %v \n", output_of_url[0], output_of_url[1], output_of_url[2:])
			}
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
}

func checkReflected(targetURL string) ([]string, error) {
	out := make([]string, 0)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return out, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	if resp.Body == nil {
		return out, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
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

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, false, err
	}
	if resp.Body == nil {
		return false, false, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, false, err
	}

	bodyStr := string(b)
	isError := strings.Contains(bodyStr, "SQL syntax") ||
		strings.Contains(bodyStr, "PSQLException") || // PostgreSQL
		strings.Contains(bodyStr, "ORA-") ||         // Oracle
		strings.Contains(bodyStr, "SQLException") || // MSSQL
		resp.StatusCode >= 500

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

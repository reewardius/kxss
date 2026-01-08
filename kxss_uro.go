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
	"path"
	"regexp"
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
	DBType       string   `json:"db_type,omitempty"` // Detected database type (if SQL injection found)
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
	"PostgreSQL": {
		"PostgreSQL query failed",
		"PSQLException",
		"org.postgresql.util.PSQLException",
		"ERROR: syntax error at or near",
		"ERROR: parser:",
		"unterminated quoted string",
		"pg_query(): Query failed:",
		"pg_exec() [:",
		"ERROR: column",
		"ERROR: relation",
		"ERROR: invalid input syntax",
		"ERROR: operator does not exist",
		"function pg_exec()",
		"Warning: pg_",
		"valid PostgreSQL result",
		"Npgsql.",
	},
	"MySQL": {
		"SQL syntax.*?MySQL",
		"Warning.*?mysql_.*",
		"MySQLSyntaxErrorException",
		"valid MySQL result",
		"check the manual that corresponds to your MySQL",
		"MySqlClient.",
		"MySqlException",
		"com.mysql.jdbc.exceptions",
		"You have an error in your SQL syntax",
		"supplied argument is not a valid MySQL",
		"mysql_fetch",
		"mysql_num_rows()",
		"MySQL Query fail",
		"Error Executing Database Query",
		"[MySQL][ODBC",
		"SQLSTATE[HY000]",
		"SQLSTATE[42000]",
		"SQLSTATE[23000]",
	},
	"MSSQL": {
		"SQLException",
		"SqlException",
		"System.Data.SqlClient.SqlException",
		"Unclosed quotation mark after the character string",
		"'80040e14'",
		"mssql_query()",
		"odbc_exec()",
		"Microsoft OLE DB Provider for ODBC Drivers",
		"Microsoft OLE DB Provider for SQL Server",
		"Incorrect syntax near",
		"Sintaxis incorrecta cerca de",
		"Syntax error in string in query expression",
		"ADODB.Field error",
		"BOF or EOF",
		"ADODB.Command",
		"JET Database Engine",
		"Access Database Engine",
		"Incorrect syntax",
		"SQLServer JDBC Driver",
		"com.microsoft.sqlserver.jdbc.SQLServerException",
		"[SQL Server]",
		"[SqlException",
		"System.Data.SqlClient.SqlException",
		"Warning.*?mssql_.*",
		"Driver.*? SQL[\\-\\_\\ ]*Server",
		"OLE DB.*? SQL Server",
	},
	"Oracle": {
		"ORA-[0-9][0-9][0-9][0-9]",
		"Oracle error",
		"Oracle.*?Driver",
		"Warning.*?oci_.*",
		"Warning.*?ora_.*",
		"oracle.jdbc.driver",
		"oracle.jdbc.OracleDriver",
		"OracleException",
		"SQL command not properly ended",
		"ORA-00933",
		"ORA-01756",
		"ORA-00942",
		"ORA-00936",
		"PLS-[0-9][0-9][0-9][0-9]",
		"TNS-[0-9][0-9][0-9][0-9]",
	},
	"SQLite": {
		"SQLite/JDBCDriver",
		"SQLite.Exception",
		"System.Data.SQLite.SQLiteException",
		"Warning.*?sqlite_.*",
		"sqlite3.OperationalError:",
		"SQLite error",
		"sqlite3.DatabaseError:",
		"SQLITE_ERROR",
		"unrecognized token",
		"near \".*?\": syntax error",
	},
	"Informix": {
		"Warning.*?ibase_.*",
		"com.informix.jdbc",
		"Dynamic SQL Error",
		"ISAM error",
		"IFX ODBC Driver",
	},
	"Sybase": {
		"Warning.*?sybase.*",
		"Sybase message",
		"Sybase.*?Server message",
		"SybSQLException",
		"com.sybase.jdbc",
	},
	"DB2": {
		"SQLSTATE[42000]",
		"DB2 SQL error",
		"db2_execute",
		"com.ibm.db2.jcc",
		"DB2Exception",
		"[IBM][CLI Driver][DB2",
	},
	"JDBC": {
		"java.sql.SQLException",
		"java.sql.SQLWarning",
		"SQLGrammarException",
		"DataIntegrityViolationException",
	},
	"PHP": {
		"Warning: mysql",
		"Warning: mysqli",
		"Warning: pg_",
		"Warning: oci_",
		"Warning: mssql_",
		"Warning: sqlite_",
		"Fatal error:",
		"Uncaught Error:",
		"Call to undefined function",
	},
	"ASP": {
		"Microsoft OLE DB Provider",
		"ADODB.Recordset",
		"ADODB.Command",
		"800a0e78",
		"800a0d5d",
	},
	"Generic": {
		"SQL syntax",
		"SQL command",
		"SQL statement",
		"Query failed",
		"SQL error",
		"Database error",
		"database error",
		"syntax error",
		"quoted string not properly terminated",
		"unexpected end of SQL command",
		"unterminated string literal",
		"invalid SQL statement",
		"SQL logic error",
		"unrecognized token",
		"SQL Error:",
		"Query Error:",
		"[ODBC",
		"supplied argument is not a valid",
		"Incorrect syntax",
	},
}

// URO-like filtering patterns and logic
var (
	// Useless extensions to filter out by default
	uselessExtensions = map[string]bool{
		"3g2": true, "3gp": true, "7z": true, "apk": true, "arj": true,
		"avi": true, "axd": true, "bmp": true, "css": true, "csv": true,
		"deb": true, "dll": true, "doc": true, "drv": true, "eot": true,
		"exe": true, "flv": true, "gif": true, "gifv": true, "gz": true,
		"ico": true, "iso": true, "jar": true, "jpeg": true, "jpg": true,
		"js": true, "less": true, "mov": true, "mp3": true, "mp4": true,
		"mpeg": true, "mpg": true, "msi": true, "ogg": true, "otf": true,
		"pdf": true, "png": true, "ppt": true, "pptx": true, "rar": true,
		"rpm": true, "scss": true, "svg": true, "swf": true, "sys": true,
		"tar": true, "tar.gz": true, "tif": true, "tiff": true, "ttf": true,
		"txt": true, "vob": true, "wav": true, "webm": true, "webp": true,
		"whl": true, "woff": true, "woff2": true, "xls": true, "xlsx": true,
		"zip": true,
	}

	// Patterns to detect content (blog posts, articles, etc.)
	contentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\.php/[a-z0-9-]+/[a-z0-9-]+`),
		regexp.MustCompile(`(?i)/20\d{2}/\d{2}/\d{2}/[a-z0-9-]+`),
		regexp.MustCompile(`(?i)/\d{4}/\d{2}/[a-z0-9-]+`),
		regexp.MustCompile(`(?i)/(article|post|blog|news|story)/[a-z0-9-]+`),
	}

	// Patterns for incremental URLs
	incrementalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/\d+/`),  // /cat/9/details.html, /cat/11/details.html
		regexp.MustCompile(`/\d+$`),  // /cat/9, /cat/11
		regexp.MustCompile(`(?i)[?&]page=\d+`),
		regexp.MustCompile(`(?i)[?&]p=\d+`),
	}
)

type URLFilter struct {
	seen               map[string]bool
	seenPaths          map[string]bool
	seenParamStructure map[string]bool
	mu                 sync.Mutex
	whitelist          map[string]bool
	blacklist          map[string]bool
	filters            map[string]bool
}

func NewURLFilter(whitelist, blacklist, filters []string) *URLFilter {
	uf := &URLFilter{
		seen:               make(map[string]bool),
		seenPaths:          make(map[string]bool),
		seenParamStructure: make(map[string]bool),
		whitelist:          make(map[string]bool),
		blacklist:          make(map[string]bool),
		filters:            make(map[string]bool),
	}

	for _, ext := range whitelist {
		uf.whitelist[strings.ToLower(ext)] = true
	}
	for _, ext := range blacklist {
		uf.blacklist[strings.ToLower(ext)] = true
	}
	for _, filter := range filters {
		uf.filters[strings.ToLower(filter)] = true
	}

	return uf
}

func (uf *URLFilter) ShouldProcess(rawURL string) bool {
	uf.mu.Lock()
	defer uf.mu.Unlock()

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check if already seen
	if uf.seen[rawURL] {
		return false
	}

	// Get extension
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(u.Path), "."))
	hasExt := ext != ""
	hasParams := len(u.Query()) > 0

	// Apply filters
	if uf.filters["hasparams"] && !hasParams {
		return false
	}
	if uf.filters["noparams"] && hasParams {
		return false
	}
	if uf.filters["hasext"] && !hasExt {
		return false
	}
	if uf.filters["noext"] && hasExt {
		return false
	}

	// Check whitelist (if provided, only allow these extensions)
	if len(uf.whitelist) > 0 && hasExt {
		if !uf.whitelist[ext] {
			return false
		}
	}

	// Check blacklist
	if len(uf.blacklist) > 0 {
		if uf.blacklist[ext] {
			return false
		}
	} else if !uf.filters["allexts"] {
		// Default: filter useless extensions
		if uselessExtensions[ext] {
			return false
		}
	}

	// Filter content patterns (blog posts, articles, etc.) unless keepcontent filter is set
	if !uf.filters["keepcontent"] {
		for _, pattern := range contentPatterns {
			if pattern.MatchString(u.Path) {
				return false
			}
		}
	}

	// Filter incremental URLs (e.g., /cat/9/details.html, /cat/11/details.html -> keep only first)
	for _, pattern := range incrementalPatterns {
		if pattern.MatchString(u.Path) {
			// Create normalized signature by replacing numbers
			normalized := regexp.MustCompile(`/\d+/`).ReplaceAllString(u.Path, "/N/")
			normalized = regexp.MustCompile(`/\d+$`).ReplaceAllString(normalized, "/N")
			
			baseSignature := u.Scheme + "://" + u.Host + normalized
			if uf.seenPaths[baseSignature] {
				return false
			}
			uf.seenPaths[baseSignature] = true
			break
		}
	}

	// Check for duplicate paths with different parameter values
	if hasParams {
		// Create a signature: protocol + host + path + sorted parameter keys
		paramKeys := make([]string, 0, len(u.Query()))
		for key := range u.Query() {
			paramKeys = append(paramKeys, key)
		}
		// Sort to ensure consistent signature
		sortedKeys := strings.Join(paramKeys, "&")
		signature := u.Scheme + "://" + u.Host + u.Path + "?" + sortedKeys

		// If we've seen this path+params structure before, skip it
		if uf.seenParamStructure[signature] {
			return false
		}
		uf.seenParamStructure[signature] = true
	} else {
		// For URLs without params, check if we've seen this exact path
		pathSignature := u.Scheme + "://" + u.Host + u.Path
		if uf.seenPaths[pathSignature] {
			return false
		}
		uf.seenPaths[pathSignature] = true
	}

	// Mark as seen
	uf.seen[rawURL] = true
	return true
}

func main() {
	var inputFile string
	var outputFile string
	var numWorkers int
	var jsonOutput bool
	var whitelist string
	var blacklist string
	var filtersStr string

	flag.StringVar(&inputFile, "f", "", "file containing URLs to process")
	flag.StringVar(&outputFile, "o", "", "file to write output to")
	flag.IntVar(&numWorkers, "w", 40, "number of worker goroutines")
	flag.BoolVar(&jsonOutput, "j", false, "output results in JSON format")
	flag.StringVar(&whitelist, "whitelist", "", "comma-separated whitelist of extensions")
	flag.StringVar(&blacklist, "blacklist", "", "comma-separated blacklist of extensions")
	flag.StringVar(&filtersStr, "filters", "", "comma-separated filters: hasparams,noparams,hasext,noext,allexts,keepcontent,keepslash")
	flag.Parse()

	if numWorkers < 1 {
		fmt.Fprintf(os.Stderr, "number of workers must be at least 1\n")
		os.Exit(1)
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Parse filter options
	var whitelistSlice, blacklistSlice, filtersSlice []string
	if whitelist != "" {
		whitelistSlice = strings.Split(whitelist, ",")
	}
	if blacklist != "" {
		blacklistSlice = strings.Split(blacklist, ",")
	}
	if filtersStr != "" {
		filtersSlice = strings.Split(filtersStr, ",")
	}

	urlFilter := NewURLFilter(whitelistSlice, blacklistSlice, filtersSlice)

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
		wasReflected, isError, _, err := checkAppend(c.url, c.param, "iy3j4h234hjb23234")
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
		detectedDB := ""
		
		for _, char := range []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}"} {
			wasReflected, isError, dbType, err := checkAppend(c.url, c.param, char)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error from checkAppend for url %s with param %s with %s: %s\n", c.url, c.param, char, err)
				continue
			}
			if wasReflected {
				output_of_url = append(output_of_url, char)
			}
			if isError {
				sqlInjection = true
				if dbType != "" && detectedDB == "" {
					detectedDB = dbType
				}
			}
		}
		if len(output_of_url) > 2 || sqlInjection {
			result := Result{
				URL:          output_of_url[0],
				Param:        output_of_url[1],
				Unfiltered:   output_of_url[2:],
				SQLInjection: sqlInjection,
				DBType:       detectedDB,
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
					dbInfo := ""
					if result.DBType != "" {
						dbInfo = fmt.Sprintf(" [%s]", result.DBType)
					}
					fmt.Fprintf(out, "URL: %s Param: %s [Possible SQL Injection]%s Unfiltered: %v\n", result.URL, result.Param, dbInfo, result.Unfiltered)
				} else {
					fmt.Fprintf(out, "URL: %s Param: %s Unfiltered: %v\n", result.URL, result.Param, result.Unfiltered)
				}
			}
			results = append(results, result)
		}
	})

	// Read URLs with filtering
	for scanner.Scan() {
		rawURL := strings.TrimSpace(scanner.Text())
		if rawURL == "" {
			continue
		}

		// Apply URO-like filtering before processing
		if urlFilter.ShouldProcess(rawURL) {
			initialChecks <- paramCheck{url: rawURL}
		}
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

func checkAppend(targetURL, param, suffix string) (bool, bool, string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, false, "", err
	}
	qs := u.Query()
	val := qs.Get(param)
	qs.Set(param, val+suffix)
	u.RawQuery = qs.Encode()

	// Perform base request for comparison
	baseResp, err := doRequestWithRetries("GET", targetURL, nil, 3)
	if err != nil {
		return false, false, "", err
	}
	if baseResp.Body == nil {
		return false, false, "", fmt.Errorf("nil base response body")
	}
	defer baseResp.Body.Close()
	baseStatusCode := baseResp.StatusCode

	// Perform test request with suffix
	resp, err := doRequestWithRetries("GET", u.String(), nil, 3)
	if err != nil {
		return false, false, "", err
	}
	if resp.Body == nil {
		return false, false, "", fmt.Errorf("nil response body")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, false, "", err
	}

	bodyStr := string(b)
	isError := false
	detectedDB := ""
	
	// Check for database error patterns (both exact match and regex)
	for dbType, patterns := range dbErrorPatterns {
		for _, pattern := range patterns {
			matched := false
			// Try exact match first (faster)
			if strings.Contains(bodyStr, pattern) {
				matched = true
			} else if strings.ContainsAny(pattern, ".*?[]()") {
				// Try regex match for patterns with special regex chars
				if regexMatched, _ := regexp.MatchString(pattern, bodyStr); regexMatched {
					matched = true
				}
			}
			
			if matched {
				isError = true
				detectedDB = dbType
				break
			}
		}
		if isError {
			break
		}
	}
	
	// Check if server error is false positive (if base request also returns 500)
	if resp.StatusCode >= 500 && baseStatusCode >= 500 {
		isError = false
		detectedDB = ""
	}
	
	// Additional check: if we get a 500 error with the suffix but not before
	if resp.StatusCode >= 500 && baseStatusCode < 500 {
		isError = true
		if detectedDB == "" {
			detectedDB = "Unknown (HTTP 500)"
		}
	}

	if strings.HasPrefix(resp.Status, "3") {
		return false, isError, detectedDB, nil
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return false, isError, detectedDB, nil
	}

	if strings.Contains(bodyStr, suffix) {
		return true, isError, detectedDB, nil
	}

	return false, isError, detectedDB, nil
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

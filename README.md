# kxss
`kxss` is a Go-based tool designed to identify reflected URL query parameters and detect unfiltered characters that could indicate potential Cross-Site Scripting (XSS) vulnerabilities. It processes URLs provided via standard input or a file, checks if query parameters are reflected in the HTTP response body, and tests for unfiltered characters that may allow XSS payloads. The tool is particularly useful in security testing workflows, such as those involving URL crawling with tools like katana.
#### Install
```
go mod init kxss.go && go mod tidy && go build -o kxss
```
#### Usage
```
Usage: ./kxss [options]

Input Options:
  -f string
        file containing URLs to process (default: stdin)

Output Options:
  -o string
        file to write output to (default: stdout)
  -j    output results in JSON format

Performance Options:
  -w int
        number of worker goroutines (default: 40)

Filtering Options:
  -whitelist string
        comma-separated whitelist of extensions (e.g., "php,asp,jsp")
  -blacklist string
        comma-separated blacklist of extensions (e.g., "jpg,png,css")
  -filters string
        comma-separated filters:
          hasparams  - only URLs with query parameters
          noparams   - only URLs without query parameters
          hasext     - only URLs with file extensions
          noext      - only URLs without extensions
          allexts    - don't filter any extensions
          keepcontent - keep blog posts and articles
          keepslash  - don't remove trailing slashes

Examples:
  ./kxss -f urls.txt
  ./kxss -f urls.txt -w 100 -o results.txt
  ./kxss -f urls.txt -j -o results.json
  ./kxss -f urls.txt -whitelist php -filters hasparams
  ./kxss -f urls.txt -blacklist jpg,png,gif
  cat urls.txt | ./kxss
```

#### Katana Workflow
```
# Full active workflow
katana -u https://vulnweb.com -o urls.txt && \
  ./kxss -f urls.txt -filters hasparams -w 100 -j -o results.json

# Full passive workflow
katana -u vulnweb.com -ps -f qurl > katana.txt && \
  ./kxss -f katana.txt -whitelist php -filters hasparams

URL: http://testphp.vulnweb.com/products.php?id= Param: id [Possible SQL Injection] [MSSQL] Unfiltered: []
URL: http://testphp.vulnweb.com/artists.php?artist=3 Param: artist [Possible SQL Injection] [MySQL] Unfiltered: [" ' < > $ | ( ) ` : ; { }]
URL: http://testphp.vulnweb.com/hpp/params.php?p=/ Param: p Unfiltered: [" ' < > $ | ( ) ` : ; { }]
```

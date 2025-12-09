package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Version   = "1.0.0"
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// Result represents secrets found in a URL
type Result struct {
	URL     string              `json:"url"`
	Secrets map[string][]string `json:"secrets"`
}

// CompiledPattern holds a compiled regex pattern
type CompiledPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// Scanner holds the scanner configuration
type Scanner struct {
	client           *http.Client
	patterns         []CompiledPattern
	genericPatterns  []*regexp.Regexp
	workers          int
	timeout          int
	silent           bool
	verbose          bool
	outputFile       string
	results          []Result
	resultsMu        sync.Mutex
	scannedCount     int64
	foundCount       int64
	totalURLs        int
}

func printBanner() {
	banner := `
` + ColorCyan + `    ╔═══════════════════════════════════════════════════════════════════╗
    ║` + ColorYellow + `   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ` + ColorCyan + `║
    ║` + ColorWhite + `     ██████╗  ██████╗       ███████╗███████╗ ██████╗               ` + ColorCyan + `║
    ║` + ColorWhite + `    ██╔════╝ ██╔═══██╗      ██╔════╝██╔════╝██╔════╝               ` + ColorCyan + `║
    ║` + ColorWhite + `    ██║  ███╗██║   ██║█████╗███████╗█████╗  ██║                    ` + ColorCyan + `║
    ║` + ColorWhite + `    ██║   ██║██║   ██║╚════╝╚════██║██╔══╝  ██║                    ` + ColorCyan + `║
    ║` + ColorWhite + `    ╚██████╔╝╚██████╔╝      ███████║███████╗╚██████╗               ` + ColorCyan + `║
    ║` + ColorWhite + `     ╚═════╝  ╚═════╝       ╚══════╝╚══════╝ ╚═════╝               ` + ColorCyan + `║
    ║` + ColorYellow + `   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀        ` + ColorCyan + `║
    ║` + ColorGreen + `              ░▒▓ Go Secrets Scanner ▓▒░                           ` + ColorCyan + `║
    ║` + ColorWhite + `     Extract API keys, tokens & credentials from files             ` + ColorCyan + `║
    ║` + ColorPurple + `     Version: ` + Version + `                                                ` + ColorCyan + `║
    ╚═══════════════════════════════════════════════════════════════════╝` + ColorReset + `
`
	fmt.Println(banner)
}

func NewScanner(workers, timeout int, silent, verbose bool, outputFile string) *Scanner {
	// Create HTTP client with custom transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        workers * 2,
		MaxIdleConnsPerHost: workers,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	scanner := &Scanner{
		client:     client,
		workers:    workers,
		timeout:    timeout,
		silent:     silent,
		verbose:    verbose,
		outputFile: outputFile,
		results:    make([]Result, 0),
	}

	// Compile all patterns
	scanner.compilePatterns()

	return scanner
}

func (s *Scanner) compilePatterns() {
	s.patterns = make([]CompiledPattern, 0, len(DefaultPatterns))

	for name, pattern := range DefaultPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			if !s.silent {
				fmt.Printf("%s[!] Failed to compile pattern '%s': %v%s\n", ColorYellow, name, err, ColorReset)
			}
			continue
		}
		s.patterns = append(s.patterns, CompiledPattern{Name: name, Pattern: re})
	}

	// Compile generic keyword patterns
	s.genericPatterns = make([]*regexp.Regexp, 0, len(GenericSecretKeywords)*2)
	for _, keyword := range GenericSecretKeywords {
		// Pattern 1: JSON/object style "keyword": "value"
		pattern1 := fmt.Sprintf(`(?i)["']?%s["']?\s*[:=]\s*["']([^"']+)["']`, regexp.QuoteMeta(keyword))
		if re, err := regexp.Compile(pattern1); err == nil {
			s.genericPatterns = append(s.genericPatterns, re)
		}
	}

	if !s.silent {
		fmt.Printf("%s[*] Loaded %d patterns + %d generic keyword patterns%s\n",
			ColorCyan, len(s.patterns), len(s.genericPatterns), ColorReset)
	}
}

func (s *Scanner) isFalsePositive(secretType, match, context string) bool {
	matchLower := strings.ToLower(match)
	contextLower := strings.ToLower(context)

	// Check false positive indicators - only in the match itself, not the whole context
	// These are code patterns that indicate the match is part of JavaScript code, not a secret
	for _, indicator := range FalsePositiveIndicators {
		indicatorLower := strings.ToLower(indicator)
		if strings.Contains(matchLower, indicatorLower) {
			return true
		}
	}

	// Special context-based checks for specific indicators that strongly suggest false positives
	// when they appear directly adjacent to the match
	contextCodeIndicators := []string{"function(", ".prototype", "Object.defineProperty"}
	for _, indicator := range contextCodeIndicators {
		if strings.Contains(contextLower, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check test file indicators in context
	for _, indicator := range TestFileIndicators {
		indicatorLower := strings.ToLower(indicator)
		// Only skip if the indicator is directly adjacent to the match (e.g., "test_api_key")
		if strings.Contains(matchLower, indicatorLower) {
			return true
		}
	}

	// Skip UUIDs that aren't actual API keys (standard UUID v4 format)
	// Exception: Heroku keys and HubSpot keys can look like UUIDs
	if matched, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, strings.ToLower(match)); matched {
		// Only allow UUID-like patterns for specific services that use UUID tokens
		allowedUUIDServices := []string{"Heroku", "HubSpot", "LaunchDarkly", "DocuSign", "Splunk"}
		isAllowed := false
		for _, service := range allowedUUIDServices {
			if strings.Contains(secretType, service) || strings.Contains(contextLower, strings.ToLower(service)) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return true
		}
	}

	// Also filter UUID-like patterns (8-4-4-4-12) even with mixed case
	if matched, _ := regexp.MatchString(`^[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}$`, match); matched {
		// This is likely a UUID, not a secret
		return true
	}

	// Skip SHA1/SHA256 hashes that look like tokens
	if len(match) == 40 || len(match) == 64 {
		if matched, _ := regexp.MatchString(`^[a-f0-9]+$`, strings.ToLower(match)); matched {
			// Check if it's in a hash-related context
			hashContexts := []string{"hash", "sha", "checksum", "integrity", "commit", "digest"}
			for _, hc := range hashContexts {
				if strings.Contains(contextLower, hc) {
					return true
				}
			}
		}
	}

	// Type-specific checks
	if strings.Contains(secretType, "Telegram") {
		// Real Telegram tokens start with digits and have 'AA' after colon
		if matched, _ := regexp.MatchString(`^\d{9,10}:AA`, match); !matched {
			return true
		}
	}

	if strings.Contains(secretType, "Azure SAS") {
		if !strings.Contains(match, "sv=") {
			return true
		}
		if matched, _ := regexp.MatchString(`\d{4}-\d{2}-\d{2}`, match); !matched {
			return true
		}
	}

	if strings.Contains(secretType, "Microsoft Graph") {
		// Require minimum length for MS Graph tokens
		if len(match) < 50 {
			return true
		}
	}

	if strings.Contains(secretType, "Generic") {
		if len(match) < 16 {
			return true
		}
		if matched, _ := regexp.MatchString(`^[a-z]{1,3}$`, match); matched {
			return true
		}
	}

	// Skip reCAPTCHA site keys (public, not secrets)
	if matched, _ := regexp.MatchString(`^6L[a-zA-Z0-9_-]{38}$`, match); matched {
		return true
	}

	// Skip Twitter Bearer Token false positives that are actually base64 image data
	if strings.Contains(secretType, "Twitter Bearer") {
		// Real Twitter bearer tokens don't contain PNG/image base64 markers
		imageMarkers := []string{"SuQmCC", "ElFTkS", "CYII", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		for _, marker := range imageMarkers {
			if strings.Contains(match, marker) {
				return true
			}
		}
		// Skip if it's mostly repeated 'A' characters (null bytes in base64)
		repeatedA := strings.Count(match, "AAAA")
		if repeatedA > 10 {
			return true
		}
	}

	return false
}

func (s *Scanner) isSkipValue(value string) bool {
	valueLower := strings.ToLower(value)
	for _, skip := range SkipValues {
		if strings.HasPrefix(valueLower, strings.ToLower(skip)) {
			return true
		}
	}

	// Skip if looks like code
	codeIndicators := []string{"function", "return", "=>", "()", "{}", "[]"}
	for _, indicator := range codeIndicators {
		if strings.Contains(value, indicator) {
			return true
		}
	}

	// Skip URL paths
	if strings.HasPrefix(value, "/") && !strings.Contains(value, "://") {
		return true
	}

	return false
}

func (s *Scanner) extractSecrets(content string) map[string][]string {
	secrets := make(map[string][]string)
	seen := make(map[string]bool)

	// Pattern-based extraction
	for _, cp := range s.patterns {
		matches := cp.Pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			var value string
			if len(match) > 1 {
				value = match[1]
			} else {
				value = match[0]
			}

			// Get context for false positive detection
			idx := strings.Index(content, value)
			var context string
			if idx != -1 {
				start := idx - 50
				if start < 0 {
					start = 0
				}
				end := idx + len(value) + 50
				if end > len(content) {
					end = len(content)
				}
				context = content[start:end]
			}

			// Skip false positives
			if s.isFalsePositive(cp.Name, value, context) {
				continue
			}

			// Deduplicate
			key := cp.Name + ":" + value
			if seen[key] {
				continue
			}
			seen[key] = true

			if secrets[cp.Name] == nil {
				secrets[cp.Name] = make([]string, 0)
			}
			secrets[cp.Name] = append(secrets[cp.Name], value)
		}
	}

	// Generic keyword extraction
	for i, keyword := range GenericSecretKeywords {
		if i >= len(s.genericPatterns) {
			break
		}
		re := s.genericPatterns[i]
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			value := strings.TrimSpace(match[1])

			// Skip short values
			if len(value) < 8 {
				continue
			}

			// Skip common non-secret values
			if s.isSkipValue(value) {
				continue
			}

			category := fmt.Sprintf("Generic (%s)", keyword)
			keyValue := fmt.Sprintf(`"%s": "%s"`, keyword, value)

			// Deduplicate
			key := category + ":" + keyValue
			if seen[key] {
				continue
			}
			seen[key] = true

			if secrets[category] == nil {
				secrets[category] = make([]string, 0)
			}
			secrets[category] = append(secrets[category], keyValue)
		}
	}

	return secrets
}

func (s *Scanner) scanURL(url string) *Result {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		if s.verbose {
			fmt.Printf("%s[!] Error creating request for %s: %v%s\n", ColorRed, url, err, ColorReset)
		}
		return nil
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := s.client.Do(req)
	if err != nil {
		if s.verbose {
			fmt.Printf("%s[!] Error fetching %s: %v%s\n", ColorRed, url, err, ColorReset)
		}
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	// Read body with limit (10MB max)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		if s.verbose {
			fmt.Printf("%s[!] Error reading %s: %v%s\n", ColorRed, url, err, ColorReset)
		}
		return nil
	}

	content := string(body)
	secrets := s.extractSecrets(content)

	if len(secrets) > 0 {
		return &Result{
			URL:     url,
			Secrets: secrets,
		}
	}

	return nil
}

func (s *Scanner) worker(urls <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for url := range urls {
		result := s.scanURL(url)

		atomic.AddInt64(&s.scannedCount, 1)
		scanned := atomic.LoadInt64(&s.scannedCount)

		if result != nil {
			s.resultsMu.Lock()
			s.results = append(s.results, *result)
			s.resultsMu.Unlock()

			atomic.AddInt64(&s.foundCount, 1)

			if !s.silent {
				secretCount := 0
				for _, v := range result.Secrets {
					secretCount += len(v)
				}
				fmt.Printf("\r%s[+] Found %d secret(s) in: %s%s\n", ColorGreen, secretCount, url, ColorReset)
			}
		}

		if !s.silent {
			fmt.Printf("\r%s[*] Progress: %d/%d URLs scanned, %d files with secrets found%s",
				ColorCyan, scanned, s.totalURLs, atomic.LoadInt64(&s.foundCount), ColorReset)
		}
	}
}

func (s *Scanner) Scan(urls []string) {
	s.totalURLs = len(urls)

	if !s.silent {
		fmt.Printf("%s[*] Starting scan of %d URLs with %d workers%s\n",
			ColorCyan, len(urls), s.workers, ColorReset)
	}

	urlChan := make(chan string, s.workers*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.worker(urlChan, &wg)
	}

	// Feed URLs
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	// Wait for completion
	wg.Wait()

	if !s.silent {
		fmt.Printf("\n%s[*] Scan complete. Found secrets in %d files.%s\n",
			ColorGreen, len(s.results), ColorReset)
	}
}

func (s *Scanner) SaveResults() error {
	data, err := json.MarshalIndent(s.results, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshaling results: %v", err)
	}

	err = os.WriteFile(s.outputFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing results: %v", err)
	}

	if !s.silent {
		fmt.Printf("%s[*] Results saved to %s%s\n", ColorGreen, s.outputFile, ColorReset)
	}

	return nil
}

func loadURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" && (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
			urls = append(urls, url)
		}
	}

	return urls, scanner.Err()
}

func main() {
	// Command-line flags
	listFile := flag.String("l", "", "Path to file containing URLs to scan (required)")
	workers := flag.Int("w", 30, "Number of concurrent workers")
	timeout := flag.Int("t", 15, "HTTP timeout in seconds")
	outputFile := flag.String("o", "secrets.json", "Output JSON file")
	silent := flag.Bool("s", false, "Silent mode (minimal output)")
	verbose := flag.Bool("v", false, "Verbose output (show errors)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gosecrets [options]\n\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  gosecrets -l urls.txt -w 50 -o secrets.json\n")
	}

	flag.Parse()

	if !*silent {
		printBanner()
	}

	if *listFile == "" {
		fmt.Printf("%s[!] Please provide a URL list file using -l option%s\n", ColorRed, ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	// Load URLs
	urls, err := loadURLsFromFile(*listFile)
	if err != nil {
		fmt.Printf("%s[!] Error loading URLs: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	if len(urls) == 0 {
		fmt.Printf("%s[!] No valid URLs found in %s%s\n", ColorRed, *listFile, ColorReset)
		os.Exit(1)
	}

	if !*silent {
		fmt.Printf("%s[*] Loaded %d URLs from %s%s\n", ColorCyan, len(urls), *listFile, ColorReset)
	}

	// Create scanner and run
	scanner := NewScanner(*workers, *timeout, *silent, *verbose, *outputFile)
	scanner.Scan(urls)

	// Save results
	if err := scanner.SaveResults(); err != nil {
		fmt.Printf("%s[!] %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
}

# SearchAbuse

package main
/*
LEGAL NOTICE:
Defensive security research only.
You must have explicit authorization.
DO NOT BREAK THE LAW or Google's rate limits.
*/
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/proxy"
)

//go:embed dorks.txt
var embeddedDorks string

// Constants for logging and retries
const (
	LogFile     = "scan_results.log" // Log file location
	MaxRetries  = 5                  // Max retry attempts for each request
	DefaultStorage = "json"          // Default output format (json)
	DefaultThreads = 5               // Default number of threads for concurrent requests
)

var EngineCaps = map[string]int{
	"duckduckgo": 10,
	"bing":       15,
	"google":     20,
}

var EngineDelay = map[string]time.Duration{
	"duckduckgo": 3 * time.Second,
	"bing":       4 * time.Second,
	"google":     5 * time.Second,
}

var BlockIndicators = []string{
	"captcha", "unusual traffic", "verify you are human", "access denied", "consent",
}

var dorks = []string{
	"allinurl:\"admin\" \"login.php\" filetype:php",            // Google & Bing supported
	"allinurl:\"backup\" \"2023\" filetype:zip",                // Google & Bing supported
	"allinurl:\"config\" \"database\" ext:json",                // Google & Bing supported
	"allinurl:\"credentials\" \"backup\" filetype:bak",         // Google & Bing supported
	"allinurl:\"private\" \"key\" filetype:key",                // Google & Bing supported
	"intitle:\"dashboard\" inurl:\"admin\" -site:github.com",   // Google & Bing supported
	"intitle:\"control panel\" inurl:\"manage\"",              // Google & Bing supported
	"intitle:\"restricted area\" inurl:\"login\"",             // Google & Bing supported
	"allintitle:\"configuration\" \"database\" filetype:ini",   // Google & Bing supported
	"filetype:env \"DB_PASSWORD\"",                            // Google & Bing supported
	"filetype:sql \"insert into\" \"password\"",                // Google & Bing supported
	"filetype:xls intext:\"password\" \"email\"",              // Google & Bing supported
	"filetype:ini \"user\" \"password\"",                       // Google & Bing supported
	"filetype:conf \"password\" \"secret\"",                    // Google & Bing supported
	// DuckDuckGo Dorks (DuckDuckGo-friendly format)
	"filetype:bak \"password\"",                               // DuckDuckGo & Google supported
	"filetype:zip \"backup\"",                                 // DuckDuckGo & Google supported
	"filetype:tar \"config\"",                                 // DuckDuckGo & Google supported
	"inurl:\"wp-content/plugins/\" intext:\"vulnerable\"",      // DuckDuckGo & Google supported
	"allinurl:\"wp-admin\" \"admin-ajax.php\"",                // DuckDuckGo & Google supported
	"inurl:\"wp-config.php\" \"DB_PASSWORD\"",                // DuckDuckGo & Google supported
	"inurl:\"wp-login.php\"",                                  // DuckDuckGo & Google supported
	// More Google-specific queries (same structure for Bing/DuckDuckGo)
	"intitle:\"server information\"",                          // Google & Bing supported
	"inurl:\"status\" \"nginx\"",                              // Google & Bing supported
	"filetype:log \"error\" \"exception\"",                    // Google & Bing supported
	"filetype:txt \"password\" \"database\"",                  // Google & Bing supported
	"filetype:log \"failed login\"",                           // Google & Bing supported
	// DuckDuckGo Dorks (DuckDuckGo-friendly format)
	"filetype:sql \"dump\" \"INSERT INTO\"",                   // DuckDuckGo & Google supported
	"filetype:env \"APP_KEY\"",                                // DuckDuckGo & Google supported
	"intext:\"client_secret\" \"oauth\"",                      // DuckDuckGo & Google supported
	"intitle:\"test page for apache\"",                        // DuckDuckGo & Google supported
	"filetype:xlsx \"confidential\" \"salary\"",               // Google & Bing supported
	"intitle:\"invoice\" \"due date\" filetype:xls",            // Google & Bing supported
	"allintitle:\"private\" \"document\" ext:doc OR ext:docx",  // Google & Bing supported
	"allintitle:\"index of\" \"private\"",                     // Google & Bing supported
	"allintitle:\"confidential\" \"report\" filetype:pdf",     // Google & Bing supported
	"inurl:\"temp\" \"passwords\"",                            // Google & Bing supported
	"allintitle:\"error log\" \"access denied\"",              // Google & Bing supported
}
// Go embedding of the dorks.txt file
var (
	EncryptionKey = []byte("0123456789abcdef0123456789abcdef")
	UserAgents    = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) Chrome/117.0.5938.92 Safari/537.36",
	}
)

type Result struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type Logger struct {
	mu sync.Mutex
}

func (l *Logger) Log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format(time.RFC3339), msg)
}

var logger = &Logger{}

func logStructured(event string, fields map[string]any) {
	fields["event"] = event
	fields["ts"] = time.Now().Format(time.RFC3339)
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}

	logger.Log(string(b))
}

func encryptAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(EncryptionKey)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(data, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(padded, padded)
	return append(iv, padded...), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(
		data,
		bytes.Repeat([]byte{byte(pad)}, pad)...,
	)
}

func buildClient(useTor bool) (*http.Client, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if useTor {
		dialer, err := proxy.SOCKS5(
			"tcp",
			"127.0.0.1:9050",
			nil,
			proxy.Direct,
		)
		if err != nil {
			return nil, err
		}
		transport.DialContext = func(
			ctx context.Context,
			netw,
			addr string,
		) (net.Conn, error) {

			return dialer.Dial(netw, addr)
		}
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: transport,
	}, nil
}

func normalizeGoogleURL(href string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	if strings.Contains(href, "/url?") {
		u, err := url.Parse(href)
		if err == nil {
			if q := u.Query().Get("q"); q != "" {
				return q
			}
		}
	}
	if strings.HasPrefix(href, "/url?") {
		u, err := url.Parse("https://www.google.com" + href)
		if err == nil {
			if q := u.Query().Get("q"); q != "" {
				return q
			}
		}
	}
	if strings.Contains(href, "google.com/search") {
		return ""
	}
	return strings.TrimRight(href, "/")
}

func fetchResults(client *http.Client, engine, query string, debug bool) ([]Result, error) {
	results := []Result{}
	cap := EngineCaps[engine]
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		time.Sleep(EngineDelay[engine])
		var req *http.Request
		var err error
		switch engine {
		case "duckduckgo":
			form := url.Values{}
			form.Set("q", query)
			req, err = http.NewRequest(
				"POST",
				"https://html.duckduckgo.com/html/",
				strings.NewReader(form.Encode()),
			)
			if err == nil {
				req.Header.Set(
					"Content-Type",
					"application/x-www-form-urlencoded",
				)
			}
		case "bing":
			req, err = http.NewRequest(
				"GET",
				"https://www.bing.com/search?q="+
					url.QueryEscape(query),
				nil,
			)
		case "google":
			req, err = http.NewRequest(
				"GET",
				"https://www.google.com/search?q="+
					url.QueryEscape(query),
				nil,
			)
		default:
			return nil, errors.New("unknown engine")
		}
		if err != nil {
			continue
		}
		req.Header.Set(
			"User-Agent",
			UserAgents[mrand.Intn(len(UserAgents))],
		)
		req.Header.Set(
			"Accept-Language",
			"en-US,en;q=0.9",
		)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		if debug {
			name := fmt.Sprintf(
				"debug_%s_%d.html",
				engine,
				time.Now().UnixNano(),
			)
			_ = os.WriteFile(name, body, 0600)
		}
		lower := strings.ToLower(string(body))
		blocked := false
		for _, b := range BlockIndicators {
			if strings.Contains(lower, b) {
				logStructured(
					"blocked",
					map[string]any{"engine": engine},
				)
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		doc, err := goquery.NewDocumentFromReader(
			bytes.NewReader(body),
		)
		if err != nil {
			continue
		}
		switch engine {
		case "duckduckgo":
			doc.Find("a.result__a").Each(
				func(_ int, s *goquery.Selection) {
					if len(results) >= cap {
						return
					}
					t := strings.TrimSpace(s.Text())
					h, _ := s.Attr("href")
					if t != "" && h != "" {
						results = append(
							results,
							Result{t, h},
						)
					}
				},
			)
		case "bing":
			doc.Find("li.b_algo h2 a").Each(
				func(_ int, s *goquery.Selection) {
					if len(results) >= cap {
						return
					}
					t := strings.TrimSpace(s.Text())
					h, _ := s.Attr("href")
					if t != "" && h != "" {
						results = append(
							results,
							Result{t, h},
						)
					}
				},
			)
		case "google":
			doc.Find("div.g h3, a h3").Each(
				func(_ int, s *goquery.Selection) {
					if len(results) >= cap {
						return
					}
					t := strings.TrimSpace(s.Text())
					a := s.ParentsFiltered("a").First()
					h, _ := a.Attr("href")
					h = normalizeGoogleURL(h)
					if t != "" && h != "" {
						results = append(
							results,
							Result{t, h},
						)
					}
				},
			)
		}
		if len(results) > 0 {
			logStructured(
				"results",
				map[string]any{
					"engine": engine,
					"count":  len(results),
				},
			)
			return results, nil
		}
	}
	return nil, errors.New("max retries exceeded")
}

func main() {
	mrand.Seed(time.Now().UnixNano())
	var target, engine, output string
	var threads int
	var useTor, debug bool
	flag.StringVar(&target, "url", "", "Target domain")
	flag.StringVar(&engine, "engine", "duckduckgo", "Search engine")
	flag.StringVar(&output, "output", DefaultStorage, "Output mode")
	flag.IntVar(&threads, "threads", DefaultThreads, "Threads")
	flag.BoolVar(&useTor, "tor", false, "Use TOR")
	flag.BoolVar(&debug, "debug", false, "Dump raw HTML")
	flag.Parse()
	if target == "" {
		log.Fatal("Target URL required")
	}
	client, err := buildClient(useTor)
	if err != nil {
		log.Fatal(err)
	}
	engineOrder := []string{
		"duckduckgo",
		"bing",
		"google",
	}
	results := []Result{}
	seen := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	for _, dork := range dorks {
		dork = strings.TrimSpace(dork)
		if dork == "" {
			continue
		}
		wg.Add(1)
		go func(dork string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			query := "site:" + target + " " + dork
			var res []Result
			for _, eng := range engineOrder {
				r, err := fetchResults(
					client,
					eng,
					query,
					debug,
				)
				if err == nil && len(r) > 0 {
					res = r
					break
				}
			}
			mu.Lock()
			for _, r := range res {
				if !seen[r.URL] {
					seen[r.URL] = true
					results = append(results, r)
				}
			}
			mu.Unlock()
		}(dork)
	}
	wg.Wait()
	// Process results based on output format
	var out []byte
	switch output {
	case "encrypted":
		// Encrypt results and save to file
		j, err := json.Marshal(results)
		if err != nil {
			log.Fatal(err)
		}
		out, err = encryptAES(j)
		if err != nil {
			log.Fatal(err)
		}
		_ = os.WriteFile("results.enc", out, 0600)
	case "plaintext":
		// Save as plain text format
		var b strings.Builder
		for _, r := range results {
			b.WriteString("Title: " + r.Title + "\nURL: " + r.URL + "\n\n")
		}
		_ = os.WriteFile("results.txt", []byte(b.String()), 0600)
	default:
		// Save in structured JSON format
		out, err = json.MarshalIndent(results, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		_ = os.WriteFile("results.json", out, 0600)
	}
	// Final message after scan completes
	fmt.Println("[INFO] Scan complete.")
}

# SearchAbuse

SearchDork Scanner (Go)

A defensive security research tool written in Go that automates search engine queries (dorks) to identify publicly exposed resources associated with a target domain.

The tool queries multiple search engines (DuckDuckGo, Bing, Google), parses results, and outputs discovered URLs in JSON, plaintext, or encrypted formats.

Important: This tool is intended strictly for defensive security research. Only scan systems you have explicit authorization to test.


Overview

SearchDork Scanner performs automated search engine reconnaissance using predefined dork queries. These queries are combined with a target domain and executed against supported search engines. The tool collects results, removes duplicates, and exports them in a structured format for further analysis.

The goal is to help security researchers identify unintentionally exposed resources such as configuration files, backups, administrative panels, and sensitive documents that are indexed by search engines.


Features

Multi-engine search support
DuckDuckGo
Bing
Google

Automated search dork scanning
Concurrent scanning with configurable threads
Automatic retry logic with rate-limit awareness
Result deduplication
Optional Tor proxy support
Search engine block detection (captcha or traffic verification pages)
Structured event logging
Multiple output formats (JSON, plaintext, AES encrypted)
Embedded dork list support
Debug mode for saving raw search HTML responses


How It Works

The scanner automates search engine reconnaissance using domain-specific search queries.

Process:

1. A list of predefined search dorks is loaded.
2. Each dork is combined with the target domain using a query such as:

site:example.com filetype:env "DB_PASSWORD"

3. Queries are sent to supported search engines.
4. HTML responses are downloaded.
5. Results are parsed using the goquery HTML parsing library.
6. URLs are normalized and duplicates removed.
7. Results are exported to the selected output format.


Architecture Overview

Search Engines

Each search engine has predefined settings for:

Result limits
Delay between requests
HTML parsing selectors

Example configuration:

EngineCaps
EngineDelay

Result Limits:

DuckDuckGo: 10
Bing: 15
Google: 20


HTTP Client Builder

The scanner constructs an HTTP client that can optionally route traffic through Tor using a SOCKS5 proxy.

Function:

buildClient(useTor bool)

Tor proxy endpoint used:

127.0.0.1:9050

This allows the scanner to route requests through the Tor network when enabled.


Result Parsing

Search engine HTML responses are parsed using the goquery library.

Selectors used:

DuckDuckGo
a.result__a

Bing
li.b_algo h2 a

Google
div.g h3
a h3


Concurrency

The scanner uses Go concurrency features including:

goroutines
waitgroups
semaphore channels

Example implementation:

sem := make(chan struct{}, threads)

This allows multiple dork queries to run concurrently while limiting the number of active requests.


Logging

Structured logging is implemented throughout the application.

Log file:

scan_results.log

Example log entry:

{
  "event": "results",
  "engine": "bing",
  "count": 10,
  "ts": "2026-03-16T18:42:10Z"
}

Logs include events such as blocked responses, result collection, and scanning progress.


Encryption

Results can optionally be encrypted before storage.

Encryption details:

AES-CBC mode
PKCS7 padding
32 byte encryption key

Encrypted output file:

results.enc


Installation

Requirements

Go version 1.20 or newer
Internet connection
Optional Tor installation for anonymity mode

Install dependencies:

go mod tidy

Build the project:

go build -o dorkscan


Usage

Basic command:

./dorkscan -url example.com


Command Line Options

-url
Target domain (required)

-engine
Search engine to use (default: duckduckgo)

-threads
Number of concurrent scanning threads

-output
Output format (json, plaintext, encrypted)

-tor
Route traffic through Tor

-debug
Save raw HTML responses for debugging


Examples

Basic Scan

./dorkscan -url example.com


Use Tor

./dorkscan -url example.com -tor


Increase Threads

./dorkscan -url example.com -threads 10


Encrypted Output

./dorkscan -url example.com -output encrypted


Debug Mode

Debug mode saves raw HTML responses to local files for troubleshooting parsing issues.

./dorkscan -url example.com -debug


Output Formats

JSON (Default)

Output file:

results.json

Example:

[
  {
    "title": "Admin Login",
    "url": "https://example.com/admin/login.php"
  }
]


Plaintext

Output file:

results.txt

Example:

Title: Admin Login
URL: https://example.com/admin/login.php


Encrypted

Output file:

results.enc

Encrypted using AES-CBC encryption.


Included Dorks

The scanner includes a built-in list of search queries targeting common exposure types.

Examples:

filetype:env "DB_PASSWORD"
filetype:sql "insert into" "password"
intitle:"dashboard" inurl:"admin"
allinurl:"backup" filetype:zip

These queries help identify possible exposures including:

Configuration files
Database dumps
Backup archives
Administrative panels
Credentials stored in public documents
Misconfigured servers
Sensitive logs


Safety Mechanisms

The scanner includes safeguards to reduce the risk of blocking or excessive requests:

Search engine rate limiting delays
CAPTCHA and traffic verification detection
Retry limits
Randomized user agents
Duplicate result filtering
Structured logging


Legal Notice

This tool is provided for educational and defensive security research purposes only.

Users must obtain explicit authorization before scanning any systems.

Users must follow the terms of service of search engines and comply with all applicable laws and regulations.

The author assumes no responsibility for misuse or illegal activities conducted with this software.


Dependencies
Primary libraries used:
goquery
Used for HTML parsing and extraction of search results.
golang.org/x/net/proxy
Used for SOCKS5 proxy support and Tor routing.




This project is intended for ethical security research and defensive purposes only.

Ensure compliance with all applicable laws and policies before using this software.

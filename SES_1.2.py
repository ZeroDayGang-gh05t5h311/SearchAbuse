""" 
Normal legal stuff: don't use this in any way that would break the law... it is for people to secure websites not break them for personal gain...
This is something that will depend on your local area and so before using this script you may want to check local laws to be sure you are not breaking them...
DO NOT BREAK THE LAW!!!
Also should note: this is untested code as for now this is just a hobby to me as of now but posting it here likely help motivate me just because it's here. 
Not to work on this though to be honest it was an interesting time. NOT much more than a POC but if you use the --custom-dorks option with the list
provided at the bottom(or your own), it can have some decent results... but due to the use of 3rd party python lib's(I personally do not want to use this and 
even though it is my code and i love it as a POC: would happily warn anyone against installing all the extras in this to run it). But if you want too
then feel free to enjoy.
"""
import os
import sys
import json
import time
import argparse
import requests
import psutil
import traceback
import re
import random
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# === CONFIG ===
DEFAULT_THREADS = 5
DEFAULT_STORAGE = "json"
DEFAULT_TOR = False
ENCRYPTION_KEY = b"0123456789abcdef0123456789abcdef"
LOG_FILE = ".log_hidden.txt"
CPU_THRESHOLD = 70
MEM_THRESHOLD = 65
EMPTY_BATCH_THRESHOLD = 0.7
NOISE_KEYWORDS = {"home", "index of", "welcome", "about", "contact", "site map"}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    " Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/117.0.5938.92 Safari/537.36",
]
RE_ALLINURL = re.compile(r'^\s*allinurl:\s*(.+)$', re.I)
RE_ALLINTITLE = re.compile(r'^\s*allintitle:\s*(.+)$', re.I)
RE_ALLINTEXT = re.compile(r'^\s*allintext:\s*(.+)$', re.I)
RE_OPERATOR_PREFIXES = re.compile(r'^(inurl|intitle|intext|filetype|ext|site|cache|link|related|info):', re.I)
 
class Logger:
    @staticmethod
    def log(msg):
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")
                exc = traceback.format_exc()
                if exc and "NoneType" not in exc:
                    f.write(exc + "\n")
        except Exception:
            pass
 
class TorManager:
    @staticmethod
    def is_running():
        try:
            r = requests.get(
                "http://check.torproject.org",
                proxies={"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"},
                timeout=5
            )
            return "Congratulations" in r.text
        except Exception:
            return False
 
    @staticmethod
    def renew_ip():
        pw = os.getenv("TOR_PASSWORD") or "default_fallback_password"
        if "TOR_PASSWORD" not in os.environ:
            Logger.log("TOR_PASSWORD not set. Using fallback password.")
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate(password=pw)
                controller.signal(Signal.NEWNYM)
                time.sleep(5)
            print("[INFO] Tor IP renewed.")
        except Exception as e:
            Logger.log(f"Error renewing Tor IP: {e}")
            print("[WARN] Failed to renew Tor IP. Proceeding with old identity.")
 
class Encryptor:
    @staticmethod
    def encrypt(data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(data.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return iv + encrypted
 
class ResultStorage:
    @staticmethod
    def save(results, mode):
        try:
            if mode == "plaintext":
                with open("results.txt", "w", encoding="utf-8") as f:
                    for r in results:
                        f.write(f"Title: {r.get('title')}\n")
                        f.write(f"URL: {r.get('url')}\n")
                        if r.get("snippet"):
                            f.write(f"Snippet: {r.get('snippet')}\n")
                        f.write("-" * 80 + "\n")
            elif mode == "json":
                with open("results.json", "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=4)
            elif mode == "encrypted":
                enc = Encryptor.encrypt(json.dumps(results), ENCRYPTION_KEY)
                with open("results.enc", "wb") as f:
                    f.write(enc)
            else:
                Logger.log("PostgreSQL storage not implemented.")
                print("[WARN] PostgreSQL storage not implemented.")
            print(f"[INFO] Results saved using '{mode}' mode.")
        except Exception as e:
            Logger.log(f"Error saving results: {e}")
            print("[ERROR] Could not save results.")
 
class SystemMonitor:
    overload_strikes = 0
 
    @staticmethod
    def resources_ok():
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        print(f"[INFO] CPU usage: {cpu}%, Memory usage: {mem}%")
        if cpu > CPU_THRESHOLD or mem > MEM_THRESHOLD:
            SystemMonitor.overload_strikes += 1
            print(f"[WARN] High system resource usage detected (strike {SystemMonitor.overload_strikes}).")
            if SystemMonitor.overload_strikes > 2:
                return False
        else:
            SystemMonitor.overload_strikes = 0
        return True
 
class DorkFetcher:
    DORKS_CACHE = "dorks.txt"
    URL = "https://raw.githubusercontent.com/PwnAwan/Google-Dorks/main/Google-Dorks-List-New-2020.txt"
 
    @staticmethod
    def load(custom_dorks=None):
        if custom_dorks:
            print(f"[INFO] Loading {len(custom_dorks)} custom dorks from provided list...")
            deduped = list(dict.fromkeys([d.strip() for d in custom_dorks if d.strip()]))
            print(f"[INFO] Loaded {len(deduped)} unique custom dorks.")
            return deduped  # ONLY use custom if provided
 
        if os.path.exists(DorkFetcher.DORKS_CACHE):
            print("[INFO] Loading dorks from cache file...")
            try:
                with open(DorkFetcher.DORKS_CACHE, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                deduped = list(dict.fromkeys(lines))
                print(f"[INFO] Loaded {len(deduped)} unique dorks from cache.")
                return deduped
            except Exception as e:
                Logger.log(f"Error reading dorks cache file: {e}")
 
        print("[INFO] Downloading dorks from online source...")
        try:
            resp = requests.get(DorkFetcher.URL, timeout=20)
            if resp.status_code == 200 and "text/plain" in resp.headers.get("Content-Type", "").lower():
                lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                deduped = list(dict.fromkeys(lines))
                try:
                    with open(DorkFetcher.DORKS_CACHE, "w", encoding="utf-8") as f:
                        f.write("\n".join(deduped))
                    print(f"[INFO] Cached {len(deduped)} dorks locally for future use.")
                except Exception as e:
                    Logger.log(f"Error writing dorks cache file: {e}")
                return deduped
            else:
                Logger.log("Unexpected content type or status code when fetching dork list.")
                print("[ERROR] Failed to load dork list.")
        except Exception as e:
            Logger.log(f"Error loading dork list: {e}")
        return []
 
class ServerDetector:
    @staticmethod
    def detect(target):
        print(f"[INFO] Detecting server type for: {target}")
        urls_to_try = [f"http://{target}", f"https://{target}"]
        for full_url in urls_to_try:
            try:
                r = requests.get(full_url, timeout=10, verify=False)
                if r.status_code >= 400:
                    print("[WARN] Server returned error status code.")
                    continue
                hdr = " ".join([r.headers.get(k, "").lower() for k in ("Server", "X-Powered-By")])
                body = r.text.lower()
                if any(x in hdr for x in ["mysql", "mariadb", "postgres", "php"]) or any(x in body for x in ["phpmyadmin", "wp-login.php"]):
                    print(f"[INFO] Server detected as likely LAMP/WAMP stack: {hdr}")
                    return "LAMP"
                elif "nginx" in hdr or "uwsgi" in hdr or "gunicorn" in hdr:
                    print(f"[INFO] Server detected as likely Python stack: {hdr}")
                    return "PYTHON"
                elif "iis" in hdr or "asp.net" in hdr:
                    print(f"[INFO] Server detected as likely .NET stack: {hdr}")
                    return ".NET"
                elif "apache" in hdr:
                    print(f"[INFO] Server detected as Apache: {hdr}")
                    return "APACHE"
                elif "caddy" in hdr:
                    print(f"[INFO] Server detected as Caddy: {hdr}")
                    return "CADDY"
                else:
                    print(f"[INFO] Server type undetermined, headers: {hdr}")
                    return "UNKNOWN"
            except Exception as e:
                Logger.log(f"Error detecting server: {e}")
        print("[WARN] Unable to detect server type.")
        return "UNKNOWN"
 
# ... rest of your script unchanged ...
class DorkScanner:
    def __init__(self, url, output_mode, threads, use_tor, fast_mode, engine, custom_dorks=None):
        self.url = url
        self.output_mode = output_mode
        self.threads = threads
        self.use_tor = use_tor
        self.fast_mode = fast_mode
        self.engine = engine
        self.custom_dorks = custom_dorks
        self.results = []
        self.context_terms = [
            "admin", "login", "config", "database", "php", "mongodb", "redis",
            "backup", "password", "secret", "portal", "wp-", "sql"
        ]
        self.context_clause = " OR ".join(self.context_terms)
 
    def translate_dork(self, dork):
        return f"site:{self.url} {dork} {self.context_clause}"
 
    def fetch_results(self, query, retries=3):
        session = requests.session()
        if self.use_tor:
            session.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
 
        base_urls = {
            "duckduckgo": "https://html.duckduckgo.com/html/?q=",
            "bing": "https://www.bing.com/search?q=",
            "google": "https://www.google.com/search?q="
        }
 
        selectors = {
            "duckduckgo": lambda soup: [
                {
                    "title": a.get_text(strip=True),
                    "url": a.get("href"),
                    "snippet": (a.find_parent("div").find_next_sibling("a") or {}).get_text(strip=True)
                    if a.find_parent("div") else ""
                }
                for a in soup.find_all("a", class_="result__a")
            ],
            "bing": lambda soup: [
                {
                    "title": a.get_text(strip=True),
                    "url": a.get("href"),
                    "snippet": (a.find_parent("h2").find_next_sibling("div") or {}).get_text(strip=True)
                    if a.find_parent("h2") else ""
                }
                for a in soup.select("li.b_algo h2 a")
            ],
            "google": lambda soup: [
                {
                    "title": h3.get_text(strip=True),
                    "url": h3.find_parent("a").get("href") if h3.find_parent("a") else "",
                    "snippet": (h3.find_parent("div").find_next_sibling("div") or {}).get_text(strip=True)
                    if h3.find_parent("div") else ""
                }
                for h3 in soup.select("div.g h3")
            ]
        }
 
        search_url = base_urls[self.engine] + requests.utils.quote(query)
 
        for attempt in range(1, retries + 1):
            try:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept-Language": "en-US,en;q=0.9",
                }
                r = session.get(search_url, headers=headers, timeout=15)
                if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "").lower():
                    lower_text = r.text.lower()
                    block_indicators = ["captcha", "unusual traffic", "verify you are human", "access denied", "are you a robot"]
                    if any(bi in lower_text for bi in block_indicators):
                        print("[WARN] Search engine is blocking or challenging traffic.")
                        if self.use_tor:
                            TorManager.renew_ip()
                        else:
                            time.sleep(10)
                        continue
                    soup = BeautifulSoup(r.text, "html.parser")
                    results = selectors[self.engine](soup)
                    filtered = [
                        res for res in results
                        if res["title"] and not any(kw in res["title"].lower() for kw in NOISE_KEYWORDS)
                    ]
                    return filtered
                else:
                    print(f"[WARN] Unexpected status or content-type: {r.status_code}")
            except requests.RequestException as e:
                Logger.log(f"Request error for query '{query}': {e}")
                time.sleep(2)
 
        Logger.log(f"Failed to fetch results after {retries} attempts: {query}")
        return []
 
    def process_dork_batches(self, queries, start_index=0):
        total = len(queries)
        batch_size = self.threads
        index = start_index
        with ThreadPoolExecutor(max_workers=batch_size) as executor, tqdm(total=total, desc="Processing dorks", unit="query") as pbar:
            pbar.update(start_index)
            try:
                while index < total:
                    if not self.fast_mode and not SystemMonitor.resources_ok():
                        print("[INFO] High system load, waiting 10 seconds...")
                        time.sleep(10)
                        continue
                    current_batch = queries[index:index + batch_size]
                    futures = [executor.submit(self.fetch_results, q) for q in current_batch]
                    batch_results = []
                    empty_count = 0
                    for f in futures:
                        res = f.result()
                        if res:
                            batch_results.extend(res)
                        else:
                            empty_count += 1
                    empty_fraction = empty_count / len(current_batch) if current_batch else 0
                    if empty_fraction > EMPTY_BATCH_THRESHOLD:
                        Logger.log(f"High empty/noisy batch at index {index}, fraction empty: {empty_fraction:.2f}")
                        print(f"[WARN] {empty_fraction:.0%} queries returned no results in batch.")
                    self.results.extend(batch_results)
                    index += batch_size
                    pbar.update(batch_size)
            except KeyboardInterrupt:
                print("\n[INFO] Ctrl+C detected. Continue? (yes/no): ", end="", flush=True)
                if input().strip().lower().startswith("y"):
                    print("[INFO] Resuming...")
                    return self.process_dork_batches(queries, index)
                else:
                    print("[INFO] Saving results and exiting...")
                    ResultStorage.save(self.results, self.output_mode)
                    sys.exit(0)
        ResultStorage.save(self.results, self.output_mode)
        print("[INFO] Dork scanning complete.")
 
    def run(self):
        print("[INFO] Starting dork scan...")
        _ = ServerDetector.detect(self.url)
        raw_dorks = DorkFetcher.load(self.custom_dorks)
        if not raw_dorks:
            print("[ERROR] No dorks loaded. Exiting.")
            return
        translated_queries = [self.translate_dork(d) for d in raw_dorks]
        self.process_dork_batches(translated_queries)
def parse_args():
    parser = argparse.ArgumentParser(description="Dork scanner optimized with threading, caching, and TOR support.")
    parser.add_argument("url", help="Target URL or domain for dork scanning")
    parser.add_argument("-o", "--output", choices=["plaintext", "json", "encrypted", "postgres"], default=DEFAULT_STORAGE, help="Output storage mode")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Number of threads")
    parser.add_argument("--tor", action="store_true", default=DEFAULT_TOR, help="Use TOR proxy")
    parser.add_argument("--fast", action="store_true", help="Fast mode (no resource checks)")
    parser.add_argument("-e", "--engine", choices=["duckduckgo", "bing", "google"], default="duckduckgo", help="Search engine to use")
    parser.add_argument("--custom-dorks", nargs="+", help="Provide custom dorks to scan with (replaces cached/online list)")
    return parser.parse_args()
def main():
    args = parse_args()
    if args.tor and not TorManager.is_running():
        print("[WARN] TOR not detected on localhost:9050. Please ensure TOR is running.")
        sys.exit(1)
    scanner = DorkScanner(
        url=args.url,
        output_mode=args.output,
        threads=args.threads,
        use_tor=args.tor,
        fast_mode=args.fast,
        engine=args.engine,
        custom_dorks=args.custom_dorks  # Comment: Add custom dorks via CLI --custom-dorks
    )
    scanner.run()
if __name__ == "__main__":
    main()
"""
  ### General Admin & Config Exposure ###
    'allinurl:"admin" "login.php" filetype:php',
    'allinurl:"backup" "2023" filetype:zip',
    'allinurl:"config" "database" ext:json',
    'allinurl:"credentials" "backup" filetype:bak',
    'allinurl:"private" "key" filetype:key',
    'intitle:"dashboard" inurl:"admin" -site:github.com',
    'intitle:"control panel" inurl:"manage"',
    'intitle:"restricted area" inurl:"login"',
    'allintitle:"configuration" "database" filetype:ini',
    ### Sensitive Files & Passwords ###
    'filetype:env "DB_PASSWORD"',
    'filetype:sql "insert into" "password"',
    'filetype:xls intext:"password" "email"',
    'filetype:ini "user" "password"',
    'filetype:conf "password" "secret"',
    'filetype:bak "config" "password"',
    'intext:"password" "credentials" "secret"',
    'intext:"authorization" "token" "key"',
    'intext:"api_key" "secret_key"',
    'intext:"private key" "-----BEGIN"',
    'intext:"access_token" "refresh_token"',
    ### Server & Platform Info Leaks ###
    'inurl:"server-status" "Apache"',
    'intitle:"test page for apache"',    'intitle:"test page for apache"',
    'inurl:"phpinfo.php"',
    'intitle:"server information"',
    'inurl:"status" "nginx"',
    'filetype:log "error" "exception"',
    'filetype:txt "password" "database"',
    ### Git, SVN, & Version Control Exposure ###
    'inurl:"/.git/config"',
    'inurl:"/.env" "DB_PASSWORD"',
    'inurl:"/.htpasswd"',
    'inurl:"/.svn" "entries"',
    'inurl:"/.bash_history"',
    ### Logs & Debug Information ###
    'filetype:log "failed login"',
    'filetype:log "stack trace"',
    'filetype:txt "debug" "info"',
    ### Backup & Archive Files ###
    'allinurl:"backup" (ext:tar OR ext:gz OR ext:bz2)',
    'allinurl:"dump" filetype:sql',
    'allinurl:"export" filetype:xls',
    'filetype:bak "password"',
    'filetype:zip "backup"',
    'filetype:tar "config"',
    ### WordPress Specific ###
    'inurl:"wp-content/plugins/" intext:"vulnerable"',
    'allinurl:"wp-admin" "admin-ajax.php"',
    'inurl:"wp-config.php" "DB_PASSWORD"',
    'inurl:"wp-login.php"',
    'intitle:"WordPress" "error"',
    'inurl:"wp-config.php.bak"',
    'inurl:"wp-content/uploads/" "password"',
    'inurl:"readme.html" intitle:"wordpress"',
    'inurl:"xmlrpc.php" "pingback"',
    ### Joomla ###
    'inurl:"configuration.php" "password"',
    'intitle:"Joomla! Control Panel"',
    'inurl:"index.php?option=com_users&view=login"',
    'filetype:ini "joomla" "config"',
    ### Drupal ###
    'inurl:"user/register" intitle:"Drupal"',
    'inurl:"sites/default/settings.php"',
    'intitle:"Drupal" "access denied"',
    'intitle:"drupal" "error"',
    ### Magento ###
    'intitle:"Magento Admin" inurl:"admin"',
    'inurl:"downloader/index.php" intitle:"Magento"',
    'inurl:"var/export/" ext:csv',
    'filetype:log "magento" "exception"',
    'inurl:"magento/downloadable/product_links.phtml"',
    ### Laravel ###
    'inurl:"storage/logs/laravel.log"',
    'filetype:env "APP_KEY"',
    'inurl:"vendor/phpunit/phpunit" "tests"',
    'inurl:"artisan" ext:php',
    ### Django ###
    'filetype:sqlite "django_session"',
    'inurl:"admin/login/" intitle:"Django"',
    'filetype:py "SECRET_KEY"',
    'intext:"csrfmiddlewaretoken"',
    ### Ruby on Rails ###
    'filetype:yml "secret_key_base"',
    'inurl:"rails/info/properties"',
    'intitle:"Ruby on Rails" "Welcome aboard"',
    ### React/Angular/Vue (JS Frameworks) ###
    'inurl:"/static/js/main." ext:js intext:"apiKey"',
    'intext:"firebaseConfig" ext:js',
    'inurl:"/dist/" "index.html" "angular"',
    ### Cloud & DevOps ###
    'filetype:json "aws_access_key_id"',
    'filetype:yml "gcp_project_id"',
    'filetype:yaml "kubectl"',
    'filetype:tf "terraform" "access_key"',
    'filetype:ini "azure_subscription_id"',
    'filetype:log "docker" "error"',
    ### API Keys & Tokens ###
    'intext:"api_key" filetype:json',
    'intext:"bearer_token" ext:env',
    'intext:"client_secret" "oauth"',
    'intext:"PRIVATE_KEY" "-----BEGIN RSA PRIVATE KEY-----"',
    ### Database Dumps ###
    'filetype:sql "dump" "INSERT INTO"',
    'filetype:sql "password" "user"',
    'allinurl:"db_backup" ext:sql',
    'allinurl:"database.sql"',
    ### Email & Webmail Portals ###
    'intitle:"webmail login"',
    'inurl:"owa/auth/logon.aspx"',
    'intitle:"exchange server" "login"',
    'inurl:"mail" "login"',
    'intitle:"email portal"',
    ### Miscellaneous ###
    'filetype:xlsx "confidential" "salary"',
    'intext:"confidential" "nda" filetype:pdf',
    'intitle:"invoice" "due date" filetype:xls',
    'allintitle:"private" "document" ext:doc OR ext:docx',
    'allintitle:"index of" "private"',
    'allintitle:"confidential" "report" filetype:pdf',
    'inurl:"temp" "passwords"',
    'allintitle:"error log" "access denied"',
    'allintext:"secret" "key" "token" filetype:txt',
"""

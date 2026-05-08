# WAF — Web Application Firewall in C

A lightweight, high-performance Web Application Firewall written in C. It sits as a reverse proxy between clients and a backend web server, inspecting HTTP/HTTPS traffic in real time against a configurable rule set and blocking malicious requests before they reach the application.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Building](#building)
- [Configuration](#configuration)
  - [config.h](#configh)
  - [rules.conf](#rulesconf)
- [Running](#running)
- [Traffic Generator](#traffic-generator)
- [Rule Categories](#rule-categories)
- [Detection Engine](#detection-engine)
- [Logging](#logging)
- [Testing](#testing)
- [Known Limitations & Future Work](#known-limitations--future-work)

---

## Architecture Overview

```
Client (HTTP/HTTPS)
        │
        ▼
  ┌───────────┐
  │   Proxy   │  ← Listens on <port>, accepts connections, spawns threads
  └─────┬─────┘
        │
        ▼
  ┌───────────────┐
  │ Client Handler│  ← Reads raw bytes, detects TLS vs plain HTTP
  └──────┬────────┘
         │
         ▼
  ┌──────────────┐
  │ HTTP Parser  │  ← Extracts method, target, headers
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │   Firewall   │  ← Extracts security context, scores request
  └──────┬───────┘
         │
    Block? ──Yes──► 403 Forbidden + JSON log
         │ No
         ▼
  ┌──────────────────┐
  │ Backend Web Server│  ← Forwards clean request, relays response
  └──────────────────┘
```

Each client connection is handled in its own `pthread`. The WAF supports both plain HTTP and TLS (via OpenSSL).

---

## Features

- **Reverse proxy** — transparent to both client and server
- **TLS/SSL support** — auto-detects TLS Client Hello vs plain HTTP on the same port
- **Anomaly scoring** — each matched rule adds a score; the request is blocked when the total exceeds a configurable threshold
- **URL decoding** — payloads are decoded before inspection to catch `%27OR%271%27%3D%271` style bypasses
- **Case-insensitive matching** — `strcasestr` is used for string rules; `REG_ICASE` for regex rules
- **Two detection modes per rule**:
  - **String** — fast substring search
  - **Regex** (`type: 7`) — POSIX extended regular expressions via `<regex.h>`
- **JSON structured logging** — every event (blocked or allowed) is appended to `waf_log.json`
- **Live rule reloading** — rules are loaded from a JSON file at startup; the engine can be extended to reload without restart
- **Graceful shutdown** — `SIGINT` (Ctrl+C) closes sockets, frees rules, and exits cleanly
- **Comment support in rules** — `/* ... */` blocks are stripped before JSON parsing

---

## Project Structure

```
.
├── src/
│   ├── main.c                  # Entry point — loads rules, starts proxy
│   ├── proxy.c                 # Socket setup, SSL context, accept loop
│   ├── client_handler.c        # Per-connection thread, TLS detection, WAF orchestration
│   ├── request_parser.c        # Hand-written HTTP/1.x parser
│   ├── firewall.c              # Rule engine — load, inspect, score, decide
│   ├── backend_connection.c    # TCP connection to the upstream web server
│   └── internal_log.c         # Unique ID generation, JSON event logging
├── inc/
│   ├── config.h                # Compile-time configuration macros
│   ├── proxy.h
│   ├── client_handler.h
│   ├── request_parser.h        # String/Scanner/Request types
│   ├── firewall.h              # rule, ThreatType, WAF function signatures
│   └── internal_log.h         # RequestInfo, RuleMatch, WafEvent types
├── lib/
│   ├── cJSON.h / cJSON.c       # Embedded JSON parser (Dave Gamble, MIT)
│   └── log.h  / log.c          # Embedded logging library (rxi, MIT)
├── config/
│   └── rules.conf              # JSON rule definitions
├── certs/
│   ├── server.crt              # TLS certificate (provide your own)
│   └── server.key              # TLS private key (provide your own)
├── tests/
│   ├── test_parser.c           # 40+ HTTP parser unit tests
│   ├── test_firewall.c         # 70+ firewall/engine unit tests (incl. all regex rules)
│   └── test_internal_log.c     # Logging and unique ID unit tests
├── generate_traffic.py         # Python script to send legitimate and attack traffic
├── CMakeLists.txt
└── README.md
```

---

## Dependencies

| Dependency | Purpose | Bundled? |
|---|---|---|
| OpenSSL ≥ 1.1 | TLS/SSL support | No — install via package manager |
| cJSON 1.7.18 | JSON rule file parsing & log output | Yes — `lib/cJSON.c` |
| rxi/log.c | Coloured terminal logging | Yes — `lib/log.c` |
| pthreads | Per-connection threading | System |
| POSIX regex (`<regex.h>`) | Regex rule matching | System |

Install OpenSSL on common platforms:

```bash
# Debian / Ubuntu
sudo apt install libssl-dev

# Fedora / RHEL
sudo dnf install openssl-devel

# macOS (Homebrew)
brew install openssl
```

---

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

This produces the following executables inside `build/`:

| Binary | Description |
|---|---|
| `WAF` | Main firewall process |
| `test_parser` | HTTP parser unit tests |
| `test_firewall` | Firewall engine unit tests |
| `test_internal_log` | Logging unit tests |

### TLS Certificates

You must provide a certificate and private key before running:

```bash
# Generate a self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
  -out certs/server.crt -days 365 -nodes \
  -subj "/CN=localhost"
```

---

## Configuration

### config.h

Compile-time settings in `inc/config.h`:

| Macro | Default | Description |
|---|---|---|
| `MAX_CLIENT` | `200` | Maximum simultaneous connections in the listen backlog |
| `BUFFER_SIZE` | `2048` | Read buffer size per connection (bytes) |
| `WEB_SERVER_ADDR` | `127.0.0.1` | Upstream web server address |
| `WEB_SERVER_PORT` | `80` | Upstream web server port |
| `CERT_PATH` | `../certs/server.crt` | Path to TLS certificate |
| `KEY_PATH` | `../certs/server.key` | Path to TLS private key |
| `DEFAULT_RULES_CONF_PATH` | `../config/rules.conf` | Path to JSON rules file |
| `BLOCK_ENABLE` | `true` | Set to `false` to run in detection-only mode |
| `THRESHOLD` | `4` | Anomaly score threshold — requests scoring ≥ this are blocked |

### rules.conf

Rules are defined as a JSON array in `config/rules.conf`. Each rule object has the following fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique rule identifier (e.g. `"1001"`) |
| `type` | integer | Threat category (see table below) |
| `name` | string | Human-readable description |
| `pattern` | string | Substring to match, or POSIX regex if `type` is `7` |
| `score` | integer | Points added to the anomaly score on match |

**Type values:**

| Value | Category |
|---|---|
| `1` | SQL Injection |
| `2` | Cross-Site Scripting (XSS) |
| `3` | Path Traversal / LFI |
| `4` | Remote Code Execution / Command Injection |
| `5` | Bots & Scanners |
| `7` | Regex (any category) |

C-style block comments (`/* ... */`) are supported in the rules file and are stripped before parsing.

**Example rule:**

```json
{ "id": "2001", "type": 2, "name": "XSS: Script Tag", "pattern": "<script>", "score": 5 }
```

**Example regex rule:**

```json
{ "id": "7009", "type": 7, "name": "Regex XSS: Script tag with attributes", "pattern": "(?i)<script[^>]*>", "score": 5 }
```

---

## Running

```bash
# Start the WAF listening on port 8080
./build/WAF 8080
```

The WAF will:
1. Load rules from `config/rules.conf` and abort if none are found
2. Initialise the SSL context and load certificates
3. Listen on the specified port
4. Forward clean traffic to `127.0.0.1:80`
5. Append JSON events to `waf_log.json` in the working directory

Stop with `Ctrl+C` for a clean shutdown.

---

## Traffic Generator

`generate_traffic.py` sends test traffic to the WAF:

```bash
# Send 20 mixed requests (half legitimate, half attacks)
python3 generate_traffic.py -u localhost:8080 -p http -m full -c 20

# Send only SQL injection attacks
python3 generate_traffic.py -u localhost:8080 -p http -m illegal -t sqli -c 10

# Send only legitimate requests
python3 generate_traffic.py -u localhost:8080 -p http -m legal -c 50

# Target HTTPS with self-signed cert
python3 generate_traffic.py -u localhost:8443 -p https --insecure -m full -c 20
```

**Options:**

| Flag | Description |
|---|---|
| `-u` / `--url` | Target host:port |
| `-p` / `--protocol` | `http` or `https` |
| `-m` / `--mode` | `legal`, `illegal`, or `full` |
| `-t` / `--type` | `all`, `sqli`, `xss`, `lfi_rfi`, `rce` |
| `-c` / `--count` | Number of requests |
| `--insecure` | Skip SSL certificate verification |

---

## Rule Categories

The default `rules.conf` ships with **~100 rules** across 7 categories:

| Category | ID Range | Count | Examples |
|---|---|---|---|
| SQL Injection | 1001–1020 | 20 | `OR 1=1`, `UNION SELECT`, `sleep(`, `xp_cmdshell` |
| XSS | 2001–2020 | 20 | `<script>`, `alert(`, `javascript:`, `document.cookie` |
| Path Traversal | 3001–3015 | 15 | `../`, `/etc/passwd`, `.env`, `.ssh/` |
| RCE / Cmd Injection | 4001–4015 | 15 | `system(`, `/bin/bash`, `powershell`, `${jndi:` |
| Bots & Scanners | 5001–5015 | 15 | `sqlmap`, `nikto`, `burpcollaborator`, `nmap` |
| Famous CVEs | 6001–6010 | 10 | Log4Shell `${jndi:`, Shellshock `() { :; };` |
| Regex (advanced) | 7001–7039 | 39 | SSRF, SSTI, XXE, NoSQL, obfuscated payloads |

---

## Detection Engine

The inspection pipeline in `perform_waf_analysis()`:

1. **Context extraction** — `extract_security_context()` maps the raw parsed request into a `RequestInfo` struct, splitting the target into URI and query string and URL-decoding both.
2. **Multi-field inspection** — `inspect_data()` is called separately on URI, query string, `User-Agent`, and `Host`.
3. **Normalisation** — `normalize_target()` copies and URL-decodes the data before matching; `strcasestr` handles case folding for string rules.
4. **Scoring** — each matching rule adds its `score` to `event->anomaly_score`. The first (or highest-scoring) match populates `event->rule`.
5. **Decision** — if `anomaly_score >= threshold` and `BLOCK_ENABLE` is true, the request is blocked with HTTP 403.

---

## Logging

Every request produces a JSON log entry appended to `waf_log.json`:

```json
{
  "timestamp": "2024-06-01 12:00:00",
  "event_type": "waf_event",
  "request_id": "WAF-AAAAAA-00000042",
  "severity": "CRITICAL",
  "source": { "client_ip": "192.168.1.100" },
  "request": {
    "method": "GET",
    "uri": "/search",
    "query_string": "q=1 UNION SELECT NULL--",
    "host": "example.com",
    "user_agent": "Mozilla/5.0",
    "protocol": "HTTP/1.1"
  },
  "matched_rule": {
    "id": "1002",
    "message": "SQLi: Union Select",
    "matched_data": "union select",
    "target": "QUERY_STRING",
    "tag": "attack-1"
  },
  "crs": { "anomaly_score": 5, "threshold": 4 },
  "action": { "final_decision": 1 },
  "response": { "status_code": 403, "bytes_sent": 0 }
}
```

Unique request IDs follow the format `WAF-XXXXXX-NNNNNNNN` and are generated with an atomic counter protected by a mutex, making them safe for concurrent threads.

---

## Testing

Run all test suites from the build directory:

```bash
cd build

# HTTP parser tests (40+ cases)
./test_parser

# Firewall engine tests (70+ cases, including all 39 regex rules)
./test_firewall

# Logging/ID generation tests
./test_internal_log
```

Test coverage includes: valid and malformed HTTP requests, all HTTP methods, URL decoding edge cases, rule loading (valid, empty, missing, invalid JSON), anomaly scoring, threshold logic, null pointer safety, and all regex rules.

---

## Known Limitations & Future Work

- **Body inspection not implemented** — POST body content is not currently parsed or inspected. Rule matching covers URI, query string, `User-Agent`, and `Host` only.
- **Single-read buffer** — the `BUFFER_SIZE` (2048 bytes) cap means large requests may be truncated; chunked transfer encoding is not supported.
- **No rate limiting** — there is no per-IP request rate limiting or connection throttling.
- **No hot reload** — rules require a process restart to take effect.
- **No IPv6 listener** — the proxy socket is bound to `AF_INET` only.
- **No response inspection** — only inbound requests are analysed; responses from the backend are relayed as-is.
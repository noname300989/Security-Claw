---
name: http-proxy
description: |
  Full HTTP/HTTPS intercepting proxy for request/response manipulation and analysis. Built on
  mitmproxy, it enables real-time traffic interception, request modification, response tampering,
  replay attacks, and automated traffic analysis. Supports TLS inspection, WebSocket capture,
  HTTP/2, custom scripts for automated manipulation, and export to Burp Suite / HAR format.
  Ideal for manual and semi-automated web application security testing workflows.
metadata:
  {
    "openclaw":
      {
        "emoji": "🔀",
        "requires": { "bins": ["python3", "mitmproxy"] },
        "install":
          [
            {
              "id": "pip-mitmproxy",
              "kind": "shell",
              "cmd": "pip3 install mitmproxy",
              "bins": ["mitmproxy", "mitmdump", "mitmweb"],
              "label": "Install mitmproxy (pip)",
            },
          ],
      },
  }
---

# HTTP Proxy — Request/Response Manipulation

Full intercepting proxy for capturing, inspecting, and manipulating HTTP/HTTPS/WebSocket traffic.

## Quick Start

```bash
# Method 1: Interactive TUI proxy (port 8080)
mitmproxy --listen-port 8080

# Method 2: Web UI at http://127.0.0.1:8081
mitmweb --listen-port 8080

# Method 3: Silent capture to file
mitmdump -w traffic.mitm --listen-port 8080

# Method 4: With custom manipulation script
mitmdump -s skills/http-proxy/proxy_scripts.py --listen-port 8080

# Configure browser/curl to use proxy
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
curl --proxy http://127.0.0.1:8080 https://target.com
```

## Install TLS Certificate (for HTTPS inspection)

```bash
# Start proxy first, then:
curl --proxy http://127.0.0.1:8080 http://mitm.it/cert/pem -o mitmproxy-ca.pem
# Import mitmproxy-ca.pem into browser / system trust store
```

## Capabilities

### 1. Request Interception & Modification

Intercept any request and modify headers, body, method, or URL before forwarding.

**mitmproxy keybindings:** `i` → intercept filter | `e` → edit | `a` → allow/forward | `r` → resume

**Usage:**

> Start HTTP proxy and intercept all requests to api.target.com

### 2. Response Manipulation

Modify server responses in real-time — inject scripts, change status codes, alter JSON.

**Usage:**

> Intercept responses from target.com and inject XSS test payload into every HTML response

### 3. Replay & Fuzzing

Replay captured requests with modified parameters for manual fuzzing and testing.

**mitmproxy:** Select request → `v` → edit → `r` replay

```bash
# Replay with modification via mitmdump script
mitmdump -s skills/http-proxy/replay_fuzzer.py -r traffic.mitm
```

### 4. TLS / HTTPS Inspection

Transparently decrypt and inspect HTTPS traffic including HTTP/2 and QUIC.

```bash
# Transparent proxy mode (requires routing)
mitmproxy --mode transparent --listen-port 8080

# Upstream certificate check bypass (test environments only)
mitmproxy --ssl-insecure
```

### 5. WebSocket Capture

Capture and analyze WebSocket frames in real-time.

```bash
mitmweb  # WebSocket frames visible in web UI
```

### 6. Export to HAR / Burp

Export captured traffic for analysis in other tools.

```bash
# Export to HAR format
mitmdump -r traffic.mitm -s skills/http-proxy/export_har.py

# View saved flows
mitmproxy -r traffic.mitm
```

### 7. Automated Manipulation Scripts

**Inject custom header into every request:**

```python
# skills/http-proxy/inject_header.py
def request(flow):
    flow.request.headers["X-Security-Test"] = "OpenClawOS"
```

**Log all POST bodies:**

```python
def request(flow):
    if flow.request.method == "POST":
        print(f"[POST] {flow.request.url}")
        print(f"  Body: {flow.request.get_text()[:200]}")
```

**Block tracking and ads:**

```python
BLOCK_HOSTS = ["ads.tracker.com", "telemetry.vendor.com"]
def request(flow):
    if any(h in flow.request.host for h in BLOCK_HOSTS):
        flow.kill()
```

**Inject XSS test into all responses:**

```python
def response(flow):
    if "text/html" in flow.response.headers.get("content-type", ""):
        body = flow.response.get_text()
        flow.response.set_text(
            body.replace("</body>", '<script>console.log("XSS-TEST-OPENCLAW")</script></body>')
        )
```

## Usage from Red Team Agent

```
Start the HTTP proxy on port 8080 for https://api.target.com
Intercept and log all authentication requests to target.com
Replay the captured login request with modified credentials
Inject security test headers into all requests to target.com
Export captured traffic to HAR format for analysis
```

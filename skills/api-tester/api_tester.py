#!/usr/bin/env python3
"""
OpenClaw API Tester — REST & GraphQL Security Testing Engine
Supports OpenAPI/Swagger import for REST and introspection-based discovery for GraphQL.

Usage:
    # REST API assessment
    python3 api_tester.py rest --url https://api.target.com --spec swagger.json
    python3 api_tester.py rest --url https://api.target.com/users/{id} --bola --token1 TOK_A --id1 1 --token2 TOK_B --id2 2

    # GraphQL assessment
    python3 api_tester.py graphql --url https://api.target.com/graphql
    python3 api_tester.py graphql --url https://api.target.com/graphql --batch-bruteforce --wordlist passwords.txt

Requirements:
    pip3 install requests httpx pyyaml rich
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import yaml
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH = True
except ImportError:
    RICH = False
    print("[!] Install dependencies: pip3 install requests pyyaml rich")
    sys.exit(1)

console = Console()

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 (SecurityResearch/OpenClawOS)"})

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}

def finding(severity: str, title: str, detail: str, owasp: str = "", evidence: str = "") -> dict:
    return {"severity": severity, "title": title, "detail": detail, "owasp": owasp, "evidence": evidence}

def print_findings(findings: list[dict], target: str) -> None:
    if not findings:
        console.print("[green]✓ No issues found for this check.[/green]\n")
        return
    table = Table(title=f"Findings — {target}", show_lines=True, border_style="dim")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Title", width=40)
    table.add_column("OWASP", width=18)
    table.add_column("Evidence", width=50)
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f["title"],
            f.get("owasp", ""),
            f.get("evidence", f.get("detail", ""))[:120],
        )
    console.print(table)

# ─────────────────────────────────────────────────────────────────────────────
# REST API Tester
# ─────────────────────────────────────────────────────────────────────────────

class RestApiTester:
    def __init__(self, base_url: str, token: str = "", spec_path: str = ""):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.spec = None
        self.findings: list[dict] = []
        if spec_path:
            self._load_spec(spec_path)

    def _load_spec(self, path: str) -> None:
        """Load OpenAPI / Swagger spec from a local file or URL."""
        try:
            if path.startswith("http"):
                resp = SESSION.get(path, timeout=15)
                resp.raise_for_status()
                raw = resp.text
            else:
                with open(path) as f:
                    raw = f.read()
            self.spec = json.loads(raw) if raw.strip().startswith("{") else yaml.safe_load(raw)
            console.print(f"[green]✓ Loaded OpenAPI spec:[/green] {self.spec.get('info', {}).get('title', path)}")
        except Exception as e:
            console.print(f"[red]✗ Failed to load spec:[/red] {e}")

    def _auth_headers(self, token: str = "") -> dict:
        tok = token or self.token
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def _req(self, method: str, path: str, token: str = "", **kwargs) -> requests.Response | None:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        try:
            return SESSION.request(method, url, headers=self._auth_headers(token), timeout=15, **kwargs)
        except Exception as e:
            console.print(f"[dim]  Request failed: {e}[/dim]")
            return None

    def enumerate_endpoints(self) -> list[dict]:
        """Parse all routes from the loaded OpenAPI spec."""
        if not self.spec:
            console.print("[yellow]No spec loaded — skipping endpoint enumeration[/yellow]")
            return []
        endpoints = []
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("get","post","put","patch","delete","head","options"):
                    security = details.get("security", self.spec.get("security", []))
                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "summary": details.get("summary", ""),
                        "authenticated": bool(security),
                        "params": [p.get("name") for p in details.get("parameters", [])],
                    })
        console.print(f"[green]✓ Discovered {len(endpoints)} endpoints from spec[/green]")
        return endpoints

    def check_unauthenticated_access(self, endpoints: list[dict]) -> list[dict]:
        """Test authenticated endpoints without a token."""
        findings = []
        console.print("\n[bold]Testing unauthenticated access...[/bold]")
        for ep in endpoints:
            if not ep["authenticated"]:
                continue
            # Build concrete URL (replace {param} with 1)
            path = ep["path"]
            for p in ep["params"]:
                path = path.replace(f"{{{p}}}", "1")
            resp = self._req(ep["method"], path)  # no token
            if resp and resp.status_code in (200, 201, 202):
                findings.append(finding(
                    "HIGH",
                    f"Unauthenticated access to {ep['method']} {ep['path']}",
                    "Endpoint returns 2xx without authentication token.",
                    "API2:2023 Broken Authentication",
                    f"HTTP {resp.status_code}: {resp.text[:100]}",
                ))
                console.print(f"  [red]VULN[/red] {ep['method']} {ep['path']} → {resp.status_code}")
            else:
                console.print(f"  [green]OK[/green]  {ep['method']} {ep['path']} → {resp.status_code if resp else 'error'}")
        return findings

    def check_bola(self, endpoint: str, token_a: str, id_a: str, token_b: str, id_b: str) -> list[dict]:
        """Test for BOLA: use token_b to access resource owned by id_a."""
        findings = []
        console.print("\n[bold]Testing BOLA (Broken Object Level Authorization)...[/bold]")

        # Get resource A with token A (baseline)
        url_a = endpoint.replace("{id}", id_a).replace("{ID}", id_a)
        resp_a = self._req("GET", url_a, token=token_a)

        # Access resource A with token B (cross-account)
        resp_cross = self._req("GET", url_a, token=token_b)

        if resp_a and resp_cross:
            if resp_cross.status_code == 200 and resp_a.status_code == 200:
                if resp_cross.text == resp_a.text:
                    findings.append(finding(
                        "CRITICAL",
                        "BOLA — Cross-user object access confirmed",
                        f"User B (token_b) can read User A's ({id_a}) resource.",
                        "API1:2023 BOLA",
                        f"Same response body when accessed by different user token.",
                    ))
                    console.print(f"  [red bold]CRITICAL BOLA CONFIRMED[/red bold] {url_a}")
                else:
                    console.print(f"  [yellow]?[/yellow]  Different response with cross-token — may be filtered")
            elif resp_cross.status_code in (401, 403):
                console.print(f"  [green]OK[/green]  Server blocked cross-account access → {resp_cross.status_code}")
            else:
                console.print(f"  [yellow]?[/yellow]  Cross-account request returned {resp_cross.status_code}")
        return findings

    def check_mass_assignment(self, endpoint: str, method: str = "POST") -> list[dict]:
        """Test for mass assignment by sending extra privilege-escalation fields."""
        findings = []
        console.print("\n[bold]Testing Mass Assignment...[/bold]")
        payloads = [
            {"role": "admin"},
            {"isAdmin": True},
            {"admin": True, "role": "superuser"},
            {"credits": 99999},
            {"verified": True, "emailVerified": True},
        ]
        for payload in payloads:
            resp = self._req(method, endpoint, json=payload)
            if resp and resp.status_code in (200, 201):
                resp_body = resp.text[:300]
                for field, value in payload.items():
                    if str(value).lower() in resp_body.lower() or field in resp_body:
                        findings.append(finding(
                            "HIGH",
                            f"Mass assignment — '{field}' accepted by server",
                            f"The field '{field}' was accepted and reflected in the response.",
                            "API6:2023 Unrestricted Access to Sensitive Business Flows",
                            f"Payload: {json.dumps(payload)} → Response: {resp_body[:100]}",
                        ))
                        console.print(f"  [red]VULN[/red] '{field}' accepted")
            console.print(f"  Tested {json.dumps(payload)} → {resp.status_code if resp else 'error'}")
        return findings

    def check_security_headers(self, path: str = "/") -> list[dict]:
        """Validate API security headers."""
        findings = []
        console.print("\n[bold]Checking security headers...[/bold]")
        resp = self._req("GET", path)
        if not resp:
            return findings
        checks = {
            "Strict-Transport-Security": ("MEDIUM", "Missing HSTS header", "API8:2023"),
            "X-Content-Type-Options": ("LOW", "Missing X-Content-Type-Options", "API8:2023"),
            "X-Frame-Options": ("LOW", "Missing X-Frame-Options", "API8:2023"),
        }
        for header, (sev, title, owasp) in checks.items():
            if header not in resp.headers:
                findings.append(finding(sev, title, f"{header} not present in response.", owasp))
                console.print(f"  [yellow]MISS[/yellow] {header}")
            else:
                console.print(f"  [green]OK[/green]  {header}: {resp.headers[header]}")
        # Check CORS
        origin_test = self._req("GET", path, headers={"Origin": "https://evil.com"})
        if origin_test and origin_test.headers.get("Access-Control-Allow-Origin") in ("*", "https://evil.com"):
            acao = origin_test.headers.get("Access-Control-Allow-Origin")
            findings.append(finding(
                "HIGH", "Overly permissive CORS policy",
                f"Access-Control-Allow-Origin: {acao}",
                "API8:2023 Security Misconfiguration",
                f"Origin reflection: {acao}",
            ))
            console.print(f"  [red]CORS VULN[/red] Access-Control-Allow-Origin: {acao}")
        return findings

    def check_rate_limiting(self, endpoint: str, method: str = "POST",
                             requests_n: int = 50, workers: int = 10) -> list[dict]:
        """Test for missing rate limiting by sending concurrent requests."""
        findings = []
        console.print(f"\n[bold]Rate limit test ({requests_n} requests, {workers} workers)...[/bold]")
        statuses = []
        with ThreadPoolExecutor(max_workers=workers) as exe:
            futures = [exe.submit(self._req, method, endpoint, json={}) for _ in range(requests_n)]
            for f_ in as_completed(futures):
                r = f_.result()
                if r:
                    statuses.append(r.status_code)
        rate_limited = sum(1 for s in statuses if s in (429, 503))
        success = sum(1 for s in statuses if s in (200, 201, 202, 302))
        console.print(f"  Success: {success}  |  Rate-limited (429/503): {rate_limited}  |  Total: {len(statuses)}")
        if rate_limited < requests_n * 0.5 and success > 5:
            findings.append(finding(
                "MEDIUM",
                "Insufficient rate limiting",
                f"{success}/{requests_n} requests succeeded without rate-limiting response.",
                "API4:2023 Unrestricted Resource Consumption",
                f"Success: {success}, Throttled: {rate_limited} out of {requests_n}",
            ))
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL API Tester
# ─────────────────────────────────────────────────────────────────────────────

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name isDeprecated deprecationReason
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

FIELD_SUGGEST_PROBES = [
    "passsword", "secrett", "tokeen", "admiin", "privat", "internall",
    "bakcup", "debugg", "secrettKey", "apiKkey",
]

class GraphQLTester:
    def __init__(self, url: str, token: str = ""):
        self.url = url
        self.token = token
        self.schema: dict = {}
        self.findings: list[dict] = []

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _gql(self, query: str, variables: dict | None = None, batch: list | None = None) -> dict | list | None:
        payload = batch if batch else {"query": query, "variables": variables or {}}
        try:
            resp = SESSION.post(self.url, json=payload, headers=self._headers(), timeout=20)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def check_introspection(self) -> list[dict]:
        """Test whether introspection is enabled in production."""
        findings = []
        console.print("\n[bold]Testing GraphQL introspection...[/bold]")
        result = self._gql(INTROSPECTION_QUERY)
        if result and "data" in result and result["data"] and "__schema" in result["data"]:
            schema = result["data"]["__schema"]
            types = schema.get("types", [])
            user_types = [t for t in types if not t["name"].startswith("__")]
            self.schema = schema
            findings.append(finding(
                "MEDIUM",
                "GraphQL Introspection Enabled in Production",
                f"Schema exposes {len(user_types)} types.",
                "API8:2023 Security Misconfiguration",
                f"Types: {', '.join(t['name'] for t in user_types[:10])}",
            ))
            console.print(f"  [yellow]WARN[/yellow] Introspection enabled — {len(user_types)} types exposed")
            # Print types summary
            table = Table(title="Discovered GraphQL Types", border_style="dim")
            table.add_column("Type Name"); table.add_column("Kind"); table.add_column("Fields")
            for t in user_types[:20]:
                fields = ", ".join(f["name"] for f in (t.get("fields") or [])[:5])
                table.add_row(t["name"], t.get("kind",""), fields or "-")
            console.print(table)
        else:
            console.print("  [green]OK[/green]  Introspection appears disabled")
        return findings

    def check_field_suggestions(self) -> list[dict]:
        """Probe for schema leakage via GraphQL field suggestions (typos)."""
        findings = []
        console.print("\n[bold]Testing field suggestion leakage...[/bold]")
        leaked_fields = []
        for probe in FIELD_SUGGEST_PROBES:
            result = self._gql(f"{{ {probe} }}")
            if result:
                errors = result.get("errors", [])
                for err in errors:
                    msg = err.get("message", "")
                    if "did you mean" in msg.lower():
                        suggestion = msg.split("'")[-2] if "'" in msg else msg
                        leaked_fields.append(suggestion)
                        console.print(f"  [yellow]LEAK[/yellow] '{probe}' → Suggests: '{suggestion}'")
        if leaked_fields:
            findings.append(finding(
                "LOW",
                "Schema field leakage via field suggestions",
                "GraphQL error messages expose valid field names.",
                "API8:2023 Security Misconfiguration",
                f"Leaked fields: {', '.join(set(leaked_fields))}",
            ))
        else:
            console.print("  [green]OK[/green]  No field suggestions detected")
        return findings

    def check_batch_attack(self, mutation: str, variable_list: list[dict]) -> list[dict]:
        """Test for batch query attack (rate limit bypass via array of queries)."""
        findings = []
        console.print(f"\n[bold]Testing batch query attack ({len(variable_list)} queries)...[/bold]")
        batch = [{"query": mutation, "variables": v} for v in variable_list]
        result = self._gql(None, batch=batch)
        if isinstance(result, list):
            successes = [r for r in result if r.get("data") is not None and "errors" not in r]
            console.print(f"  Batch size: {len(batch)} | Successful: {len(successes)}")
            if len(successes) > 1:
                findings.append(finding(
                    "HIGH",
                    "GraphQL Batch Query Attack — Rate Limit Bypass",
                    f"{len(successes)}/{len(batch)} batch queries succeeded.",
                    "API4:2023 Unrestricted Resource Consumption",
                    f"{len(successes)} mutations processed in a single batch request",
                ))
        else:
            console.print(f"  Batch result: {str(result)[:100]}")
        return findings

    def check_depth_limit(self, query_type: str = "user", depth: int = 8) -> list[dict]:
        """Test for query depth limit enforcement."""
        findings = []
        console.print(f"\n[bold]Testing query depth limit (depth={depth})...[/bold]")
        # Build a deeply nested query
        nested = "{ id }"
        for _ in range(depth):
            nested = f"{{ id friends {nested} }}"
        q = f"{{ {query_type} {nested} }}"
        result = self._gql(q)
        if result and "data" in result and result["data"]:
            findings.append(finding(
                "MEDIUM",
                f"No query depth limit enforced (depth={depth})",
                "Server processed deeply nested query without error.",
                "API4:2023 Unrestricted Resource Consumption",
                f"Depth {depth} query returned data successfully",
            ))
            console.print(f"  [yellow]WARN[/yellow] Server allowed depth={depth} query")
        elif result and result.get("errors"):
            console.print(f"  [green]OK[/green]  Depth limit enforced → {result['errors'][0].get('message','')[:80]}")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def cli_rest(args) -> None:
    tester = RestApiTester(args.url, token=getattr(args, "token", ""), spec_path=getattr(args, "spec", "") or "")
    all_findings: list[dict] = []

    if args.spec:
        endpoints = tester.enumerate_endpoints()
        all_findings += tester.check_unauthenticated_access(endpoints)

    if args.bola and args.token1 and args.id1 and args.token2 and args.id2:
        all_findings += tester.check_bola(args.url, args.token1, args.id1, args.token2, args.id2)

    if args.mass_assignment:
        all_findings += tester.check_mass_assignment(args.url, method=args.method or "POST")

    if args.headers:
        all_findings += tester.check_security_headers(args.url)

    if args.rate_limit:
        all_findings += tester.check_rate_limiting(args.url, method=args.method or "POST")

    print_findings(all_findings, args.url)


def cli_graphql(args) -> None:
    tester = GraphQLTester(args.url, token=getattr(args, "token", "") or "")
    all_findings: list[dict] = []

    all_findings += tester.check_introspection()
    all_findings += tester.check_field_suggestions()

    if args.depth_test:
        qt = args.query_type or "user"
        all_findings += tester.check_depth_limit(query_type=qt, depth=args.depth or 8)

    if args.batch_bruteforce and args.mutation:
        wl = getattr(args, "wordlist", "") or ""
        if wl:
            try:
                with open(wl) as f:
                    passwords = [line.strip() for line in f if line.strip()][:50]
                variables = [{"email": "admin@target.com", "password": p} for p in passwords]
                all_findings += tester.check_batch_attack(args.mutation, variables)
            except Exception as e:
                console.print(f"[red]Could not read wordlist: {e}[/red]")

    print_findings(all_findings, args.url)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenClaw API Tester — REST & GraphQL Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # REST — enumerate from OpenAPI spec
  python3 api_tester.py rest --url https://api.target.com --spec https://api.target.com/openapi.json

  # REST — BOLA test
  python3 api_tester.py rest --url https://api.target.com/users/{id} --bola \\
    --token1 BEARER_A --id1 1 --token2 BEARER_B --id2 2

  # REST — full checks
  python3 api_tester.py rest --url https://api.target.com --headers --rate-limit --mass-assignment

  # GraphQL — introspection + depth test
  python3 api_tester.py graphql --url https://api.target.com/graphql --depth-test

  # GraphQL — batch bruteforce
  python3 api_tester.py graphql --url https://api.target.com/graphql \\
    --batch-bruteforce --mutation 'mutation($email:String!,$password:String!){login(email:$email,password:$password){token}}' \\
    --wordlist /usr/share/wordlists/rockyou.txt
        """,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── REST ──────────────────────────────────────────────────────────────
    rest = sub.add_parser("rest", help="REST API security testing")
    rest.add_argument("--url",             required=True, help="Base URL or target endpoint")
    rest.add_argument("--token",           default="",   help="Bearer token for authentication")
    rest.add_argument("--spec",            default="",   help="Path or URL to OpenAPI/Swagger spec")
    rest.add_argument("--method",          default="GET",help="HTTP method (GET, POST, PUT, ...)")
    rest.add_argument("--bola",            action="store_true", help="Run BOLA test")
    rest.add_argument("--token1",          default="", help="Token for user A (BOLA test)")
    rest.add_argument("--id1",             default="", help="Resource ID for user A (BOLA test)")
    rest.add_argument("--token2",          default="", help="Token for user B (BOLA test)")
    rest.add_argument("--id2",             default="", help="Resource ID for user B (BOLA test)")
    rest.add_argument("--mass-assignment", action="store_true", help="Run mass assignment test")
    rest.add_argument("--headers",         action="store_true", help="Check security headers & CORS")
    rest.add_argument("--rate-limit",      action="store_true", help="Run rate limit test")
    rest.set_defaults(func=cli_rest)

    # ── GraphQL ───────────────────────────────────────────────────────────
    gql = sub.add_parser("graphql", help="GraphQL API security testing")
    gql.add_argument("--url",             required=True, help="GraphQL endpoint URL")
    gql.add_argument("--token",           default="",   help="Bearer token for authentication")
    gql.add_argument("--depth-test",      action="store_true", help="Test query depth limits")
    gql.add_argument("--depth",           type=int, default=8, help="Nesting depth to test (default: 8)")
    gql.add_argument("--query-type",      default="user", help="Root query type for depth test (default: user)")
    gql.add_argument("--batch-bruteforce",action="store_true", help="Run batch query brute-force")
    gql.add_argument("--mutation",        default="", help="Mutation string for batch brute-force")
    gql.add_argument("--wordlist",        default="", help="Password wordlist for batch brute-force")
    gql.set_defaults(func=cli_graphql)

    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold red]OpenClaw API Tester[/bold red]\n"
        "[dim]REST & GraphQL Security Engine — Mapped to OWASP API Security Top 10 2023[/dim]",
        border_style="red",
    ))
    args.func(args)


if __name__ == "__main__":
    main()

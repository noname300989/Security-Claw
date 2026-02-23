---
name: web-search
description: "Web search and page fetching via `web_search` (Brave/Perplexity) and `web_fetch` (HTML→markdown). Use when: (1) searching the web for current information, (2) fetching and reading public web pages, (3) researching CVEs, tools, or documentation. NOT for: JS-heavy sites or login-required pages (use browser tool), or local file reading (use read tool)."
metadata: { "openclaw": { "emoji": "🔍" } }
---

# Web Search + Fetch

Search the web and fetch readable page content without a full browser.

## When to Use

✅ **USE this skill when:**

- Looking up current CVEs, exploits, or security advisories
- Fetching public documentation or API references
- Searching for tool documentation, configs, or news
- Reading the content of a URL (static HTML sites)
- Research tasks that don't need JavaScript execution

## When NOT to Use

❌ **DON'T use this skill when:**

- The page requires JavaScript to render → use `browser` tool
- The page requires a login → use `browser` tool
- Reading local files → use `read` tool
- Bulk crawling sites → use `browser` + loop

## Providers

| Provider             | Best for                           | API Key Required                             |
| -------------------- | ---------------------------------- | -------------------------------------------- |
| **Brave** (default)  | Fast structured results            | `BRAVE_API_KEY`                              |
| **Perplexity Sonar** | AI-synthesized answers + citations | `OPENROUTER_API_KEY` or `PERPLEXITY_API_KEY` |

## web_search

### Basic Search

```json
{ "tool": "web_search", "query": "CVE-2024-1234 exploit PoC" }
```

### With Options

```json
{
  "tool": "web_search",
  "query": "nuclei templates SSRF",
  "count": 10,
  "freshness": "pw"
}
```

### Freshness Filters

| Value                    | Meaning                   |
| ------------------------ | ------------------------- |
| `pd`                     | Past day                  |
| `pw`                     | Past week                 |
| `pm`                     | Past month                |
| `py`                     | Past year                 |
| `YYYY-MM-DDtoYYYY-MM-DD` | Custom range (Brave only) |

### Region / Language

```json
{
  "tool": "web_search",
  "query": "vulnerability disclosure",
  "country": "US",
  "search_lang": "en"
}
```

## web_fetch

Fetch a URL and get readable markdown/text content:

```json
{ "tool": "web_fetch", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234" }
```

### With Options

```json
{
  "tool": "web_fetch",
  "url": "https://docs.example.com/api",
  "extractMode": "markdown",
  "maxChars": 20000
}
```

### Parameters

| Parameter     | Notes                                  |
| ------------- | -------------------------------------- |
| `url`         | Required, http/https only              |
| `extractMode` | `markdown` (default) or `text`         |
| `maxChars`    | Truncate long pages (capped by config) |

> [!NOTE]
> Results are cached for 15 minutes. `web_fetch` does not execute JavaScript — for SPAs or auth-required pages, use the `browser` tool.

## Setup

### Brave Search (default)

```bash
openclaw configure --section web
# Enter BRAVE_API_KEY when prompted
```

Or set in config:

```json5
{
  tools: { web: { search: { apiKey: "YOUR_BRAVE_KEY", enabled: true } } },
}
```

### Perplexity via OpenRouter

```json5
{
  tools: {
    web: {
      search: {
        provider: "perplexity",
        perplexity: {
          apiKey: "sk-or-v1-...",
          baseUrl: "https://openrouter.ai/api/v1",
          model: "perplexity/sonar-pro",
        },
      },
    },
  },
}
```

### Perplexity Models

| Model                            | Best for            |
| -------------------------------- | ------------------- |
| `perplexity/sonar`               | Fast Q&A            |
| `perplexity/sonar-pro`           | Multi-step research |
| `perplexity/sonar-reasoning-pro` | Deep analysis       |

## Usage from Agent

```
Search for recent exploits for CVE-2024-1234
Fetch the nuclei templates documentation page
Find the latest news about Apache Log4j vulnerabilities from the past week
Look up the OWASP API Security Top 10 2023
```

---
name: firecrawl
description: "Fetch web pages with bot-circumvention via Firecrawl as a fallback for `web_fetch`. Use when: (1) web_fetch fails due to bot protection (Cloudflare, captchas), (2) scraping JavaScript-heavy pages without a full browser, (3) needing cached, clean markdown from heavily protected sites. Requires Firecrawl API key configured."
metadata:
  { "openclaw": { "emoji": "🔥", "requires": { "config": ["tools.web.fetch.firecrawl.apiKey"] } } }
---

# Firecrawl — Bot-Bypass Web Fetching

Fetch content from bot-protected websites as a fallback for `web_fetch`.

## When to Use

✅ **USE this skill when:**

- `web_fetch` returns a Cloudflare or bot-protection block
- The target page uses heavy JavaScript rendering (but you don't need a full browser session)
- You need clean, cached markdown from a protected site
- Batch scraping multiple URLs from a protected domain

## When NOT to Use

❌ **DON'T use this skill when:**

- Page loads fine with `web_fetch` → no need for Firecrawl overhead
- Page requires a user login session → use `browser` tool
- You need real-time DOM interaction → use `browser` tool

## Setup

Get an API key at [firecrawl.dev](https://firecrawl.dev/) and configure:

```json5
{
  tools: {
    web: {
      fetch: {
        firecrawl: {
          enabled: true,
          apiKey: "fc-YOUR_API_KEY",
          baseUrl: "https://api.firecrawl.dev",
          onlyMainContent: true,
          maxAgeMs: 86400000,
          timeoutSeconds: 60,
        },
      },
    },
  },
}
```

Or set the `FIRECRAWL_API_KEY` environment variable.

## How It Works

Firecrawl is automatically used as a **fallback** by `web_fetch` when the primary extractor fails:

```
web_fetch → Readability extraction → ✓ done
                                  → ✗ failed → Firecrawl fallback → result
```

No separate tool call is needed — just use `web_fetch` normally:

```json
{
  "tool": "web_fetch",
  "url": "https://protected-site.com/research-page",
  "extractMode": "markdown"
}
```

## Firecrawl Config Options

| Option            | Default                     | Description               |
| ----------------- | --------------------------- | ------------------------- |
| `enabled`         | `false`                     | Enable Firecrawl fallback |
| `apiKey`          | —                           | Your Firecrawl API key    |
| `baseUrl`         | `https://api.firecrawl.dev` | API base URL              |
| `onlyMainContent` | `true`                      | Extract only main content |
| `maxAgeMs`        | `86400000`                  | Cache TTL (1 day)         |
| `timeoutSeconds`  | `60`                        | Request timeout           |

## Notes

> [!NOTE]
> Firecrawl caches results by URL. Repeated fetches within `maxAgeMs` return cached results.
> For fresh content, clear the cache or increase `maxAgeMs` to `0`.

> [!CAUTION]
> Firecrawl uses bot-evasion techniques. Only use it on sites you have authorization to access.

## Usage from Agent

```
Fetch the content from https://protected-site.com/report — use Firecrawl if web_fetch fails
Scrape the CVE details page that has Cloudflare protection using Firecrawl
Get clean markdown from the heavily protected vendor advisory page
```

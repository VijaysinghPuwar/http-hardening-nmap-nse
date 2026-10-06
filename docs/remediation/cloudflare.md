# Cloudflare

When a site is proxied through Cloudflare, the scanner sees Cloudflare's response: headers from your origin plus whatever Cloudflare adds, removes or overrides. Scan the public hostname to judge what browsers get, and the origin directly (if you are authorized) to see what it sends on its own.

## Redirect and HSTS

- **SSL/TLS > Edge Certificates > Always Use HTTPS** redirects plain HTTP (`no-https-redirect`).
- **SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS)** sets `max-age`, `includeSubDomains` and `preload`. The dashboard warns that HSTS is hard to undo; the same advice applies as anywhere else.

## Other headers

Use a **Response Header Transform Rule** (Rules > Transform Rules) to set static headers for all or some requests:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

A static header cannot carry a per-request CSP nonce. Nonce-based policies need the application or a Worker to generate the nonce and insert it into both the header and the HTML.

**Managed Transforms** include one that removes `X-Powered-By` (`tech-disclosure`, `info-disclosure`) and a preset that adds a set of security headers. Check which headers that preset adds before enabling it: presets can include legacy headers such as `X-XSS-Protection`, which this tool reports as `xxp-enabled` (INFO).

## What Cloudflare cannot fix

Cookie flags, CORS decisions and exposed files (`/.git/HEAD`, `/.env`) come from the origin. Fix them there; the CDN only passes them through. Cloudflare's own `Server: cloudflare` header has no version and is not reported.

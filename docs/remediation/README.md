# Remediation guides

Server-specific ways to fix the findings in [checks.md](../checks.md):

- [nginx](nginx.md)
- [Apache httpd](apache.md)
- [IIS](iis.md)
- [Cloudflare](cloudflare.md)

Before copying any header into production:

- **CSP breaks things.** Deploy it as `Content-Security-Policy-Report-Only` first, collect reports, then enforce. Inline scripts need nonces or hashes, which usually means an application change.
- **HSTS is sticky.** Browsers remember it for `max-age` seconds. Start with a short max-age, add `includeSubDomains` only when every subdomain serves HTTPS, and treat `preload` as close to permanent.
- **Permissions-Policy and cross-origin isolation are per application.** Disable what you do not use; COEP in particular breaks pages that load cross-origin resources without CORP or CORS.
- **Set headers in one place.** If the application and a proxy both set the same header, you get duplicates, and the script judges what browsers would do with them (for example, conflicting X-Frame-Options values are ignored).

Re-scan after each change; the score and the finding list show exactly what moved.

# Checks

Every finding the script can report, grouped by area. Severity is the built-in default; a [policy](policy.md) can change it or turn a check off. References are given only where the mapping is direct: CWE, OWASP Top 10 (2021) and OWASP ASVS 4.0.3 requirement numbers.

This file is checked against the script by a unit test, so every finding ID listed here exists and every ID the script can emit is listed.

## Transport and HSTS

Plain HTTP is judged on whether it redirects to HTTPS. HSTS is judged only on TLS responses: browsers ignore it over plain HTTP (RFC 6797 section 8.1), so a missing HSTS header on port 80 is not a finding.

Only the first HSTS header counts, and a header with a repeated directive is invalid and ignored by browsers (RFC 6797 section 6.1). `preload` in the header does not prove the domain is on the preload list; the script never claims enrollment. `hsts-no-subdomains` is INFO unless the policy sets `hsts.require_include_subdomains`, which raises it to at least LOW.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="no-https-redirect"></a>`no-https-redirect` | MEDIUM | Plain HTTP without redirect to HTTPS | CWE-319 | A02:2021 | 9.1.1 | Redirect all plain HTTP requests to HTTPS with 301 or 308. |
| <a id="hsts-missing"></a>`hsts-missing` | MEDIUM | HSTS header missing | CWE-319 | A05:2021 | 14.4.5 | Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses. |
| <a id="hsts-invalid"></a>`hsts-invalid` | MEDIUM | HSTS header is invalid and ignored | CWE-319 | A05:2021 | 14.4.5 | Send exactly one max-age directive with a numeric value. |
| <a id="hsts-disabled"></a>`hsts-disabled` | MEDIUM | HSTS disabled with max-age=0 | CWE-319 | A05:2021 | 14.4.5 | Set max-age to at least one year once HTTPS works for the whole site. |
| <a id="hsts-short-max-age"></a>`hsts-short-max-age` | LOW | HSTS max-age below policy minimum | CWE-319 | A05:2021 | 14.4.5 | Raise max-age to the policy minimum (one year is common). |
| <a id="hsts-no-subdomains"></a>`hsts-no-subdomains` | INFO | HSTS does not cover subdomains | - | - | 14.4.5 | Add includeSubDomains once every subdomain serves HTTPS. |
| <a id="hsts-no-preload"></a>`hsts-no-preload` | INFO (off) | HSTS preload directive absent | - | - | - | Add preload and submit the domain at hstspreload.org if every subdomain is HTTPS-only. |
| <a id="hsts-over-http"></a>`hsts-over-http` | INFO | HSTS sent over plain HTTP is ignored | - | - | - | Send HSTS on HTTPS responses; redirect plain HTTP to HTTPS. |

## Content-Security-Policy

The policy is judged for what it lets scripts do, not for being present. Rules that follow browser behaviour:

- `'unsafe-inline'` is ignored by browsers when the same directive has a nonce or hash, so it is not reported then.
- `'strict-dynamic'` makes browsers ignore host and scheme sources, so `https:` next to it is not reported.
- `script-src` falls back to `default-src`; so does `object-src`. `base-uri` does not fall back.
- Several enforced policies (several headers, or a header plus a `<meta>` tag) must all allow a resource, so a weakness is reported only when every policy has it.
- A `<meta http-equiv="Content-Security-Policy">` tag counts for scripts, but its `frame-ancestors` is ignored (browsers ignore it there too).
- Report-Only alone is `csp-report-only`. Report-Only next to an enforced policy is not reported.

These are policy weaknesses, not proof of exploitable XSS. `'unsafe-inline'` matters only if an attacker can inject markup; the finding says the browser would not stop it.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="csp-missing"></a>`csp-missing` | MEDIUM | Content-Security-Policy missing | CWE-693 | A05:2021 | 14.4.3 | Deploy a CSP that restricts script-src, starting in Report-Only mode. |
| <a id="csp-report-only"></a>`csp-report-only` | LOW | CSP is Report-Only and not enforced | CWE-693 | A05:2021 | 14.4.3 | Promote the policy to Content-Security-Policy once reports are clean. |
| <a id="csp-no-script-restriction"></a>`csp-no-script-restriction` | MEDIUM | CSP does not restrict scripts | CWE-693 | A05:2021 | 14.4.3 | Add script-src or default-src to the policy. |
| <a id="csp-unsafe-inline"></a>`csp-unsafe-inline` | MEDIUM | CSP allows inline scripts | CWE-693 | A05:2021 | 14.4.3 | Replace 'unsafe-inline' with nonces or hashes. |
| <a id="csp-unsafe-eval"></a>`csp-unsafe-eval` | LOW | CSP allows eval() | CWE-693 | A05:2021 | 14.4.3 | Remove 'unsafe-eval'; refactor code that builds scripts from strings. |
| <a id="csp-broad-script-source"></a>`csp-broad-script-source` | MEDIUM | CSP allows scripts from any host or data: URLs | CWE-693 | A05:2021 | 14.4.3 | List specific script hosts, or use nonces with 'strict-dynamic'. |
| <a id="csp-no-object-src"></a>`csp-no-object-src` | LOW | CSP does not restrict plugins (object-src) | CWE-693 | A05:2021 | 14.4.3 | Add object-src 'none'. |
| <a id="csp-no-base-uri"></a>`csp-no-base-uri` | INFO | CSP does not restrict base-uri | CWE-693 | - | 14.4.3 | Add base-uri 'none' or 'self'; base-uri does not fall back to default-src. |

## Framing (clickjacking)

CSP `frame-ancestors` (header only) overrides X-Frame-Options in current browsers, so a restrictive `frame-ancestors` passes without X-Frame-Options, and `frame-ancestors *` fails even next to `X-Frame-Options: DENY`. Without `frame-ancestors`, X-Frame-Options must be `DENY` or `SAMEORIGIN`; `ALLOW-FROM` is ignored by current browsers, and conflicting repeated values are ignored as a whole.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="framing-missing"></a>`framing-missing` | MEDIUM | No clickjacking protection | CWE-1021 | A05:2021 | 14.4.7 | Add CSP frame-ancestors 'none' (or 'self'); X-Frame-Options DENY for old browsers. |
| <a id="framing-allowed"></a>`framing-allowed` | MEDIUM | Framing protection is ineffective | CWE-1021 | A05:2021 | 14.4.7 | Use CSP frame-ancestors with explicit origins instead of * or ALLOW-FROM. |

## Other response headers

Referrer-Policy may list several values; the browser uses the last one it recognises, and so does the script. Only `unsafe-url` and `no-referrer-when-downgrade` are reported as leaky.

There is no single correct Permissions-Policy, so a missing header is INFO and only granting a powerful feature (camera, microphone, geolocation, payment, USB and similar) to every origin is LOW.

Cross-origin isolation headers (COOP, COEP, CORP) are needed by some applications and break others, so `cross-origin-isolation-missing` is off in the baseline policy and INFO in the strict policy.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="xcto-missing"></a>`xcto-missing` | LOW | X-Content-Type-Options is not nosniff | CWE-693 | A05:2021 | 14.4.4 | Send X-Content-Type-Options: nosniff on all responses. |
| <a id="referrer-policy-missing"></a>`referrer-policy-missing` | INFO | Referrer-Policy missing or unrecognised | - | - | 14.4.6 | Send Referrer-Policy: strict-origin-when-cross-origin (or stricter). |
| <a id="referrer-policy-leaky"></a>`referrer-policy-leaky` | LOW | Referrer-Policy leaks full URLs cross-origin | CWE-200 | A05:2021 | 14.4.6 | Use strict-origin-when-cross-origin, same-origin or no-referrer. |
| <a id="permissions-policy-missing"></a>`permissions-policy-missing` | INFO | Permissions-Policy missing | - | - | - | Disable browser features the site does not use, e.g. camera=(), microphone=(), geolocation=(). |
| <a id="permissions-policy-permissive"></a>`permissions-policy-permissive` | LOW | Permissions-Policy grants powerful features to any origin | - | - | - | Restrict powerful features to self or named origins instead of *. |
| <a id="cross-origin-isolation-missing"></a>`cross-origin-isolation-missing` | INFO (off) | Cross-origin isolation headers missing | - | - | - | Consider Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy where compatible. |

## Cookies

Cookies are classified by name. Session-like names (containing `sess`, `auth`, `token`, `jwt`, `login`, `remember`, or ending in `sid`, such as `PHPSESSID`, `JSESSIONID`, `connect.sid`) get the full checks. CSRF tokens (`csrf`, `xsrf`) are designed to be read by JavaScript for the double-submit pattern, so HttpOnly is never demanded for them. Other cookies are reported together as one INFO finding, because the script cannot know whether a script needs them.

Secure is only demanded on HTTPS responses. On plain HTTP the problem is the missing redirect, which is already a finding.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="cookie-no-secure"></a>`cookie-no-secure` | MEDIUM | Session cookie without Secure over HTTPS | CWE-614 | A05:2021 | 3.4.1 | Add the Secure attribute to session cookies. |
| <a id="cookie-no-httponly"></a>`cookie-no-httponly` | LOW | Session cookie readable by JavaScript | CWE-1004 | A05:2021 | 3.4.2 | Add HttpOnly to session cookies that scripts do not need to read. |
| <a id="cookie-samesite-none-insecure"></a>`cookie-samesite-none-insecure` | LOW | SameSite=None cookie without Secure | CWE-1275 | A05:2021 | 3.4.3 | Browsers reject SameSite=None without Secure; add Secure or use Lax. |
| <a id="cookie-no-samesite"></a>`cookie-no-samesite` | INFO | Session cookie without SameSite | CWE-1275 | - | 3.4.3 | Set SameSite=Lax (or Strict) explicitly; browser defaults differ. |
| <a id="cookie-flags-nonsession"></a>`cookie-flags-nonsession` | INFO | Non-session cookies without Secure or HttpOnly | - | - | - | Review whether these cookies need to be readable by scripts or sent over plain HTTP. |

## CORS

The single GET carries `Origin: https://hardening-check.invalid`, a name that cannot exist. If the response echoes it, the server reflects any origin. With `Access-Control-Allow-Credentials: true` that lets any website read authenticated responses, which is the only HIGH finding in the default catalog.

`Access-Control-Allow-Origin: *` on its own is normal for public resources and is not reported. `*` together with credentials is LOW: browsers refuse the combination, so it is not exploitable as sent, but it shows a policy that intends to allow credentials broadly. A reflected `null` origin is not tested (it needs a second request with a different Origin).

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="cors-reflected-credentials"></a>`cors-reflected-credentials` | HIGH | CORS reflects arbitrary origins with credentials | CWE-942 | A05:2021 | 14.5.3 | Match the Origin against an allowlist before echoing it; never reflect it with credentials. |
| <a id="cors-reflected-origin"></a>`cors-reflected-origin` | LOW | CORS reflects arbitrary origins | CWE-942 | A05:2021 | 14.5.3 | Match the Origin against an allowlist, or use * deliberately for public resources. |
| <a id="cors-wildcard-credentials"></a>`cors-wildcard-credentials` | LOW | CORS wildcard combined with credentials | CWE-942 | A05:2021 | 14.5.3 | Browsers refuse this combination; decide whether credentials are needed and list origins explicitly. |

## Information disclosure and deprecated headers

A version number in `Server`, `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` is LOW; it speeds up matching known vulnerabilities but is not a vulnerability itself. The same headers without a version are INFO. Deprecated headers are INFO: they do no harm, except `X-XSS-Protection: 1`, which enabled a filter that browsers have removed.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="info-disclosure"></a>`info-disclosure` | LOW | Software version disclosed | CWE-200 | A05:2021 | 14.3.3 | Remove version numbers from Server and X-Powered-By style headers. |
| <a id="tech-disclosure"></a>`tech-disclosure` | INFO | Technology disclosed in headers | CWE-200 | - | 14.3.3 | Drop X-Powered-By and similar headers; they help fingerprinting only. |
| <a id="xxp-enabled"></a>`xxp-enabled` | INFO | Legacy X-XSS-Protection filter enabled | - | - | - | Set X-XSS-Protection: 0 or drop it; rely on CSP. |
| <a id="hpkp-present"></a>`hpkp-present` | INFO | Deprecated Public-Key-Pins header | - | - | - | Remove Public-Key-Pins; browsers removed HPKP support. |
| <a id="expect-ct-present"></a>`expect-ct-present` | INFO | Deprecated Expect-CT header | - | - | - | Remove Expect-CT; Certificate Transparency is enforced by browsers without it. |

## Exposure (opt-in)

`directory-listing` is checked on every response the script fetches. The rest needs `exposure=true` (or `exposure.enabled` in a policy) or an explicit `paths` list.

Built-in paths: `/.git/HEAD`, `/.env`, `/server-status`, `/actuator/env`, `/phpinfo.php`, `/.DS_Store`, `/backup.zip`, `/admin`, `/wp-admin/`, plus one `TRACE /`.

- A sensitive file is reported only when the body matches a content signature (a git ref, `KEY=value` lines, the ZIP or .DS_Store magic bytes, an Apache status page, actuator JSON, phpinfo output). A single page app that answers every path with its index page is therefore never reported.
- Paths without a signature (`/admin`, `/wp-admin/`, and any path you add) use Nmap's soft-404 detection (`http.identify_404`, `http.page_exists`), so "200 for everything" servers are not reported.
- Response bodies are never copied into results; evidence describes the match. A real `.env` file's values do not end up in a report.
- Probes use GET (and one TRACE), bodies are capped at 64 KB, and the list is bounded by `max-paths` (default 25). Nothing is sent that changes state, authenticates, or guesses credentials.

| ID | Default | Finding | CWE | Top 10 | ASVS | Fix |
|---|---|---|---|---|---|---|
| <a id="directory-listing"></a>`directory-listing` | MEDIUM | Directory listing enabled | CWE-548 | A05:2021 | 4.3.2 | Disable autoindex/directory browsing. |
| <a id="trace-enabled"></a>`trace-enabled` | LOW | HTTP TRACE method enabled | - | A05:2021 | 14.5.1 | Disable TRACE (TraceEnable Off, or deny the method at the proxy). |
| <a id="path-exposed"></a>`path-exposed` | MEDIUM | Configured path is reachable | - | A05:2021 | - | Restrict or remove the path if it should not be public. |
| <a id="admin-interface-reachable"></a>`admin-interface-reachable` | LOW | Administrative interface reachable | - | A05:2021 | - | Restrict administrative paths by network or authentication. |
| <a id="exposed-git"></a>`exposed-git` | HIGH | Git repository metadata exposed | CWE-538 | A05:2021 | - | Block /.git/ at the web server and remove it from the document root. |
| <a id="exposed-env"></a>`exposed-env` | HIGH | Environment file exposed | CWE-538 | A05:2021 | - | Remove .env from the document root and rotate any secrets it contained. |
| <a id="exposed-actuator-env"></a>`exposed-actuator-env` | HIGH | Spring Boot actuator env endpoint exposed | CWE-200 | A05:2021 | 14.3.2 | Do not expose actuator endpoints publicly; require authentication. |
| <a id="exposed-backup-archive"></a>`exposed-backup-archive` | HIGH | Backup archive downloadable | CWE-538 | A05:2021 | - | Remove backup files from the document root. |
| <a id="exposed-server-status"></a>`exposed-server-status` | MEDIUM | Apache server-status exposed | CWE-200 | A05:2021 | 14.3.2 | Restrict mod_status to localhost or an admin network. |
| <a id="exposed-phpinfo"></a>`exposed-phpinfo` | MEDIUM | phpinfo() page exposed | CWE-200 | A05:2021 | 14.3.2 | Remove phpinfo pages from production. |
| <a id="exposed-ds-store"></a>`exposed-ds-store` | LOW | .DS_Store file exposed | CWE-538 | A05:2021 | - | Remove .DS_Store files and block dotfiles at the web server. |

## What is not checked

- TLS protocol versions, ciphers and certificates. Use Nmap's `ssl-enum-ciphers` and `ssl-cert` scripts, which do this well.
- Pages other than the evaluated one (default `/`). There is no crawler.
- Application logic, authentication and injection flaws. This is a configuration audit, not a vulnerability scanner.

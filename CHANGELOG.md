# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-05

First tagged release. The script now evaluates HTTP hardening against a policy instead of checking whether three headers exist, and a companion CLI turns results into reports and CI decisions.

### Added

- **Policy as code.** JSON policies with presets `baseline` (built-in default), `strict` and `owasp-asvs-l1`, a JSON Schema, and strict validation: an unknown key or finding ID is an error, never a silently weaker scan.
- **Scoring.** 0 to 100 score and A to F grade per port, documented in `docs/scoring.md`. Info findings never affect the score.
- **Findings model.** 48 finding IDs, each with severity, title, detail, evidence, recommendation and CWE, OWASP Top 10 and OWASP ASVS 4.0.3 references where the mapping is direct.
- **More checks:** CSP `object-src` and `base-uri`, CSP from `<meta>` tags, several CSP policies combined the way browsers combine them, Permissions-Policy, cross-origin isolation headers (opt-in), CORS wildcard with credentials, deprecated HPKP and Expect-CT, technology disclosure without versions, directory listings, HSTS preload (opt-in, never claimed as enrollment).
- **Opt-in exposure probing** (`exposure=true`): `/.git/HEAD`, `/.env`, `/server-status`, `/actuator/env`, `/phpinfo.php`, `/.DS_Store`, `/backup.zip`, `/admin`, `/wp-admin/` and one TRACE. Sensitive files are reported only on a content signature; response bodies are never copied into results.
- **Error states** (`timeout`, `no-response`, `unsupported-response`, `policy-error`, ...) reported as `result: ERROR` instead of empty output.
- **`hhc-report`** (Python, standard library only): table, JSON (with a schema), CSV, Markdown, HTML and SARIF 2.1.0 output; `--fail-on` CI gating with documented exit codes; `--baseline` drift detection where only new findings fail.
- **Docker lab** with real nginx (hardened, weak and single-page-app virtual hosts) and Apache, on an internal network with no published ports, plus a scanner container running Alpine's Nmap.
- **GitHub Action** (`action.yml`) that refuses public targets unless `allow-public-targets: true` is set.
- **Tests:** Lua engine unit tests, reporter tests, integration tests against the Python and Docker labs, a stress suite and parser fuzzing; CI with least-privilege permissions, SHA-pinned actions and a secret scan.
- Documentation: `docs/checks.md`, `docs/policy.md`, `docs/scoring.md`, `docs/reporter.md`, remediation guides for nginx, Apache, IIS and Cloudflare. `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`.

### Changed

- Cookie checks distinguish session cookies, CSRF tokens (which scripts must read) and other cookies, instead of demanding HttpOnly on everything.
- `cookie-samesite-none-insecure` is LOW (browsers reject such cookies outright), not MEDIUM.
- The default fail threshold, finding IDs and console layout changed; the console shows score, grade and policy.
- `tools/report.py` is replaced by `hhc-report`.

### Fixed

- Probes after a redirect were sent over TLS to plain-HTTP ports and got no response, because Nmap's `http.get` writes `options.scheme` into the caller's options table. Every request now gets its own options.
- A 3xx response without `Location` was described as a redirect loop.
- Errors from the network could break console output across lines.

### Removed

- Script arguments `headers`, `brief` and `host` from 1.x. Using them now prints a warning naming the replacement.

## 1.x - 2025-12 (untagged)

`http_hardening_check.nse`: presence check for HSTS, CSP and X-Frame-Options on `/`, optional `/admin` probe, one-line output. Superseded by 2.0.0, which fixes its argument parsing, SNI, HSTS-over-HTTP, framing and soft-404 problems (see the commit history of pull request #1 and this release).

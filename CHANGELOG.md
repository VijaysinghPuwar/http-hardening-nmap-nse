# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Robustness pass driven by a stress and fuzzing campaign against the script: every item below was reproduced against the lab before it was fixed, and each has a regression test.

### Fixed

- **`vhost` with an empty or over-255-character value aborted the whole Nmap run.** OpenSSL rejects such a name in `SSL_set_tlsext_host_name`, which is fatal: Nmap finished with `exit="error"` and scanned nothing, including other hosts, ports and scripts. The value is now validated before the first request and reported as `result: ERROR`, `error: argument-error`.
- **`hsts-min=1.5` and `hsts-min=1e400` aborted the script** with `bad argument #2 to 'format' (number has no integer representation)` when a target's `max-age` fell below the minimum. `hsts-min` and `max-paths` now have to be whole numbers, as the equivalent policy keys already did.
- **`timeout=-5` aborted the script** inside `http.get`. A timeout that is not a positive whole number of milliseconds now falls back to the default, like other unparseable optional values.
- **The `path` argument was not validated,** so `path=/a b` or `path=` produced a malformed request line and the score was then reported against whatever the server made of it (usually a 400). It now goes through the same check as `paths` and is reported as `argument-error`. A value without a leading slash is normalised instead of refused.
- **`X-Content-Type-Options: nosniff, nosniff`** (what a proxy that duplicates the header, and Nmap's header joining, produce) was reported as `xcto-missing`. Fetch's "determine nosniff" reads the first comma-separated value, so this is nosniff. A header whose first value is not `nosniff` is still flagged.
- **A reflected `Access-Control-Allow-Origin` with surrounding whitespace was missed,** dropping the HIGH `cors-reflected-credentials` finding. Header values are compared trimmed.
- **IPv6 targets produced unusable URLs** such as `http://::1:8080/` instead of `http://[::1]:8080/` (RFC 3986), in the console, the XML, the JSON report, SARIF locations and the HTML report.
- **A policy document that was a JSON array, `null`, a number, a string or a boolean was accepted** and silently became an empty policy; only `{}` could be told apart by shape. The decoder's own type is now checked, so `[]` and `null` are refused like any other malformed policy.
- **`Location:` with an empty or whitespace-only value was followed,** which resolved back to the current page and was reported as a redirect loop. It is now treated as a 3xx without a usable `Location`. A redirect target that is not a usable request path is reported as `unusable Location ...` instead of being requested.
- **A `max-age` with more digits than a 64-bit integer holds** was kept as a float, which could not be formatted and was a latent abort. It is capped at the largest integer.
- A `Location` header quoted in the `note` line was copied through as the server sent it. Like other text from the network it is now stripped of control characters and shortened, so one response cannot spread the console output over several lines.
- Explicit probe paths (`paths=`, `exposure.paths`) are probed **before** the built-in exposure catalog, so a small `max-paths` no longer silently drops the list the operator asked for.

### Fixed (`hhc-report`)

- **The XML entity guard could be bypassed by changing the encoding.** The check searches raw bytes for `<!ENTITY`, so a UTF-16 or UTF-32 document slipped past it, and `xml.etree.ElementTree` does expand internal entities. The reader now refuses input that contains NUL bytes or is not UTF-8, which is what Nmap writes.
- A file declaring a multi-byte encoding made `ElementTree` raise `ValueError`, which was not caught, so the CLI exited with a traceback instead of `hhc-report: ... cannot be parsed as XML`.
- The gate summary used an `assert` for type narrowing, which `python -O` strips.

### Added

- Lab targets for every case above: `/dup-xcto`, `/xcto-sniff-first`, `/cors-padded`, `/cors-wildcard-padded`, `/hsts-huge`, `/hsts-repeated-directive`, `/meta-csp`, `/empty-location`, `/blank-location`, `/long-location` on port 8445, and the `bare` profile on `[::1]:8086` for IPv6 URL formatting.
- Stress suite grown from 42 to 84 tests, including engine invariants under random input (score monotonicity, CSP combination, `clean_paths` bounds, `summarise` counts and ordering, exposure signatures on arbitrary bytes), a determinism soak over every lab port, and a check that an invalid argument never aborts the Nmap run.
- `tests/integration/test_differential.py`: runs this script and Nmap's bundled `http-security-headers` in one scan and asserts that every header the bundled script lists is either passed or judged here, so the difference the README claims cannot silently regress.
- `make lint` now also runs `shellcheck`, `hadolint`, `actionlint`, `yamllint` and `bandit`, with `.yamllint.yml` and `bandit.yml` recording why each suppression exists. The CI lint job requires all of them.

### Changed

- `lab/docker/scanner/scan.sh` passes its targets through the positional parameters instead of relying on word splitting.
- The scanner image declares a non-root `USER`; Compose still overrides it with the invoking user's ids so reports in `lab/docker/out/` stay writable.
- The lab's nginx vhosts set `ssl_protocols` explicitly, so the transport is not part of what the lab varies.

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

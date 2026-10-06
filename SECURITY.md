# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x (`http-hardening-check.nse`, `hhc-report`) | Yes |
| 1.x (`http_hardening_check.nse`, untagged) | No |

## Reporting a vulnerability

Please report vulnerabilities in this project privately:

1. Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**.
2. If that option is not available, open an issue titled "Security contact request" **without any details**, and the maintainer will reply with a private channel.

Include the version or commit, what you ran, what happened and what you expected. You can expect an acknowledgement within 7 days. Please allow a reasonable time for a fix before disclosing publicly.

## In scope

- The NSE script sending requests it should not (state-changing methods, payloads, requests outside the documented budget, probes when exposure is off).
- Response content (for example a real `.env` file) leaking into console output or reports.
- Injection through scanned content into the reporter's HTML, Markdown, CSV or SARIF output.
- Unsafe XML or JSON handling in `hhc-report` (entity expansion, path traversal, overwriting files it should not).
- Input validation bypasses in the GitHub Action (`action.yml`, `action/guard.py`), such as running scans against public addresses without `allow-public-targets: true`, or shell injection through inputs.

## Out of scope

- Findings the tool reports about third-party sites. Report those to the site owner.
- The intentionally insecure lab targets in `lab/`. They are weak on purpose, bind to `127.0.0.1` (Python lab) or an internal Docker network with no published ports (Docker lab), and must never be exposed.
- False positives or negatives in a check. Please open a normal issue with the response headers involved.

## Safe use

This is a defensive auditing tool. Scan only systems you own or are explicitly authorized to test. It sends ordinary GET requests (plus one TRACE when exposure probing is on), and it does not exploit, brute force, authenticate, evade detection or modify anything. That does not make scanning someone else's systems acceptable.

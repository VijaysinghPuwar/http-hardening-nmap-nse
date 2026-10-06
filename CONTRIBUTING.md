# Contributing

## Setup

You need Nmap (7.94 or later), Python 3.10+, Lua 5.4 and, for the Docker lab, Docker with Compose v2.

```bash
make install        # .venv with hhc-report, pytest, ruff, mypy, jsonschema
brew install luacheck   # or: apt-get install lua-check
```

## Commands

| Command | What it runs |
|---|---|
| `make lint` | luacheck, ruff (lint and format check), mypy strict |
| `make unit` | Lua engine tests (`tests/unit`, no Nmap needed) |
| `make reporter-test` | `hhc-report` tests, including SARIF schema validation |
| `make integration` | Real Nmap against the Python lab and the Docker lab |
| `make stress` | Status codes, odd headers, argument edge cases, parser fuzzing |
| `make check` | All of the above |
| `make demo` | Docker lab, scan, reports into `lab/docker/out/` |

## Making a change

1. Branch from `main`; one topic per pull request.
2. A new check needs: an entry in `CHECKS` in the script, a lab target or unit test that triggers it, an exact-set assertion in the integration tests, a row in `docs/checks.md` (a unit test fails otherwise) and the ID in `policies/policy.schema.json`.
3. A bug fix needs a regression test that fails without the fix.
4. Run `make check` and `python3 scripts/check_text.py` before pushing. CI runs the same steps.

## Code expectations

- Keep `Engine` in the script pure (no network, no Nmap state) so it stays unit-testable.
- Severities must be defensible. Prefer under-reporting to a false positive, and explain the reasoning in `docs/checks.md`. Map to CWE, OWASP or ASVS only when the mapping is direct.
- No new runtime dependencies for the script or the reporter without a strong reason.
- Never copy response bodies into findings or reports.
- Match the existing style: short comments that explain why, not what.

## Security testing rules

- Test against `lab/` targets or systems you own. Never point tests, examples or CI at third-party hosts.
- New lab targets bind to `127.0.0.1` or the internal Docker network only, contain no real credentials, and are marked as intentionally insecure.
- No exploitation, brute forcing, authentication attempts, payloads or evasion features. Proposals for those will be declined.

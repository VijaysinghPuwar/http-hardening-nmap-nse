# Policies

A policy is a JSON file that sets thresholds, changes severities and turns checks on or off. Pass it with:

```bash
nmap -sV -p443 --script ./http-hardening-check.nse \
  --script-args 'http-hardening-check.policy=policies/strict.json' example.internal
```

Without a policy the script uses its built-in defaults, which are identical to `policies/baseline.json` (a unit test enforces this).

## Presets

| File | Use it for | Fails on |
|---|---|---|
| `baseline.json` | Any site. Reports what clearly matters; HSTS of 182.5 days is enough. | medium |
| `strict.json` | Sites that already pass baseline. One-year HSTS with includeSubDomains, stricter CSP, cookie and header rules, cross-origin isolation reported as INFO. | low |
| `owasp-asvs-l1.json` | Checking the externally testable HTTP header and cookie requirements of OWASP ASVS 4.0.3 Level 1 (V3.4, V14.3.3, V14.4, V14.5). Passing it does not make an application ASVS compliant. | low |

## Format

Every key is optional. `policies/policy.schema.json` is a JSON Schema for editors and CI.

```json
{
  "$schema": "./policy.schema.json",
  "name": "my-team",
  "description": "Internal services behind the corporate proxy.",
  "fail_on": "medium",
  "hsts": {
    "min_max_age": 31536000,
    "require_include_subdomains": true,
    "require_preload": false
  },
  "exposure": {
    "enabled": true,
    "trace": true,
    "paths": ["/internal/metrics", "/debug/vars"],
    "max_paths": 25
  },
  "skip": ["info-disclosure"],
  "checks": {
    "csp-unsafe-eval": {"severity": "medium"},
    "permissions-policy-missing": {"enabled": false},
    "cross-origin-isolation-missing": {"enabled": true, "severity": "low"}
  }
}
```

| Key | Meaning |
|---|---|
| `name` | Shown in results. Defaults to `custom` for a policy file without a name. |
| `fail_on` | Lowest severity that makes a target `FAIL`: `critical`, `high`, `medium`, `low` or `info`. |
| `hsts.min_max_age` | Seconds. A shorter max-age is `hsts-short-max-age`. |
| `hsts.require_include_subdomains` | Raises `hsts-no-subdomains` from INFO to at least LOW and stops HSTS counting as passed without it. |
| `hsts.require_preload` | Turns on `hsts-no-preload` at least at LOW. The directive is checked, not list enrollment. |
| `exposure.enabled` | Probe the built-in sensitive paths (see [checks](checks.md#exposure-opt-in)). |
| `exposure.trace` | With exposure enabled, send one `TRACE /`. |
| `exposure.paths` | Extra paths to probe, judged with soft-404 detection. Probed even when `enabled` is false. |
| `exposure.max_paths` | Upper bound on probed paths per port. |
| `skip` | Finding IDs to suppress, for accepted risks. Prefer this over editing severities, so the decision is visible. |
| `checks.<id>.severity` | Override the severity of one finding. |
| `checks.<id>.enabled` | Turn a finding off, or on if it is off by default. An explicit `false` wins over `require_*` settings. |

## Validation

A policy with an unknown key, an unknown finding ID, a wrong type or an invalid severity is rejected. The script then reports `result: ERROR` with `error: policy-error` for every port instead of scanning with a policy you did not intend. A typo such as `csp-mising` never silently disables a check.

## Precedence

Built-in defaults, then the policy file, then script arguments. `fail-on`, `hsts-min`, `skip`, `exposure` and `max-paths` given as script arguments override the file, which keeps one-off runs easy:

```bash
--script-args 'http-hardening-check.policy=policies/strict.json,http-hardening-check.fail-on=high'
```

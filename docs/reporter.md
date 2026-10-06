# hhc-report

`hhc-report` reads Nmap XML (`-oX`) produced with `http-hardening-check` and writes reports, then exits with a code a CI job can act on. Python 3.10+, standard library only.

```bash
pip install ./reporter            # or: make install (creates .venv)
hhc-report scan.xml                                   # table on stdout, policy gate
hhc-report scan.xml --format html --output report.html
hhc-report scan.xml -o report.sarif --sarif-artifact deploy/nginx.conf
hhc-report scan.xml --fail-on high
hhc-report scan.xml --baseline last-week.json --fail-on medium
```

The format is taken from `--format`, else from the `--output` extension (`.json`, `.csv`, `.md`, `.html`, `.sarif`), else `table`. Several XML files can be combined in one report.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Gate passed. |
| 1 | Gate failed: findings at or above `--fail-on`, or scan errors with `--fail-on-error`. |
| 2 | Usage or input error: missing or unreadable file, malformed or non-Nmap XML, corrupted baseline, no `http-hardening-check` results, or the output path is one of the inputs. |

`--fail-on` values:

| Value | Fails when |
|---|---|
| `policy` (default) | Any target's own result is `FAIL`, i.e. the policy used in the scan decides. |
| `critical`, `high`, `medium`, `low`, `info` | Any finding is at or above that severity. |
| `none` | Never on findings (still 2 on input errors). |

A target that could not be scanned (`result: ERROR`, for example a timeout or a policy error) does not fail the gate unless `--fail-on-error` is given, but it is always listed.

## Baseline (drift detection)

`--baseline PREVIOUS.json` takes an earlier `--format json` report. Each finding is marked `new` or `existing`, findings that disappeared are listed as `resolved`, and **only new findings can fail the gate**. That lets a team adopt the gate on an existing estate without fixing everything first.

Findings are matched by a fingerprint of the target origin (`scheme://host:port`), finding ID, path and detail with digits removed, so upgrading `nginx/1.24` to `nginx/1.25` does not count as a new finding.

## JSON

`--format json` is the stable machine format, described by [`report.schema.json`](../reporter/src/hhc_report/report.schema.json) (`schema_version` `1.0`; fields are only added in later 1.x versions). The output is deterministic: the same input gives byte-identical output, and no timestamp of the report run is added.

```json
{
  "schema_version": "1.0",
  "tool": {
    "name": "hhc-report",
    "version": "2.0.0",
    "script": "http-hardening-check"
  },
  "scan": {
    "files": [
      "scan.xml"
    ],
    "nmap_versions": [
      "7.95"
    ],
    "started": 1791250250
  },
  "summary": {
    "targets": 7,
    "passed": 2,
    "failed": 5,
    "errors": 0,
    "findings": {
      "critical": 0,
      "high": 6,
      "medium": 14,
      "low": 15,
      "info": 15
    },
    "lowest_score": 0,
    "worst_grade": "F"
  },
  "targets": [
    {
      "key": "https://weak.lab:443",
      "host": "172.21.0.3",
      "port": 443,
      "url": "https://weak.lab:443/",
      "status": 200,
      "result": "FAIL",
      "score": 0,
      "grade": "F",
      "policy": "baseline",
      "fail_on": "medium",
      "error": null,
      "error_detail": null,
      "note": null,
      "requests": 12,
      "counts": {
        "critical": 0,
        "high": 3,
        "medium": 5,
        "low": 6,
        "info": 6
      },
      "findings": [
        {
          "id": "cors-reflected-credentials",
          "severity": "high",
          "title": "CORS reflects arbitrary origins with credentials",
          "detail": "Origin reflected in Access-Control-Allow-Origin with credentials allowed",
          "evidence": "Access-Control-Allow-Origin: https://hardening-check.invalid; Access-Control-Allow-Credentials: true",
          "path": "/",
          "cwe": "CWE-942",
          "owasp": "A05:2021",
          "asvs": "14.5.3",
          "recommendation": "Match the Origin against an allowlist before echoing it; never reflect it with credentials.",
          "fingerprint": "9772ee5d8399475c",
          "baseline": null
        }
      ],
      "passed": [],
      "paths": [
        {
          "path": "/.git/HEAD",
          "status": 200,
          "verdict": "exposed"
        }
      ],
      "warnings": []
    }
  ],
  "baseline": null,
  "gate": {
    "fail_on": "high",
    "only_new": false,
    "fail_on_error": false,
    "failing_findings": 6,
    "failed": true,
    "reasons": [
      "6 finding(s) at high or above"
    ]
  }
}
```

(From the Docker demo lab, `--fail-on high`; abridged to one target, one finding and one probed path.)

## CSV

One row per finding; a target without findings, or one that errored, gets one row so every target appears. Columns:

`host, port, url, result, score, grade, policy, severity, id, title, detail, evidence, path, cwe, owasp, asvs, recommendation, baseline, fingerprint`

Cells that a spreadsheet would treat as a formula (starting with `=`, `+`, `-`, `@`, tab, CR, LF or `|`) are prefixed with `'`, and control characters are collapsed, so scanned header values cannot run formulas when the CSV is opened in Excel, LibreOffice or Google Sheets.

## Markdown and HTML

Markdown is meant for pull request comments and `$GITHUB_STEP_SUMMARY`. The HTML report is one self-contained file: no JavaScript, no external fonts or images, its own `Content-Security-Policy` (`default-src 'none'`), and light and dark themes from `prefers-color-scheme`. Every value from the scan is escaped in both formats.

## SARIF

`--format sarif` writes SARIF 2.1.0. The test suite validates the output against the official schema.

| Field | Content |
|---|---|
| `ruleId`, `rules[]` | Finding ID, title, recommendation, link to [checks.md](checks.md), CWE and OWASP tags |
| `level` | critical and high: `error`; medium: `warning`; low and info: `note` |
| `security-severity` | 9.5 / 8.0 / 5.5 / 3.0 / 0.0, the scale GitHub uses to label severity |
| `message` | Title, target URL and detail |
| `locations` | The file given by `--sarif-artifact` (default: the XML file name), plus the URL as a logical location |
| `partialFingerprints` | The finding fingerprint, so alerts track across runs |

Web findings have no source line. GitHub code scanning requires a file location, so point `--sarif-artifact` at the file that controls the headers, such as your nginx configuration. The SARIF output is schema-validated; uploading it to GitHub code scanning has not been exercised by this project's CI.

## What reports never contain

- The Nmap command line (it can contain local paths and arguments).
- Response bodies. Exposure findings describe the match (for example "body has KEY=value lines") instead of copying content.
- The time the report was generated (output stays reproducible).

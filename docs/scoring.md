# Scoring

Each scanned port gets a score from 0 to 100 and a letter grade. The score summarises posture; whether the port `PASS`es or `FAIL`s is decided separately by the policy's `fail_on` threshold.

## Algorithm

```
score = max(0, 100 - sum(weight[severity] for each finding))
```

| Severity | Weight | Reasoning |
|---:|---:|---|
| critical | 40 | One critical finding alone drops below the C band. |
| high | 25 | One high finding costs two and a half grades. |
| medium | 10 | One medium finding costs one grade. |
| low | 3 | About three lows equal one medium. |
| info | 0 | Informational findings never change the score. |

| Grade | Score |
|---|---|
| A | 90 to 100 |
| B | 80 to 89 |
| C | 70 to 79 |
| D | 60 to 69 |
| F | below 60 |

Two caps make sure the letter matches the worst finding:

- any critical finding: grade F, whatever the score;
- any high finding: grade at most C.

Severities are the effective ones after the policy is applied, so a policy that raises `csp-unsafe-eval` to medium also changes the score.

## Examples from the demo lab

These come from `make demo` against the Docker lab (baseline policy). They are lab results, not measurements of real sites.

| Target | Findings | Score | Grade |
|---|---|---:|---|
| `https://hardened.lab` | none | 100 | A |
| `https://spa.lab` | 1 medium, 1 info | 90 | A |
| `http://mixed.lab` (Apache) | 2 medium, 4 low, 1 info | 68 | D |
| `https://weak.lab` | 3 high, 5 medium, 6 low, 6 info | 0 | F |

## Why grade and result can disagree

`https://spa.lab` scores 90 (A) but its result is `FAIL`: the baseline policy fails on any medium finding, and a missing HSTS header is medium. The grade says the site is mostly well configured; the result says it does not meet the policy. CI gates use the result (or `hhc-report --fail-on`), never the grade.

## Limits of the score

The weights are a documented convention, not a risk model. They do not know which application handles sensitive data, and twenty low findings can outweigh one medium. Use the score to compare targets and track change over time; use findings and the policy to decide what to fix.

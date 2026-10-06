#!/usr/bin/env bash
# Runs the scan for action.yml. All inputs arrive as environment variables
# (never interpolated into the script) and are validated by guard.py first.
set -euo pipefail
set -f  # no glob expansion of targets

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
out="${HHC_OUTPUT_DIR:-hhc-report}"

targets=()
guarded="$(python3 "$here/guard.py")"
while IFS= read -r t; do targets+=("$t"); done <<< "$guarded"
mkdir -p "$out"

policy="${HHC_POLICY:-baseline}"
case "$policy" in
  baseline|strict|owasp-asvs-l1) policy="$root/policies/$policy.json" ;;
esac
[ -f "$policy" ] || { echo "::error::policy file not found: $policy" >&2; exit 2; }
case "$policy" in
  *\"*|*,*) echo "::error::policy path must not contain quotes or commas" >&2; exit 2 ;;
esac

args="http-hardening-check.policy=\"$policy\""
if [ "${HHC_EXPOSURE:-false}" = "true" ]; then
  args="$args,http-hardening-check.exposure=true"
fi

nmap -Pn -sT -sV -p "$HHC_PORTS" --script "$root/http-hardening-check.nse" \
  --script-args "$args" -oX "$out/scan.xml" -- "${targets[@]}"

extra=()
[ -n "${HHC_SARIF_ARTIFACT:-}" ] && extra=(--sarif-artifact "$HHC_SARIF_ARTIFACT")
for fmt in json html md sarif; do
  hhc-report "$out/scan.xml" --output "$out/report.$fmt" --fail-on none --quiet ${extra[@]+"${extra[@]}"}
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$out/report.md" >> "$GITHUB_STEP_SUMMARY"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "report-dir=$out"; echo "sarif-file=$out/report.sarif"; } >> "$GITHUB_OUTPUT"
fi

gate=(--fail-on "$HHC_FAIL_ON")
[ -n "${HHC_BASELINE:-}" ] && gate+=(--baseline "$HHC_BASELINE")
hhc-report "$out/scan.xml" "${gate[@]}"

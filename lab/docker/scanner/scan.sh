#!/bin/sh
# Scans the lab targets and renders every report format into /out.
#   scan.sh            scan + reports
#   scan.sh report     reports only, from an existing /out/scan.xml
set -eu

MODE="${1:-scan}"
POLICY="${HHC_POLICY:-/opt/hhc/policies/baseline.json}"

# The targets live in the positional parameters: POSIX sh has no arrays, and
# this passes each host to nmap as its own argument without relying on word
# splitting.
set -- hardened.lab weak.lab spa.lab mixed.lab

if [ "$MODE" != "report" ]; then
  nmap -Pn -sT -sV -p80,443 \
    --script /opt/hhc/http-hardening-check.nse \
    --script-args "http-hardening-check.policy=${POLICY},http-hardening-check.exposure=true,http-hardening-check.paths={/files/}" \
    -oX /out/scan.xml "$@"
fi

# Reports record the gate decision for --fail-on high; exit code 1 (gate
# failed) is expected for this lab, anything else is an error.
for fmt in json csv md html sarif; do
  hhc-report /out/scan.xml --output "/out/report.${fmt}" --fail-on high --quiet || [ $? -eq 1 ]
done
# The table and the gate decision go to the terminal.
hhc-report /out/scan.xml --fail-on high || echo "gate: findings at high or above (exit $?)"

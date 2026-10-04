#!/usr/bin/env python3
"""Turn http-hardening-check results in Nmap XML (-oX) into a table, CSV or JSON.

Exits 1 when any finding is at or above --fail-on, so a scan can gate a pipeline:

    nmap -sV -p443 --script ./http-hardening-check.nse -oX scan.xml example.com
    python3 tools/report.py scan.xml --fail-on high
"""
import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET

SCRIPT_ID = "http-hardening-check"
RANK = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
FIELDS = ["host", "port", "url", "severity", "id", "detail"]


def elem(table, key):
    node = table.find(f"elem[@key='{key}']")
    return node.text if node is not None else None


def parse(path):
    """Yield one dict per finding. A port with no findings yields one row with severity PASS."""
    for host in ET.parse(path).getroot().iter("host"):
        addr = host.find("address").get("addr")
        for port in host.iter("port"):
            script = port.find(f"script[@id='{SCRIPT_ID}']")
            if script is None:
                continue
            base = {"host": addr, "port": int(port.get("portid")), "url": elem(script, "url")}
            findings = script.findall("table[@key='findings']/table")
            if not findings:
                yield {**base, "severity": "PASS", "id": "", "detail": ""}
            for f in findings:
                yield {**base, **{k: elem(f, k) for k in ("severity", "id", "detail")}}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("xml", nargs="+", help="Nmap XML output files")
    ap.add_argument("-f", "--format", choices=["table", "csv", "json"], default="table")
    ap.add_argument("--fail-on", choices=[s.lower() for s in RANK], default="medium",
                    help="lowest severity that causes exit code 1 (default: medium)")
    args = ap.parse_args()

    try:
        rows = [r for path in args.xml for r in parse(path)]
    except (OSError, ET.ParseError) as e:
        print(f"cannot read Nmap XML: {e}", file=sys.stderr)
        return 2
    rows.sort(key=lambda r: (r["host"], r["port"], RANK.get(r["severity"], 0), r["id"]))

    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2)
        print()
    elif args.format == "csv":
        w = csv.DictWriter(sys.stdout, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    else:
        for r in rows:
            print(f"{r['host']}:{r['port']:<6} {r['severity']:<7} {r['id']:<30} {r['detail']}".rstrip())

    threshold = RANK[args.fail_on.upper()]
    failing = [r for r in rows if RANK.get(r["severity"], 99) <= threshold]
    if not rows:
        print("no http-hardening-check results found", file=sys.stderr)
        return 2
    print(f"{len(failing)} finding(s) at {args.fail_on} or above", file=sys.stderr)
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())

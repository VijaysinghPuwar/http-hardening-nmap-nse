"""Read http-hardening-check results from Nmap XML into plain data.

The result is a dict that is also the JSON output format (see
report.schema.json), so every renderer works from the same structure.
"""

from __future__ import annotations

import hashlib
import os
import re
import xml.etree.ElementTree as ET
from typing import Any

from hhc_report import SCRIPT_ID, __version__

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
GRADES = ["A", "B", "C", "D", "F"]
SCHEMA_VERSION = "1.0"

# Nmap XML for a large scan can be big, but not this big.
MAX_XML_BYTES = 256 * 1024 * 1024

FINDING_FIELDS = [
    "id",
    "severity",
    "title",
    "detail",
    "evidence",
    "path",
    "cwe",
    "owasp",
    "asvs",
    "recommendation",
]

Report = dict[str, Any]
Target = dict[str, Any]
Finding = dict[str, Any]


class InputError(Exception):
    """The input file is missing, unreadable, unsafe or not Nmap XML."""


def read_xml(path: str) -> ET.Element:
    """Parses Nmap XML, refusing entity declarations (Nmap never writes them),
    so entity expansion attacks are not possible regardless of the parser."""
    try:
        size = os.path.getsize(path)
        if size > MAX_XML_BYTES:
            raise InputError(f"{path}: file is larger than {MAX_XML_BYTES // (1024 * 1024)} MB")
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise InputError(f"{path}: {e.strerror or e}") from e
    if not data.strip():
        raise InputError(f"{path}: file is empty")
    if re.search(rb"<!ENTITY", data, re.IGNORECASE):
        raise InputError(f"{path}: XML entity declarations are not allowed")
    try:
        root = ET.fromstring(data)  # noqa: S314 - entities rejected above
    except ET.ParseError as e:
        raise InputError(f"{path}: not well-formed XML ({e})") from e
    if root.tag != "nmaprun":
        raise InputError(f"{path}: not Nmap XML output (root element is <{root.tag}>)")
    return root


def _convert(node: ET.Element) -> Any:
    """Converts an NSE <table> into a dict (keyed children) or a list."""
    children = list(node)
    if any(c.get("key") is not None for c in children):
        out: dict[str, Any] = {}
        for c in children:
            key = c.get("key")
            if key is not None:
                out[key] = (c.text or "") if c.tag == "elem" else _convert(c)
        return out
    return [(c.text or "") if c.tag == "elem" else _convert(c) for c in children]


def _int(v: Any) -> int | None:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s if s != "" else None


def fingerprint(target_key: str, finding: Finding) -> str:
    """Stable identity of a finding across scans. Digits in the detail are
    ignored so a version bump (nginx/1.24 -> 1.25) is not a 'new' finding."""
    detail = re.sub(r"\d+", "#", finding.get("detail") or "")
    raw = "\x1f".join([target_key, finding["id"], finding.get("path") or "/", detail])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def target_key(url: str | None, host: str, port: int) -> str:
    m = re.match(r"^(https?://[^/]+)", url or "")
    return m.group(1) if m else f"{host}:{port}"


def _target(host: str, port: int, script: ET.Element) -> Target:
    raw = {k: v for k, v in (_convert(script) or {}).items()} if list(script) else {}
    if not isinstance(raw, dict):
        raw = {}
    url = _str(raw.get("url"))
    key = target_key(url, host, port)
    findings: list[Finding] = []
    for f in raw.get("findings") or []:
        if not isinstance(f, dict) or not f.get("id"):
            continue
        sev = str(f.get("severity") or "info").lower()
        item: Finding = {k: _str(f.get(k)) for k in FINDING_FIELDS}
        item["severity"] = sev if sev in RANK else "info"
        item["fingerprint"] = fingerprint(key, item)
        item["baseline"] = None
        findings.append(item)
    findings.sort(key=lambda f: (RANK[f["severity"]], f["id"], f.get("detail") or ""))

    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1

    paths = []
    for p in raw.get("paths") or []:
        if isinstance(p, dict):
            paths.append(
                {
                    "path": _str(p.get("path")),
                    "status": _int(p.get("status")),
                    "verdict": _str(p.get("verdict")),
                }
            )

    def str_list(v: Any) -> list[str]:
        return [str(x) for x in v] if isinstance(v, list) else []

    result = str(raw.get("result") or ("ERROR" if not raw else "PASS")).upper()
    if result not in ("PASS", "FAIL", "ERROR"):
        result = "ERROR"
    grade = _str(raw.get("grade"))
    return {
        "key": key,
        "host": host,
        "port": port,
        "url": url,
        "status": _int(raw.get("status")),
        "result": result,
        "score": _int(raw.get("score")),
        "grade": grade if grade in GRADES else None,
        "policy": _str(raw.get("policy")),
        "fail_on": _str(raw.get("fail_on")),
        "error": _str(raw.get("error")) if result == "ERROR" else None,
        "error_detail": _str(raw.get("error_detail")),
        "note": _str(raw.get("note")),
        "requests": _int(raw.get("requests")),
        "counts": counts,
        "findings": findings,
        "passed": str_list(raw.get("passed")),
        "paths": paths,
        "warnings": str_list(raw.get("warnings")),
    }


def load(paths: list[str]) -> Report:
    """Builds the report from one or more Nmap XML files."""
    targets: list[Target] = []
    nmap_versions: set[str] = set()
    started: list[int] = []
    for path in paths:
        root = read_xml(path)
        if root.get("version"):
            nmap_versions.add(str(root.get("version")))
        if _int(root.get("start")) is not None:
            started.append(int(str(root.get("start"))))
        for host in root.iter("host"):
            addr_node = host.find("address")
            addr = addr_node.get("addr", "unknown") if addr_node is not None else "unknown"
            for port in host.iter("port"):
                script = port.find(f"script[@id='{SCRIPT_ID}']")
                if script is None:
                    continue
                portid = _int(port.get("portid")) or 0
                targets.append(_target(addr, portid, script))
    targets.sort(key=lambda t: (t["host"], t["port"], t["url"] or ""))
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "hhc-report", "version": __version__, "script": SCRIPT_ID},
        "scan": {
            "files": [os.path.basename(p) for p in paths],
            "nmap_versions": sorted(nmap_versions),
            "started": min(started) if started else None,
        },
        "summary": summarise(targets),
        "targets": targets,
        "baseline": None,
        "gate": None,
    }


def summarise(targets: list[Target]) -> dict[str, Any]:
    counts = {s: 0 for s in SEVERITIES}
    scores = [t["score"] for t in targets if t["score"] is not None]
    grades = [t["grade"] for t in targets if t["grade"]]
    for t in targets:
        for f in t["findings"]:
            counts[f["severity"]] += 1
    return {
        "targets": len(targets),
        "passed": sum(1 for t in targets if t["result"] == "PASS"),
        "failed": sum(1 for t in targets if t["result"] == "FAIL"),
        "errors": sum(1 for t in targets if t["result"] == "ERROR"),
        "findings": counts,
        "lowest_score": min(scores) if scores else None,
        "worst_grade": max(grades, key=GRADES.index) if grades else None,
    }


def all_findings(report: Report) -> list[tuple[Target, Finding]]:
    return [(t, f) for t in report["targets"] for f in t["findings"]]

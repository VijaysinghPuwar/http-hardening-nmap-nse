"""Shared fixtures. XML builders produce Nmap-shaped output so edge cases do
not need a live scan; fixtures/lab-scan.xml is a real scan of lab/server.py."""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.sax.saxutils import quoteattr

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _elem(key: str | None, value: Any) -> str:
    k = f" key={quoteattr(key)}" if key is not None else ""
    if isinstance(value, dict):
        return f"<table{k}>" + "".join(_elem(kk, vv) for kk, vv in value.items()) + "</table>"
    if isinstance(value, list):
        return f"<table{k}>" + "".join(_elem(None, v) for v in value) + "</table>"
    return f"<elem{k}>{_esc(str(value))}</elem>"


def finding(fid: str = "csp-missing", severity: str = "MEDIUM", **extra: Any) -> dict[str, Any]:
    f = {
        "id": fid,
        "severity": severity,
        "title": f"title of {fid}",
        "detail": f"detail of {fid}",
        "recommendation": f"fix {fid}",
    }
    f.update(extra)
    return f


def target(
    port: int = 443, host: str = "192.0.2.10", findings: list[dict[str, Any]] | None = None, **fields: Any
) -> dict[str, Any]:
    findings = findings or []
    out: dict[str, Any] = {
        "url": f"https://lab.test:{port}/",
        "status": 200,
        "result": "FAIL" if findings else "PASS",
        "score": 100,
        "grade": "A",
        "policy": "baseline",
        "fail_on": "medium",
        "findings": findings,
        "passed": ["hsts"],
        "requests": 1,
    }
    out.update(fields)
    out["_host"], out["_port"] = host, port
    return out


def nmap_xml(targets: list[dict[str, Any]], start: int = 1767225600) -> str:
    hosts: dict[str, list[str]] = {}
    for t in targets:
        t = dict(t)
        host, port = t.pop("_host"), t.pop("_port")
        body = "".join(_elem(k, v) for k, v in t.items() if v is not None)
        hosts.setdefault(host, []).append(
            f'<port protocol="tcp" portid="{port}"><state state="open"/>'
            f'<script id="http-hardening-check" output="...">{body}</script></port>'
        )
    parts = [
        f'<host><address addr="{h}" addrtype="ipv4"/><ports>{"".join(p)}</ports></host>'
        for h, p in hosts.items()
    ]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        f'<nmaprun scanner="nmap" args="nmap" start="{start}" version="7.99">{"".join(parts)}</nmaprun>\n'
    )


@pytest.fixture
def write_xml(tmp_path: Path) -> Callable[..., str]:
    def _write(targets: list[dict[str, Any]], name: str = "scan.xml") -> str:
        p = tmp_path / name
        p.write_text(nmap_xml(targets), encoding="utf-8")
        return str(p)

    return _write


@pytest.fixture
def lab_xml() -> str:
    return str(FIXTURES / "lab-scan.xml")


@pytest.fixture
def hardened_xml() -> str:
    return str(FIXTURES / "hardened.xml")


@pytest.fixture(scope="session")
def report_schema() -> dict[str, Any]:
    from importlib.resources import files

    return json.loads((files("hhc_report") / "report.schema.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def sarif_schema(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The official SARIF 2.1.0 schema. Set HHC_SARIF_SCHEMA to a local copy
    to run offline; set HHC_ALLOW_OFFLINE=1 to skip instead of failing."""
    local = os.environ.get("HHC_SARIF_SCHEMA")
    if local:
        return json.loads(Path(local).read_text(encoding="utf-8"))
    dest = tmp_path_factory.mktemp("schema") / "sarif-2.1.0.json"
    try:
        with urllib.request.urlopen(SARIF_SCHEMA_URL, timeout=20) as r:
            dest.write_bytes(r.read())
    except OSError as e:
        if os.environ.get("HHC_ALLOW_OFFLINE") == "1":
            pytest.skip(f"SARIF schema unavailable offline: {e}")
        raise
    return json.loads(dest.read_text(encoding="utf-8"))

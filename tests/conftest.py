"""Fixtures for the integration and stress tests: real Nmap, real script,
targets from lab/server.py on 127.0.0.1.

Set NMAP to use another binary, e.g. NMAP="/opt/nmap/bin/nmap --datadir /opt/nmap/share/nmap".
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "http-hardening-check.nse")
sys.path.insert(0, str(ROOT / "lab"))

import server
from hhc_report.model import load

NMAP = shlex.split(os.environ.get("NMAP", "nmap"))


def nmap_available() -> bool:
    return shutil.which(NMAP[0]) is not None


@pytest.fixture(scope="session")
def lab() -> Iterator[Any]:
    if not nmap_available():
        pytest.fail(f"nmap not found ({NMAP[0]}); install Nmap to run the integration tests")
    servers = server.start()
    yield server
    for s in servers:
        s.shutdown()
        s.server_close()


ScanFn = Callable[..., dict[str, Any]]


@pytest.fixture(scope="session")
def scan(lab: Any, tmp_path_factory: pytest.TempPathFactory) -> ScanFn:
    """Runs Nmap with the script and returns the hhc-report model. service=True
    adds -sV (needed for HTTP on ports Nmap does not associate with HTTP);
    service=False forces the script with '+' and skips service detection."""
    counter = iter(range(10_000))

    def _scan(
        ports: str, script_args: str = "", service: bool = True, flags: tuple[str, ...] = ()
    ) -> dict[str, Any]:
        out = tmp_path_factory.mktemp("scan") / f"scan-{next(counter)}.xml"
        script = SCRIPT if service else "+" + SCRIPT
        cmd = [*NMAP, "-Pn", "-sT", "-p", ports, "--script", script, "-oX", str(out), *flags]
        if service:
            cmd += ["-sV", "--version-light"]
        if script_args:
            cmd += ["--script-args", script_args]
        cmd.append("127.0.0.1")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        assert proc.returncode == 0, proc.stderr
        report = load([str(out)])
        report["_xml"] = str(out)
        report["_stdout"] = proc.stdout
        return report

    return _scan


def by_port(report: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {t["port"]: t for t in report["targets"]}


def ids(target: dict[str, Any]) -> set[str]:
    return {f["id"] for f in target["findings"]}

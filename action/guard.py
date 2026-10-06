#!/usr/bin/env python3
"""Validates GitHub Action inputs before anything is scanned.

Targets must be host names or IP addresses (no URLs, options or shell
characters). Unless allow-public-targets is "true", every target must resolve
only to loopback, private (RFC 1918 / ULA) or link-local addresses, so the
action cannot be pointed at the internet by accident.

Prints the validated targets, one per line, for run.sh.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys

HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
PORTS = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$")
SEVERITY = {"critical", "high", "medium", "low", "info", "policy", "none"}


def fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(2)


def is_internal(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return ip.is_loopback or ip.is_private or ip.is_link_local


def resolve(target: str) -> list[str]:
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror as e:
        fail(f"cannot resolve target {target!r}: {e}")
    return sorted({str(info[4][0]).split("%")[0] for info in infos})


def main() -> None:
    raw = os.environ.get("HHC_TARGETS", "").split()
    ports = os.environ.get("HHC_PORTS", "")
    fail_on = os.environ.get("HHC_FAIL_ON", "")
    allow_public = os.environ.get("HHC_ALLOW_PUBLIC", "false").strip().lower() == "true"
    if not raw:
        fail("input 'targets' is empty")
    if len(raw) > 256:
        fail("more than 256 targets; split the scan")
    if not PORTS.match(ports):
        fail(f"input 'ports' must look like 80,443 or 8000-8100 (got {ports!r})")
    if fail_on not in SEVERITY:
        fail(f"input 'fail-on' must be one of {sorted(SEVERITY)} (got {fail_on!r})")
    for t in raw:
        if not HOST.match(t) and not _is_ip(t):
            fail(f"target {t!r} is not a host name or IP address (no URLs, ports or options)")
        public = [a for a in resolve(t) if not is_internal(a)]
        if public and not allow_public:
            fail(
                f"target {t!r} resolves to public address(es) {', '.join(public)}. Scan only systems you are "
                "authorized to test; set allow-public-targets: true to confirm."
            )
    print("\n".join(raw))


def _is_ip(t: str) -> bool:
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main()

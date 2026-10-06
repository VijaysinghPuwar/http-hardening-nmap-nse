"""Tests that need neither Nmap nor the lab: the GitHub Action input guard
and the shipped policy files against their JSON Schema."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import jsonschema
import pytest
from conftest import ROOT

GUARD = ROOT / "action" / "guard.py"


def guard(targets: str, ports: str = "80,443", fail_on: str = "policy", allow: str = "false"):
    env = {
        **os.environ,
        "HHC_TARGETS": targets,
        "HHC_PORTS": ports,
        "HHC_FAIL_ON": fail_on,
        "HHC_ALLOW_PUBLIC": allow,
    }
    return subprocess.run([sys.executable, str(GUARD)], capture_output=True, text=True, env=env, check=False)


@pytest.mark.parametrize(
    "targets", ["127.0.0.1", "10.0.0.5 192.168.1.10", "172.16.0.1", "::1", "fd00::1", "localhost"]
)
def test_internal_targets_are_accepted(targets):
    r = guard(targets)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == targets.split()


@pytest.mark.parametrize("targets", ["8.8.8.8", "127.0.0.1 1.1.1.1", "2001:4860:4860::8888"])
def test_public_targets_need_explicit_permission(targets):
    r = guard(targets)
    assert r.returncode == 2 and "authorized" in r.stderr
    assert guard(targets, allow="true").returncode == 0


@pytest.mark.parametrize(
    "targets",
    [
        "127.0.0.1;id",
        "$(id)",
        "`id`",
        "-oN/tmp/x",
        "--script=evil",
        "http://127.0.0.1/",
        "127.0.0.1:8080",
        "a b|c",
        "host/24",
        "",
    ],
)
def test_malicious_or_malformed_targets(targets):
    r = guard(targets)
    assert r.returncode == 2


@pytest.mark.parametrize("ports", ["443;id", "80 443", "-p-", "1,2,", "abc", "$(id)"])
def test_bad_ports(ports):
    assert guard("127.0.0.1", ports=ports).returncode == 2


def test_ports_ranges_ok():
    assert guard("127.0.0.1", ports="80,443,8000-8100").returncode == 0


def test_bad_fail_on():
    assert guard("127.0.0.1", fail_on="urgent").returncode == 2


def test_action_never_interpolates_inputs_into_scripts():
    # Every ${{ inputs.* }} must appear only as an env value, never in run:.
    text = (ROOT / "action.yml").read_text()
    for line in text.splitlines():
        if "${{ inputs." in line:
            assert line.strip().startswith("HHC_") and ": ${{ inputs." in line, line


@pytest.mark.parametrize("name", ["baseline", "strict", "owasp-asvs-l1"])
def test_policies_match_schema(name):
    schema = json.loads((ROOT / "policies" / "policy.schema.json").read_text())
    doc = json.loads((ROOT / "policies" / f"{name}.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["name"] == name


@pytest.mark.parametrize(
    "bad",
    [
        {"fail_on": "urgent"},
        {"checks": {"nope": {}}},
        {"hsts": {"min_max_age": -1}},
        {"extra": 1},
        {"checks": {"csp-missing": {"severity": "HIGH"}}},
    ],
)
def test_schema_rejects_bad_policies(bad):
    schema = json.loads((ROOT / "policies" / "policy.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(bad)

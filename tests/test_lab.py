"""End-to-end tests: real Nmap, real script, against the servers in lab/server.py.

    python3 -m unittest -v tests/test_lab.py

Set NMAP to use a different binary, e.g. NMAP="/opt/nmap/bin/nmap --datadir /opt/nmap/share/nmap".
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))
sys.path.insert(0, str(ROOT / "tools"))

import report  # noqa: E402
import server  # noqa: E402

SCRIPT = str(ROOT / "http-hardening-check.nse")
NMAP = shlex.split(os.environ.get("NMAP", "nmap"))
PORTS = "8080,8081,8082,8443,8444,8445"


def scan(ports, script_args, out):
    cmd = NMAP + ["-Pn", "-sT", "-sV", "-p", ports, "--script", SCRIPT,
                  "--script-args", script_args, "-oX", out, "127.0.0.1"]
    subprocess.run(cmd, check=True, capture_output=True, timeout=300)
    return out


def ids_by_port(xml):
    found = {}
    for row in report.parse(xml):
        found.setdefault(row["port"], set())
        if row["id"]:
            found[row["port"]].add(row["id"])
    return found


class LabScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = server.start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.default_xml = scan(PORTS, "http-hardening-check.paths={/admin,/.git/HEAD}",
                               os.path.join(cls.tmp.name, "default.xml"))
        # Quoted-string list form, SNI, suppression and threshold in one run.
        cls.vhost_xml = scan("8443,8444", 'http-hardening-check.vhost=app.lab.test,'
                             'http-hardening-check.paths="/admin,/.git/HEAD",'
                             'http-hardening-check.skip={info-disclosure},'
                             'http-hardening-check.fail-on=high',
                             os.path.join(cls.tmp.name, "vhost.xml"))
        cls.redirect_xml = scan("8081", "http-hardening-check.path=/old/page",
                                os.path.join(cls.tmp.name, "redirect.xml"))
        cls.found = ids_by_port(cls.default_xml)
        cls.found_vhost = ids_by_port(cls.vhost_xml)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()
        cls.tmp.cleanup()

    def test_redirect_to_https_passes(self):
        self.assertEqual(self.found[8080], set())

    def test_bare_http(self):
        self.assertEqual(self.found[8081], {
            "no-https-redirect", "csp-missing", "framing-missing", "xcto-missing",
            "referrer-policy-missing", "info-disclosure", "path-exposed",
        })

    def test_legacy_http(self):
        self.assertEqual(self.found[8082], {
            "no-https-redirect", "hsts-over-http", "csp-report-only", "info-disclosure",
        })

    def test_weak_https_values_are_judged(self):
        self.assertEqual(self.found[8443], {
            "hsts-disabled", "csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-source",
            "framing-allowed", "xcto-missing", "referrer-policy-leaky", "xxp-enabled",
            "info-disclosure", "cookie-no-secure", "cookie-no-httponly",
            "cookie-samesite-none-insecure", "cors-reflected-credentials",
        })

    def test_soft_404_is_not_reported_as_exposed(self):
        # The weak server returns 200 for every path; /.git/HEAD must not count.
        self.assertNotIn("path-exposed", self.found[8443])

    def test_without_sni_the_default_vhost_is_judged(self):
        self.assertIn("hsts-missing", self.found[8444])
        self.assertIn("csp-missing", self.found[8444])

    def test_partial_edge_cases(self):
        self.assertEqual(self.found[8445], {
            "hsts-short-max-age", "hsts-no-subdomains", "csp-no-script-restriction",
            "framing-allowed", "referrer-policy-leaky", "cors-reflected-origin",
        })

    def test_vhost_sets_sni_and_host(self):
        # Hardened profile is only served when SNI is app.lab.test; HEAD returns 405 there.
        self.assertEqual(self.found_vhost[8444], set())
        rows = [r for r in report.parse(self.vhost_xml) if r["port"] == 8444]
        self.assertEqual(rows[0]["url"], "https://app.lab.test:8444/")

    def test_relative_redirect_is_followed(self):
        rows = list(report.parse(self.redirect_xml))
        self.assertTrue(rows[0]["url"].endswith(":8081/index.html"), rows[0]["url"])

    def test_quoted_list_and_skip(self):
        self.assertNotIn("info-disclosure", self.found_vhost[8443])
        self.assertIn("cors-reflected-credentials", self.found_vhost[8443])

    def test_report_exit_codes(self):
        cmd = [sys.executable, str(ROOT / "tools" / "report.py")]
        fail = subprocess.run(cmd + [self.default_xml, "-f", "csv"], capture_output=True, text=True)
        self.assertEqual(fail.returncode, 1)
        self.assertTrue(fail.stdout.startswith("host,port,url,severity,id,detail"))
        high = subprocess.run(cmd + [self.vhost_xml, "--fail-on", "high", "-f", "json"],
                              capture_output=True, text=True)
        self.assertEqual(high.returncode, 1)  # 8443 still has a HIGH (CORS)
        rows = json.loads(high.stdout)
        self.assertIn({"port": 8444, "severity": "PASS"},
                      [{"port": r["port"], "severity": r["severity"]} for r in rows])


if __name__ == "__main__":
    unittest.main()

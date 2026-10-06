#!/usr/bin/env python3
"""Local test targets for http-hardening-check.nse. Python stdlib + openssl CLI.

Ports (all on 127.0.0.1):
  8080  redirect   plain HTTP, 301 to https://localhost:8444/
  8081  bare       plain HTTP, no security headers, /admin open
  8082  legacy     plain HTTP, HSTS sent over HTTP (ignored), CSP in Report-Only mode
  8443  weak       HTTPS, every header present but misconfigured, soft-404
  8444  hardened   HTTPS, correct headers, but only when SNI is app.lab.test; "bare" otherwise
  8445  partial    HTTPS, the edge cases: short HSTS, CSP without script rules, CORS without credentials
  8180  exposed    plain HTTP, real /.git/HEAD and /.env, a directory listing, TRACE enabled
  8000  garbage    answers every request with bytes that are not HTTP
  8088  silent     accepts connections and never answers (timeout)

Extra routes on every HTTP profile: /status/<code> answers with that code,
/loop/a and /loop/b redirect to each other. On 8445: /dup-csp (two CSP
headers), /big-header (8 KB header), /cookies (30 Set-Cookie headers).

These are intentionally insecure test targets. They bind to 127.0.0.1 only.
"""

import argparse
import collections
import contextlib
import http.server
import socketserver
import ssl
import subprocess
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
CERT, KEY = HERE / "cert.pem", HERE / "key.pem"
VHOST = "app.lab.test"
PROBE_ORIGIN = "https://hardening-check.invalid"

# Requests carrying the script's probe Origin, per port. The tests use it to
# check the request budget (Nmap's own -sV and soft-404 probes do not send it).
SCRIPT_REQUESTS = collections.Counter()

PROFILES = {
    "bare": {},
    "exposed": {"X-Content-Type-Options": "nosniff"},
    "weak": {
        "Strict-Transport-Security": "max-age=0",
        "Content-Security-Policy": "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:",
        "X-Frame-Options": "ALLOW-FROM https://partner.example",
        "X-Content-Type-Options": "sniff",
        "Referrer-Policy": "unsafe-url",
        "X-XSS-Protection": "1; mode=block",
        "X-Powered-By": "PHP/8.1.2",
        "Set-Cookie": ["session=abc123; Path=/", "tracker=1; SameSite=None"],
    },
    "legacy": {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy-Report-Only": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    },
    "partial": {
        "Strict-Transport-Security": "max-age=86400",
        "Content-Security-Policy": "object-src 'none'; frame-ancestors *",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer, no-referrer-when-downgrade",
    },
    "hardened": {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        # frame-ancestors with no X-Frame-Options: must pass, not be flagged.
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Set-Cookie": ["session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"],
    },
}


# Routes on the partial profile used by the stress tests.
EXTRA_ROUTES = {
    # Two enforced policies: the second one closes the first one's gaps.
    "/dup-csp": (
        200,
        {
            "Content-Security-Policy": [
                "script-src *",
                "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ],
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        },
        b"dup",
    ),
    "/big-header": (200, {"X-Padding": "a" * 8192}, b"big"),
    "/cookies": (
        200,
        {
            "Set-Cookie": [f"c{i}=v; Path=/; Secure; HttpOnly; SameSite=Lax" for i in range(29)]
            + ["sessionid=x; Path=/"]
        },
        b"cookies",
    ),
}


def make_handler(profile_for, server_header, soft404=False, cors_reflect=False, head_405=False):
    """cors_reflect echoes Origin; credentials are allowed only for the weak profile."""

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self):
            return server_header

        def log_message(self, *args):
            pass

        def do_HEAD(self):
            if head_405:
                self._send(405, {}, b"")
            else:
                self.do_GET()

        def do_TRACE(self):
            if profile_for(self) == "exposed":
                echo = f"TRACE {self.path} HTTP/1.1\r\n{self.headers}".encode()
                self._send(200, {"Content-Type": "message/http"}, echo)
            else:
                self._send(405, {}, b"")

        def do_GET(self):
            if self.headers.get("Origin") == PROBE_ORIGIN:
                SCRIPT_REQUESTS[self.server.server_address[1]] += 1
            profile = profile_for(self)
            path = self.path.split("?")[0]
            if path.startswith("/status/") and path[8:].isdigit():
                code = int(path[8:])
                self._send(code, dict(PROFILES.get(profile, {})), b"" if code in (204, 304) else b"status")
                return
            if path in ("/loop/a", "/loop/b"):
                self._send(302, {"Location": "/loop/b" if path == "/loop/a" else "/loop/a"}, b"")
                return
            if profile == "redirect":
                self._send(301, {"Location": "https://localhost:8444/"}, b"")
                return
            headers = dict(PROFILES[profile])
            if cors_reflect and "Origin" in self.headers:
                headers["Access-Control-Allow-Origin"] = self.headers["Origin"]
                if profile == "weak":
                    headers["Access-Control-Allow-Credentials"] = "true"

            if profile == "exposed":
                self._exposed(path, headers)
                return
            if profile == "partial" and path in EXTRA_ROUTES:
                code, extra, body = EXTRA_ROUTES[path]
                self._send(code, {**headers, **extra}, body)
                return
            if path in ("/", "/index.html"):
                self._send(200, headers, f"<h1>{profile}</h1>".encode())
            elif path == "/old/page":
                self._send(302, {"Location": "../index.html"}, b"")  # relative, no leading slash
            elif path == "/admin" and profile == "bare":
                self._send(200, headers, b"<h1>admin console</h1>")
            elif path == "/admin":
                self._send(403, headers, b"forbidden")
            elif soft404:
                self._send(200, headers, b"<h1>Page not found</h1>")
            else:
                self._send(404, headers, b"not found")

        def _exposed(self, path, headers):
            files = {
                "/.git/HEAD": b"ref: refs/heads/main\n",
                "/.env": b"APP_ENV=lab\nDB_PASSWORD=not-a-real-secret\n",
                "/files/": (
                    b"<html><head><title>Index of /files/</title></head>"
                    b"<body><h1>Index of /files/</h1><a href='a.txt'>a.txt</a></body></html>"
                ),
            }
            if path == "/":
                self._send(200, headers, b"<h1>exposed</h1>")
            elif path in files:
                self._send(200, headers, files[path])
            else:
                self._send(404, headers, b"not found")

        def _send(self, code, headers, body):
            self.send_response(code)
            for name, value in headers.items():
                for v in value if isinstance(value, list) else [value]:
                    self.send_header(name, v)
            if "Content-Type" not in headers:
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    return Handler


def ensure_cert():
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(KEY),
            "-out",
            str(CERT),
        ],
        check=True,
        capture_output=True,
    )


def tls_context(on_sni=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    if on_sni:
        ctx.sni_callback = on_sni
    return ctx


class LabServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # scanners drop connections mid-request; that is expected


class TLSServer(LabServer):
    """Wraps each accepted socket in TLS."""

    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(10)
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def finish_request(self, request, client_address):
        # Runs in the worker thread, so a slow handshake does not block accept().
        request.do_handshake()
        super().finish_request(request, client_address)

    def shutdown_request(self, request):
        # Send close_notify. Without it OpenSSL 3 clients (Nmap, ncat) report
        # "unexpected eof" and drop the response.
        try:
            request.settimeout(1)
            request.unwrap()
        except (OSError, ValueError):
            pass
        request.close()


class RawHandler(socketserver.BaseRequestHandler):
    """Speaks something that is not HTTP (garbage) or nothing at all (silent)."""

    mode = "garbage"

    def handle(self):
        try:
            self.request.settimeout(5)
            self.request.recv(4096)
            if self.mode == "garbage":
                self.request.sendall(b"\x00\x01 this is not HTTP\r\n\r\n")
            else:
                self.request.recv(4096)  # wait until the client gives up
        except OSError:
            pass


class RawServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


def serve_raw(port, mode):
    handler = type(f"{mode}Handler", (RawHandler,), {"mode": mode})
    srv = RawServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def serve(port, handler, ctx=None):
    addr = ("127.0.0.1", port)
    srv = TLSServer(addr, handler, ctx) if ctx else LabServer(addr, handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start():
    ensure_cert()

    def record_sni(sslsock, name, _ctx):
        sslsock.sni = name

    def hardened_or_default(handler):
        return "hardened" if getattr(handler.connection, "sni", None) == VHOST else "bare"

    servers = [
        serve(8080, make_handler(lambda h: "redirect", "nginx")),
        serve(8081, make_handler(lambda h: "bare", "Apache/2.4.41 (Ubuntu)")),
        serve(8082, make_handler(lambda h: "legacy", "Microsoft-IIS/10.0")),
        serve(
            8443,
            make_handler(lambda h: "weak", "nginx/1.18.0", soft404=True, cors_reflect=True),
            tls_context(),
        ),
        serve(8444, make_handler(hardened_or_default, "nginx", head_405=True), tls_context(record_sni)),
        serve(8445, make_handler(lambda h: "partial", "nginx", cors_reflect=True), tls_context()),
        serve(8180, make_handler(lambda h: "exposed", "Apache/2.4.58 (Unix)")),
        serve_raw(8000, "garbage"),
        serve_raw(8088, "silent"),
    ]
    return servers


if __name__ == "__main__":
    argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    ).parse_args()
    start()
    print(
        "lab up on 127.0.0.1: 8080 redirect, 8081 bare, 8082 legacy, 8443 weak, "
        "8444 hardened (SNI app.lab.test), 8445 partial, 8180 exposed, 8000 garbage, 8088 silent"
    )
    with contextlib.suppress(KeyboardInterrupt):
        threading.Event().wait()

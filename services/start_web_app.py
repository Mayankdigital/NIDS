#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
start_web_app.py
A deliberately vulnerable-looking local web application for WEB_ATTACK data collection.
This is intentionally simplistic and local — it is the TARGET, not a real site.
Listens on 127.0.0.1:8082

Vulnerability surface (intentionally minimal, local-only):
  - /search?q=... (echoes parameter — SQLi/XSS simulation target)
  - /admin (restricted area)
  - /files/../../etc/passwd style paths (path traversal target)
  - /api/exec (command injection target surface)

NOTE: This does NOT actually execute any injected code.
It only responds to HTTP requests so NFStream can observe the FLOW.
Payload content is NOT visible to NFStream — only flow statistics are.

Usage:
    python3 services/start_web_app.py
"""
import argparse
import logging
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WEB-APP] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("web_app")


class WebAppHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def send_html(self, code: int, body: str):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        log.info("GET %s  qs=%s  from=%s", path, qs, self.client_address[0])

        if path == "/":
            self.send_html(200, "<h1>Local Test Web App</h1><a href='/search?q=test'>Search</a>")
        elif path == "/search":
            q = qs.get("q", [""])[0]
            # Note: we are NOT executing q — this is a flow-level target
            self.send_html(200, f"<h1>Search Results</h1><p>Query: {len(q)} chars</p>")
        elif path == "/admin":
            self.send_html(403, "<h1>403 Forbidden</h1>")
        elif path.startswith("/files/"):
            # Detect path traversal attempts (log only, do not serve real files)
            raw = unquote(path)
            if ".." in raw or "%2e" in raw.lower():
                log.warning("PATH TRAVERSAL ATTEMPT: %s", raw)
                self.send_html(403, "<h1>403 Forbidden</h1>")
            else:
                self.send_html(404, "<h1>404 Not Found</h1>")
        elif path == "/api/exec":
            self.send_html(403, "<h1>Forbidden</h1>")
        elif path == "/health":
            self.send_html(200, "{\"status\": \"ok\"}")
        else:
            self.send_html(404, "<h1>404</h1>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        log.info("POST %s  body_len=%d", self.path, length)
        self.send_html(200, "{\"result\": \"ok\"}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()
    server = HTTPServer((args.host, args.port), WebAppHandler)
    log.info("Web app target on %s:%d  (interface: lo)", args.host, args.port)
    log.info("This is the WEB_ATTACK target — local only, no real vulnerabilities executed")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()

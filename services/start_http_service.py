#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
start_http_service.py
A minimal HTTP server that acts as the BENIGN / target service.
Listens on 127.0.0.1:8080 by default.
All traffic goes through the loopback interface (lo).

Usage:
    python3 services/start_http_service.py [--host 127.0.0.1] [--port 8080]
"""
import argparse
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HTTP-SERVICE] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("http_service")


class BenignHandler(BaseHTTPRequestHandler):
    """Handles GET/POST requests for the dummy target service."""

    PAGES = {
        "/": b"<html><body><h1>Test Service</h1><p>OK</p></body></html>",
        "/health": b"{\"status\": \"ok\"}",
        "/api/data": b"{\"data\": [1,2,3,4,5]}",
        "/api/users": b"{\"users\": [{\"id\":1,\"name\":\"alice\"},{\"id\":2,\"name\":\"bob\"}]}",
        "/files/report.txt": b"This is a sample report file.\nLine 2.\nLine 3.",
        "/login": b"<html><body><form method='POST'><input name='user'><input name='pass' type='password'><button>Login</button></form></body></html>",
    }

    def log_message(self, fmt, *args):  # redirect to our logger
        log.info("%s %s", self.address_string(), fmt % args)

    def send_page(self, code: int, body: bytes, content_type: str = "text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        body = self.PAGES.get(path, b"<html><body><h1>404 Not Found</h1></body></html>")
        code = 200 if path in self.PAGES else 404
        ct = "application/json" if path.startswith("/api") else "text/html"
        self.send_page(code, body, ct)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body_data = self.rfile.read(length)
        log.info("POST %s  body_len=%d", self.path, length)
        response = b"{\"result\": \"received\"}"
        self.send_page(200, response, "application/json")


def main():
    parser = argparse.ArgumentParser(description="Dummy HTTP target service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), BenignHandler)
    log.info("Starting on %s:%d  (interface: lo)", args.host, args.port)
    log.info("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()

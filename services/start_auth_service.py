#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
start_auth_service.py
A deliberately simple local authentication service for BRUTE_FORCE data collection.
Exposes a login endpoint that accepts POST with username/password.
Returns 200 on correct credentials, 401 on wrong credentials.
Never exposes real credentials — uses a fixed test secret.

Listens on 127.0.0.1:8081

Usage:
    python3 services/start_auth_service.py
"""
import argparse
import hashlib
import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AUTH-SERVICE] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("auth_service")

# Correct credential for testing (not a real credential)
CORRECT_USER = "admin"
CORRECT_PASS_HASH = hashlib.sha256(b"correct_test_password_xyz").hexdigest()

ATTEMPT_COUNTER = {"total": 0, "success": 0, "fail": 0}


class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def send_json(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ok", "attempts": ATTEMPT_COUNTER})
        elif self.path == "/login":
            body = b"<html><body><form method='POST' action='/login'>"\
                   b"<input name='username'><input name='password' type='password'>"\
                   b"<button>Login</button></form></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        ATTEMPT_COUNTER["total"] += 1

        try:
            if self.headers.get("Content-Type", "").startswith("application/json"):
                data = json.loads(raw)
                username = data.get("username", "")
                password = data.get("password", "")
            else:
                params = parse_qs(raw)
                username = params.get("username", [""])[0]
                password = params.get("password", [""])[0]
        except Exception:
            username, password = "", ""

        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == CORRECT_USER and pw_hash == CORRECT_PASS_HASH:
            ATTEMPT_COUNTER["success"] += 1
            log.info("AUTH SUCCESS  user=%s", username)
            self.send_json(200, {"token": "test_token_abc123", "status": "ok"})
        else:
            ATTEMPT_COUNTER["fail"] += 1
            log.info("AUTH FAIL     user=%s  (total_fail=%d)", username, ATTEMPT_COUNTER["fail"])
            self.send_json(401, {"error": "invalid credentials"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    server = HTTPServer((args.host, args.port), AuthHandler)
    log.info("Auth service on %s:%d", args.host, args.port)
    log.info("Target user: '%s'  (password is a local test secret)", CORRECT_USER)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopped. Stats: %s", ATTEMPT_COUNTER)
        sys.exit(0)


if __name__ == "__main__":
    main()

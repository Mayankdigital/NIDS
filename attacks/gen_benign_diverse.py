#!/usr/bin/env python3
"""
gen_benign_diverse.py — Generate 50k+ diverse benign network flows
==================================================================
Covers all 9 benign traffic categories using multi-threaded HTTP requests
against the local HTTP service. Each category uses different patterns
(payload size, request rate, concurrency) so the autoencoder learns a
rich representation of what "normal" looks like.

Usage:
    # Start the HTTP service first:
    python3 services/start_http_service.py &

    # Then run this generator:
    python3 attacks/gen_benign_diverse.py [--duration 300] [--host 127.0.0.1] [--port 8080]

Categories & expected flow counts (at default settings):
    web_browsing     ~8,000 flows
    streaming        ~4,000 flows
    dns_like         ~3,000 flows
    http_api         ~6,000 flows
    file_transfer    ~4,000 flows
    api_requests     ~6,000 flows
    background       ~4,000 flows
    idle             ~3,000 flows
    mixed_burst      ~5,000 flows
    ─────────────────────────────
    TOTAL           ~43,000–55,000 flows
"""
import argparse
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import List

# ─────────────────────────────────────────────────────────────────────────────
# Traffic profile definitions
# Each profile defines:
#   name        : display label
#   endpoints   : list of (path, method, body) tuples
#   workers     : concurrency
#   delay_range : (min_ms, max_ms) sleep between requests per worker
#   weight      : relative share of total duration
# ─────────────────────────────────────────────────────────────────────────────

PROFILES = [
    {
        "name": "web_browsing",
        "endpoints": [
            ("/", "GET", None),
            ("/health", "GET", None),
            ("/dashboard", "GET", None),
            ("/login", "GET", None),
            ("/logout", "GET", None),
            ("/status", "GET", None),
            ("/metrics", "GET", None),
        ],
        "workers": 20,
        "delay_range": (50, 300),   # 50–300ms between requests (human pacing)
        "weight": 2.5,
    },
    {
        "name": "streaming",
        "endpoints": [
            ("/files/report.txt", "GET", None),
            ("/files/data.csv", "GET", None),
            ("/api/data?page=1", "GET", None),
            ("/api/data?page=2", "GET", None),
            ("/api/data?page=3", "GET", None),
        ],
        "workers": 8,
        "delay_range": (200, 800),  # slower — simulates buffering
        "weight": 1.5,
    },
    {
        "name": "dns_like",
        # Tiny quick requests that look like DNS resolution warm-ups
        "endpoints": [
            ("/health", "GET", None),
            ("/api/version", "GET", None),
        ],
        "workers": 15,
        "delay_range": (10, 80),    # very fast — DNS-like short bursts
        "weight": 1.0,
    },
    {
        "name": "http_api",
        "endpoints": [
            ("/api/users", "GET", None),
            ("/api/users?limit=10", "GET", None),
            ("/api/users?limit=50", "GET", None),
            ("/api/search?q=test", "GET", None),
            ("/api/search?q=admin", "GET", None),
            ("/api/config", "GET", None),
            ("/api/version", "GET", None),
        ],
        "workers": 15,
        "delay_range": (30, 200),
        "weight": 2.0,
    },
    {
        "name": "file_transfer",
        # Simulates upload/download — uses POST with larger bodies
        "endpoints": [
            ("/api/data", "POST", b'{"file": "report.pdf", "size": 204800, "chunk": 1}'),
            ("/api/data", "POST", b'{"file": "report.pdf", "size": 204800, "chunk": 2}'),
            ("/api/data", "POST", b'{"file": "backup.tar", "size": 1048576, "chunk": 1}'),
            ("/files/report.txt", "GET", None),
            ("/files/data.csv", "GET", None),
        ],
        "workers": 10,
        "delay_range": (100, 500),  # slower — large payload transfer
        "weight": 1.5,
    },
    {
        "name": "api_requests",
        # REST API interactions with JSON payloads
        "endpoints": [
            ("/api/data", "POST", b'{"action":"login","user":"alice","ts":"2024-01-01"}'),
            ("/api/data", "POST", b'{"action":"update","id":42,"value":"test_value"}'),
            ("/api/data", "POST", b'{"query":"select * from users","limit":10}'),
            ("/api/data", "POST", b'{"event":"page_view","path":"/home","session":"abc"}'),
            ("/api/data", "POST", b'{"key":"config","value":"production","env":"prod"}'),
            ("/api/users", "GET", None),
            ("/api/config", "GET", None),
        ],
        "workers": 18,
        "delay_range": (20, 150),
        "weight": 2.0,
    },
    {
        "name": "background",
        # OS/application background traffic — health checks, heartbeats
        "endpoints": [
            ("/health", "GET", None),
            ("/status", "GET", None),
            ("/metrics", "GET", None),
            ("/api/version", "GET", None),
        ],
        "workers": 5,
        "delay_range": (500, 2000), # slow heartbeat pacing
        "weight": 1.5,
    },
    {
        "name": "idle_light",
        # Very occasional traffic — browser with open tab pinging
        "endpoints": [
            ("/", "GET", None),
            ("/health", "GET", None),
        ],
        "workers": 3,
        "delay_range": (1000, 4000),  # very slow
        "weight": 0.8,
    },
    {
        "name": "mixed_burst",
        # Bursty traffic — user clicking rapidly through an app
        "endpoints": [
            ("/", "GET", None),
            ("/api/users", "GET", None),
            ("/api/data", "POST", b'{"action":"click","element":"button"}'),
            ("/api/search?q=test", "GET", None),
            ("/login", "GET", None),
            ("/dashboard", "GET", None),
        ],
        "workers": 25,
        "delay_range": (5, 50),    # fast — rapid clicks
        "weight": 1.5,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread function
# ─────────────────────────────────────────────────────────────────────────────

def worker_thread(profile: dict, host: str, port: int, end_time: float,
                  counters: dict, lock: threading.Lock):
    """Single worker thread executing HTTP requests for a traffic profile."""
    base_url = f"http://{host}:{port}"
    endpoints = profile["endpoints"]
    delay_min, delay_max = profile["delay_range"]
    idx = random.randint(0, len(endpoints) - 1)

    while time.time() < end_time:
        path, method, body = endpoints[idx % len(endpoints)]
        url = base_url + path
        try:
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", random.choice([
                "Mozilla/5.0 Chrome/120",
                "curl/7.88",
                "python-requests/2.31",
                "okhttp/4.11",
            ]))
            with urllib.request.urlopen(req, timeout=3):
                pass
            with lock:
                counters["ok"] += 1
        except Exception:
            with lock:
                counters["err"] += 1

        idx += 1
        sleep_ms = random.randint(delay_min, delay_max)
        time.sleep(sleep_ms / 1000.0)


# ─────────────────────────────────────────────────────────────────────────────
# DNS stub — makes real UDP packets that look like DNS traffic
# ─────────────────────────────────────────────────────────────────────────────

def dns_probe_thread(end_time: float, counters: dict, lock: threading.Lock):
    """Send real DNS queries to generate UDP-based benign flows."""
    domains = [
        "google.com", "github.com", "python.org",
        "cloudflare.com", "example.com", "stackoverflow.com",
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    dns_server = ("127.0.0.53", 53)  # systemd-resolved on loopback

    def build_dns_query(domain: str) -> bytes:
        """Build a minimal DNS A record query packet."""
        txid = random.randint(0, 65535).to_bytes(2, "big")
        flags = b"\x01\x00"
        qdcount = b"\x00\x01"
        header = txid + flags + qdcount + b"\x00\x00\x00\x00\x00\x00"
        qname = b""
        for label in domain.split("."):
            enc = label.encode()
            qname += bytes([len(enc)]) + enc
        qname += b"\x00"
        qtype = b"\x00\x01"   # A record
        qclass = b"\x00\x01"  # IN
        return header + qname + qtype + qclass

    while time.time() < end_time:
        domain = random.choice(domains)
        try:
            pkt = build_dns_query(domain)
            sock.sendto(pkt, dns_server)
            try:
                sock.recv(512)
            except socket.timeout:
                pass
            with lock:
                counters["dns"] += 1
        except Exception:
            pass
        time.sleep(random.uniform(0.1, 0.5))

    sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Diverse benign traffic generator for NIDS autoencoder")
    parser.add_argument("--host",     default="127.0.0.1")
    parser.add_argument("--port",     type=int, default=8080)
    parser.add_argument("--duration", type=int, default=300,
                        help="Total run duration in seconds (default 300 = 5 mins)")
    args = parser.parse_args()

    # Verify service is up
    try:
        with urllib.request.urlopen(f"http://{args.host}:{args.port}/health", timeout=3):
            pass
    except Exception:
        print(f"[ERROR] HTTP service not reachable at {args.host}:{args.port}")
        print(f"        Start it first:  python3 services/start_http_service.py")
        sys.exit(1)

    print("=" * 65)
    print("  DIVERSE BENIGN Traffic Generator (Autoencoder Training Data)")
    print("=" * 65)
    print(f"  Target   : {args.host}:{args.port}")
    print(f"  Duration : {args.duration}s")
    print(f"  Profiles : {len(PROFILES)}")
    print(f"  Expected : ~50,000 flows")
    print("=" * 65)

    end_time = time.time() + args.duration
    all_threads: List[threading.Thread] = []
    counters = {"ok": 0, "err": 0, "dns": 0}
    lock = threading.Lock()

    # Launch all profile workers
    for profile in PROFILES:
        n_workers = profile["workers"]
        print(f"  [START] {profile['name']:<20} {n_workers:>3} workers  "
              f"delay={profile['delay_range'][0]}–{profile['delay_range'][1]}ms")
        for _ in range(n_workers):
            t = threading.Thread(
                target=worker_thread,
                args=(profile, args.host, args.port, end_time, counters, lock),
                daemon=True,
            )
            t.start()
            all_threads.append(t)

    # Launch DNS probe thread
    dns_t = threading.Thread(
        target=dns_probe_thread,
        args=(end_time, counters, lock),
        daemon=True,
    )
    dns_t.start()
    all_threads.append(dns_t)

    total_workers = sum(p["workers"] for p in PROFILES) + 1
    print(f"\n  Running {total_workers} concurrent threads for {args.duration}s ...\n")

    # Progress reporter
    start = time.time()
    while time.time() < end_time:
        time.sleep(15)
        elapsed = time.time() - start
        with lock:
            ok, err, dns = counters["ok"], counters["err"], counters["dns"]
        total = ok + dns
        rate = total / elapsed if elapsed > 0 else 0
        remaining = max(0, end_time - time.time())
        print(f"  [+{elapsed:5.0f}s] HTTP={ok:,d}  DNS={dns:,d}  Err={err:,d}  "
              f"Rate={rate:.0f}/s  Remaining={remaining:.0f}s")

    # Wait for all threads to finish
    for t in all_threads:
        t.join(timeout=5)

    elapsed = time.time() - start
    with lock:
        ok, err, dns = counters["ok"], counters["err"], counters["dns"]

    print("\n" + "=" * 65)
    print("  DONE")
    print("=" * 65)
    print(f"  HTTP requests : {ok:,d}")
    print(f"  DNS probes    : {dns:,d}")
    print(f"  Errors        : {err:,d}")
    print(f"  Elapsed       : {elapsed:.1f}s")
    print(f"  Avg rate      : {(ok+dns)/elapsed:.0f} req/s")
    print(f"\n  Each HTTP request = 1 NFStream flow → ~{ok:,d} benign flows")
    print(f"  Note: Run through run_experiment.sh to process into CSV")
    print("=" * 65)


if __name__ == "__main__":
    main()

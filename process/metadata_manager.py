#!/home/mayank/Desktop/DATACOLLECTION/venv/bin/python
"""
metadata_manager.py — Record and query experiment metadata
===========================================================
Usage:
    # Record a new experiment
    python3 process/metadata_manager.py record \\
        --experiment-id DOS_001 \\
        --class-id 2 \\
        --class-name dos \\
        --interface lo \\
        --src-ip 127.0.0.1 \\
        --dst-ip 127.0.0.1 \\
        --dst-port 8080 \\
        --protocol TCP \\
        --notes "hping3 + ab, 120s duration"

    # List all experiments
    python3 process/metadata_manager.py list

    # Show summary
    python3 process/metadata_manager.py summary

    # Mark experiment start/end times
    python3 process/metadata_manager.py start --experiment-id DOS_001
    python3 process/metadata_manager.py stop  --experiment-id DOS_001
"""
import argparse
import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent / "nids_dataset"
META_FILE = BASE_DIR / "metadata" / "experiments.csv"

FIELDNAMES = [
    "experiment_id", "class_id", "class_name", "label",
    "start_time", "end_time", "duration_s",
    "interface", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol",
    "pcap_file", "simulated_ddos", "notes",
]

LABEL_MAP = {
    "benign": 0, "port_scan": 1, "dos": 2, "ddos": 3,
    "brute_force": 4, "network_recon": 5,
    "udp_flood": 6, "icmp_flood": 7, "web_attack": 8,
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_experiments() -> list:
    if not META_FILE.exists():
        return []
    with open(META_FILE, newline="") as f:
        return list(csv.DictReader(f))


def _save_experiments(rows: list):
    META_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(META_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def cmd_record(args):
    rows = _load_experiments()

    # Check for duplicate
    existing_ids = {r["experiment_id"] for r in rows}
    if args.experiment_id in existing_ids:
        print(f"[META] WARNING: experiment_id '{args.experiment_id}' already exists.")
        if not args.force:
            print("[META] Use --force to overwrite. Exiting.")
            sys.exit(1)
        rows = [r for r in rows if r["experiment_id"] != args.experiment_id]

    class_name = args.class_name
    label = LABEL_MAP.get(class_name, args.class_id)

    is_ddos_sim = "true" if class_name == "ddos" else "false"

    pcap_dir = BASE_DIR / "captures" / class_name
    pcap_file = str(pcap_dir / f"{args.experiment_id}.pcap")

    row = {
        "experiment_id":    args.experiment_id,
        "class_id":         args.class_id,
        "class_name":       class_name,
        "label":            label,
        "start_time":       args.start_time or "",
        "end_time":         "",
        "duration_s":       "",
        "interface":        args.interface,
        "source_ip":        args.src_ip,
        "destination_ip":   args.dst_ip,
        "source_port":      args.src_port or "-",
        "destination_port": args.dst_port or "-",
        "protocol":         args.protocol,
        "pcap_file":        pcap_file,
        "simulated_ddos":   is_ddos_sim,
        "notes":            args.notes or "",
    }
    rows.append(row)
    _save_experiments(rows)
    print(f"[META] Recorded: {args.experiment_id}  class={class_name}({label})")
    print(f"[META] PCAP expected: {pcap_file}")


def cmd_start(args):
    rows = _load_experiments()
    found = False
    for row in rows:
        if row["experiment_id"] == args.experiment_id:
            row["start_time"] = _now_utc()
            found = True
            print(f"[META] start_time={row['start_time']}  for {args.experiment_id}")
    if not found:
        print(f"[META] ERROR: experiment_id '{args.experiment_id}' not found.")
        sys.exit(1)
    _save_experiments(rows)


def cmd_stop(args):
    rows = _load_experiments()
    found = False
    for row in rows:
        if row["experiment_id"] == args.experiment_id:
            end = _now_utc()
            row["end_time"] = end
            if row.get("start_time"):
                try:
                    t0 = datetime.fromisoformat(row["start_time"].replace("Z", "+00:00"))
                    t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    row["duration_s"] = str(int((t1 - t0).total_seconds()))
                except Exception:
                    row["duration_s"] = ""
            found = True
            print(f"[META] end_time={end}  duration={row['duration_s']}s  for {args.experiment_id}")
    if not found:
        print(f"[META] ERROR: experiment_id '{args.experiment_id}' not found.")
        sys.exit(1)
    _save_experiments(rows)


def cmd_list(args):
    rows = _load_experiments()
    if not rows:
        print("[META] No experiments recorded yet.")
        return
    print(f"{'ID':<20} {'CLASS':<15} {'LABEL':<6} {'INTERFACE':<10} {'START':<22} {'NOTES'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['experiment_id']:<20} {r['class_name']:<15} "
              f"{r['label']:<6} {r['interface']:<10} "
              f"{r.get('start_time',''):<22} {r.get('notes','')}")


def cmd_summary(args):
    rows = _load_experiments()
    if not rows:
        print("[META] No experiments recorded yet.")
        return

    from collections import Counter
    class_counts = Counter(r["class_name"] for r in rows)
    print("\n=== Experiment Summary ===")
    print(f"Total experiments: {len(rows)}")
    print()
    print(f"{'CLASS':<16} {'LABEL':<6} {'COUNT':<8} {'RECOMMENDED'}")
    print("-" * 50)
    label_map_r = {v: k for k, v in LABEL_MAP.items()}
    for cls, cnt in sorted(class_counts.items()):
        lbl = LABEL_MAP.get(cls, "?")
        rec = "✓ enough" if cnt >= 4 else f"need {4-cnt} more"
        print(f"{cls:<16} {lbl:<6} {cnt:<8} {rec}")

    interfaces = Counter(r["interface"] for r in rows)
    print()
    print(f"Interfaces used: {dict(interfaces)}")


def main():
    parser = argparse.ArgumentParser(description="NIDS Experiment Metadata Manager")
    sub = parser.add_subparsers(dest="command")

    # record
    p_rec = sub.add_parser("record", help="Record a new experiment entry")
    p_rec.add_argument("--experiment-id", required=True)
    p_rec.add_argument("--class-id", type=int, required=True)
    p_rec.add_argument("--class-name", required=True, choices=list(LABEL_MAP.keys()))
    p_rec.add_argument("--interface", default="lo")
    p_rec.add_argument("--src-ip", default="127.0.0.1")
    p_rec.add_argument("--dst-ip", default="127.0.0.1")
    p_rec.add_argument("--src-port", default="-")
    p_rec.add_argument("--dst-port", default="-")
    p_rec.add_argument("--protocol", default="TCP")
    p_rec.add_argument("--start-time", default=None)
    p_rec.add_argument("--notes", default="")
    p_rec.add_argument("--force", action="store_true")

    # start / stop
    p_start = sub.add_parser("start", help="Mark start_time for an experiment")
    p_start.add_argument("--experiment-id", required=True)

    p_stop = sub.add_parser("stop", help="Mark end_time for an experiment")
    p_stop.add_argument("--experiment-id", required=True)

    # list / summary
    sub.add_parser("list",    help="List all experiments")
    sub.add_parser("summary", help="Show per-class experiment counts")

    args = parser.parse_args()
    if args.command == "record":   cmd_record(args)
    elif args.command == "start":  cmd_start(args)
    elif args.command == "stop":   cmd_stop(args)
    elif args.command == "list":   cmd_list(args)
    elif args.command == "summary": cmd_summary(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

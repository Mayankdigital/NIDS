# NIDS Dataset Generation — Single Laptop Setup

> **Complete pipeline** for generating a labeled network flow dataset for ML-based  
> Network Intrusion Detection, using **one Linux laptop**, **no VM**, **no second device**.

---

## 📐 lo vs wlo1: The Critical Interface Question

### When traffic uses `lo` (loopback)

```
Condition: destination IP is 127.0.0.1 or ::1 or "localhost"
Result: ALL traffic goes through lo, NEVER touches wlo1
```

| Experiment | Target IP | Interface | Reason |
|-----------|-----------|-----------|--------|
| BENIGN    | 127.0.0.1 | **lo**    | curl → localhost |
| PORT_SCAN | 127.0.0.1 | **lo**    | nmap → localhost |
| DOS       | 127.0.0.1 | **lo**    | hping3/ab → localhost |
| BRUTE_FORCE | 127.0.0.1 | **lo** | HTTP POST → localhost |
| NETWORK_RECON | 127.0.0.1 | **lo** | nmap probes → localhost |
| UDP_FLOOD | 127.0.0.1 | **lo**    | UDP datagrams → localhost |
| ICMP_FLOOD | 127.0.0.1 | **lo**   | ICMP echo → localhost |
| WEB_ATTACK | 127.0.0.1 | **lo**   | HTTP → localhost |

### When traffic uses `wlo1` (Wi-Fi)

```
Condition: destination IP is the laptop's LAN IP (e.g., 192.168.x.x)
Even if sender is on same machine, routing goes through wlo1
```

### DDOS (simulated via namespaces)

```
Namespaces create veth_h0, veth_h1, ... interfaces
Traffic travels on veth_h* interfaces, NOT lo or wlo1
Capture with: sudo tcpdump -i any
```

### Verify which interface to capture on

```bash
# Check your LAN IP
ip addr show wlo1

# Check what's listening
ss -tuln

# Test: does traffic go through lo?
sudo tcpdump -i lo -n -c 5 &
curl http://127.0.0.1:8080/
# If you see packets → it's using lo ✓

# Test: does traffic go through wlo1?
sudo tcpdump -i wlo1 -n -c 5 &
curl http://127.0.0.1:8080/
# Unlikely to see packets → confirms lo is correct

# Verify route
ip route get 127.0.0.1
# Should show: local 127.0.0.1 dev lo
```

---

## 🏗️ Directory Structure

```
nids_dataset/
├── captures/           # Raw PCAPs from tcpdump
│   ├── benign/         # BENIGN_001.pcap, BENIGN_002.pcap, ...
│   ├── port_scan/
│   ├── dos/
│   ├── ddos/
│   ├── brute_force/
│   ├── network_recon/
│   ├── udp_flood/
│   ├── icmp_flood/
│   └── web_attack/
├── processed/          # Per-class labeled CSVs from NFStream
│   ├── benign.csv
│   ├── port_scan.csv
│   └── ...
├── metadata/
│   └── experiments.csv # Experiment registry
└── final/
    ├── nids_dataset.csv          # Merged, all classes
    ├── nids_dataset_splits.csv   # With train/val/test column
    └── ml_results/               # Confusion matrices, plots
```

---

## 🏷️ Label Mapping

| ID | Class | Tool | Interface | Flow Separability |
|----|-------|------|-----------|-------------------|
| 0 | BENIGN | curl + HTTP | lo | Baseline |
| 1 | PORT_SCAN | nmap (SYN/connect) | lo | **High** — tiny flows, many ports |
| 2 | DOS | hping3 + ab | lo | **High** — extreme packet rate |
| 3 | DDOS | Namespaces | veth_h* | **Moderate** — multiple src IPs |
| 4 | BRUTE_FORCE | Python HTTP POST | lo | **Low-Moderate** — overlaps benign |
| 5 | NETWORK_RECON | nmap -sV -O | lo | **Moderate** — overlaps port_scan |
| 6 | UDP_FLOOD | hping3 UDP | lo | **High** — protocol + rate |
| 7 | ICMP_FLOOD | hping3 ICMP | lo | **High** — ICMP protocol field |
| 8 | WEB_ATTACK | Python HTTP GET/POST | lo | **Low** — same as benign HTTP |

---

## ⚡ Quick Start

### Step 0: Install dependencies

```bash
bash setup/check_deps.sh
```

Common installs:
```bash
sudo apt update && sudo apt install -y nmap hping3 tcpdump apache2-utils ncat
pip3 install nfstream pandas numpy scikit-learn xgboost matplotlib seaborn imbalanced-learn
```

### Step 1: Create directories

```bash
bash setup/create_dirs.sh
```

### Step 2: Start target services (3 terminals)

```bash
# Terminal 1: HTTP service (for BENIGN, PORT_SCAN, DOS, DDOS, NETWORK_RECON)
python3 services/start_http_service.py

# Terminal 2: Auth service (for BRUTE_FORCE)
python3 services/start_auth_service.py

# Terminal 3: Web app (for WEB_ATTACK)
python3 services/start_web_app.py
```

### Step 3: Run experiments

The master script handles everything automatically:

```bash
# Format: ./run_experiment.sh <class> <experiment_number> [duration_seconds]

./run_experiment.sh benign       1 300
./run_experiment.sh benign       2 300
./run_experiment.sh benign       3 300
./run_experiment.sh benign       4 300    # ← need ≥4 for train/val/test split

./run_experiment.sh port_scan    1
./run_experiment.sh port_scan    2
./run_experiment.sh port_scan    3
./run_experiment.sh port_scan    4

./run_experiment.sh dos          1 120
./run_experiment.sh dos          2 120
./run_experiment.sh dos          3 120
./run_experiment.sh dos          4 120

./run_experiment.sh ddos         1 120   # uses network namespaces
./run_experiment.sh ddos         2 120
./run_experiment.sh ddos         3 120
./run_experiment.sh ddos         4 120

./run_experiment.sh brute_force  1
./run_experiment.sh brute_force  2
./run_experiment.sh brute_force  3
./run_experiment.sh brute_force  4

./run_experiment.sh network_recon 1
./run_experiment.sh network_recon 2
./run_experiment.sh network_recon 3
./run_experiment.sh network_recon 4

./run_experiment.sh udp_flood    1 120
./run_experiment.sh udp_flood    2 120
./run_experiment.sh udp_flood    3 120
./run_experiment.sh udp_flood    4 120

./run_experiment.sh icmp_flood   1 120
./run_experiment.sh icmp_flood   2 120
./run_experiment.sh icmp_flood   3 120
./run_experiment.sh icmp_flood   4 120

./run_experiment.sh web_attack   1
./run_experiment.sh web_attack   2
./run_experiment.sh web_attack   3
./run_experiment.sh web_attack   4
```

### Step 4: Merge and split

```bash
python3 process/merge_dataset.py
```

This creates:
- `nids_dataset/final/nids_dataset.csv`
- `nids_dataset/final/nids_dataset_splits.csv` (with `split` column: train/val/test)

### Step 5: Validate

```bash
python3 validate/dataset_validator.py
```

### Step 6: Train ML model

```bash
python3 ml/train_eval.py
```

---

## 🔬 Background Traffic Isolation

Because you're on a live laptop, background processes may contaminate your captures.

### Before each experiment, silence background traffic:

```bash
# Stop NetworkManager auto-updates
sudo systemctl stop NetworkManager

# Disable browser (close it manually)

# Stop Docker if running
sudo systemctl stop docker

# Disable apt background updates
sudo systemctl stop unattended-upgrades

# Flush DNS to reduce background DNS traffic
sudo systemd-resolve --flush-caches

# Check what else is generating traffic
sudo nethogs lo        # per-process on lo
sudo nethogs wlo1      # per-process on wlo1
```

### After experiments, restore:

```bash
sudo systemctl start NetworkManager
```

### Identifying background flows in your dataset:

The NFStream processor captures EVERYTHING on the interface. After processing:

```python
import pandas as pd
df = pd.read_csv("nids_dataset/processed/benign.csv")

# Flows NOT going to your test services
background = df[~df["dst_port"].isin([8080, 8081, 8082, 9999, 53, 80, 443])]
print(f"Potential background flows: {len(background)}")
print(background[["src_ip","dst_ip","src_port","dst_port","protocol"]].head(20))
```

**Do NOT silently delete these.** Tag them in the metadata and document what you decide:
- If they're DNS queries (port 53): expected on loopback from systemd-resolved
- If they're unknown TCP connections: document and consider filtering

---

## 📊 Data Leakage Prevention

### What to NEVER do:
```python
# ❌ WRONG — splits correlated flows from same experiment
from sklearn.model_selection import train_test_split
X_train, X_test = train_test_split(df[df.label==2], test_size=0.2)
```

### What to ALWAYS do:
```python
# ✓ CORRECT — experiment-level splitting (done automatically by merge_dataset.py)
# DOS_001 → train
# DOS_002 → train
# DOS_003 → val
# DOS_004 → test
train = df[df["split"] == "train"]
val   = df[df["split"] == "val"]
test  = df[df["split"] == "test"]
```

### Columns to drop before ML training:

```python
DROP = [
    "src_ip", "dst_ip",        # environment-specific
    "src_mac", "dst_mac",      # environment-specific
    "src_port", "dst_port",    # may encode class (e.g., dst_port=8081 ≡ BRUTE_FORCE)
    "experiment_id",           # label leakage
    "class_name",              # direct label
    "label",                   # target variable
    "split",                   # split assignment
    "first_seen", "last_seen", # timestamp leakage
    "processed_at",
    "pcap_file",
]
```

---

## 🧠 NFStream Limitations (Honest Assessment)

### What NFStream captures:
- Bidirectional packet counts and byte counts
- Flow duration (ms)
- Inter-packet arrival times (min, mean, std, max)
- Packet size statistics
- TCP flags (SYN, ACK, RST, FIN counts)
- Protocol (TCP=6, UDP=17, ICMP=1)
- Source/destination IP and port (not for ML features)
- First N packet sizes (SPLT)

### What NFStream CANNOT capture:
- HTTP URLs, headers, or body content
- SQL injection or XSS payload strings
- Username/password values in login requests
- HTTP status codes (200, 401, 403...)
- DNS query names (only flow metadata)
- Application-layer session state

### Separability matrix:

| Class Pair | Expected Separability | Primary Signal |
|-----------|----------------------|----------------|
| PORT_SCAN vs everything | **High** | Tiny flows, many dst_ports, high rate |
| UDP_FLOOD vs everything | **High** | Protocol=UDP, extreme packet/byte rate |
| ICMP_FLOOD vs everything | **High** | Protocol=ICMP, high rate |
| DOS vs UDP_FLOOD | **Moderate** | Protocol (TCP vs UDP) |
| DOS vs ICMP_FLOOD | **High** | Protocol (TCP vs ICMP) |
| PORT_SCAN vs NETWORK_RECON | **Moderate** | Packet/flow count, rate, duration |
| BENIGN vs BRUTE_FORCE | **Low-Moderate** | Flow rate to same port, timing regularity |
| BENIGN vs WEB_ATTACK | **Low** | NFStream cannot see HTTP payloads |
| BRUTE_FORCE vs WEB_ATTACK | **Low** | Both HTTP, similar flow sizes |

---

## 🔬 Methodology: Why Multiple Runs?

### Problem with one 30-minute run:

```
Single 30-minute DOS session:
  │
  ├── All flows are highly correlated (same src, dst, rate, timing)
  ├── Splitting flows 80/20 means test set is nearly identical to train
  └── Model will overfit to THIS specific attack pattern
```

### Correct approach — multiple independent sessions:

```
DOS_001 (run 1, morning):   → TRAIN
DOS_002 (run 2, after reboot): → TRAIN
DOS_003 (run 3, different rate): → VALIDATION
DOS_004 (run 4, different tool): → TEST
```

Each run is an independent experiment. The model must generalize across runs.

---

## ⚠️ DDOS Honest Disclaimer

This dataset includes a `DDOS` class generated using **Linux network namespaces**.

- Each namespace has an isolated network context and a different source IP
- NFStream will see flows with different `src_ip` values
- However: all namespaces run on the same physical kernel and same hardware
- This is **NOT** a true distributed denial-of-service attack

**Metadata flag:** `simulated_ddos=true` is set in `experiments.csv`

If you publish this dataset, document: *"DDOS class is a single-host simulation  
using Linux network namespaces; it does not represent genuine distributed traffic."*

---

## 📈 Expected Results (Realistic Estimates)

After full data collection (~4 experiments × 9 classes):

| Class | Expected F1 (RF) | Reason |
|-------|-----------------|--------|
| PORT_SCAN | 0.90–0.98 | Very distinct flow pattern |
| UDP_FLOOD | 0.90–0.98 | Protocol + rate clearly distinct |
| ICMP_FLOOD | 0.90–0.98 | Protocol clearly distinct |
| DOS | 0.80–0.95 | High rate, distinct from benign |
| DDOS | 0.70–0.90 | Multiple src IPs help |
| NETWORK_RECON | 0.60–0.80 | Overlaps with PORT_SCAN |
| BRUTE_FORCE | 0.40–0.70 | Overlaps with benign HTTP |
| WEB_ATTACK | 0.30–0.60 | Nearly identical to benign HTTP |
| BENIGN | 0.70–0.90 | Depends on contamination |

**If WEB_ATTACK F1 is < 0.50, this is EXPECTED — not a bug.**  
You need DPI or application-layer logs to reliably detect web attacks.

---

## 🔧 Manual Commands (If Master Script Fails)

### Manually run one experiment:

```bash
# 1. Start capture
sudo tcpdump -i lo -w nids_dataset/captures/dos/DOS_001.pcap -s 0 &
TCPDUMP_PID=$!

# 2. Run attack (from another terminal or background)
bash attacks/gen_dos.sh 120

# 3. Stop capture
sudo kill -SIGTERM $TCPDUMP_PID

# 4. Process PCAP
python3 process/nfstream_processor.py \
    --pcap nids_dataset/captures/dos/DOS_001.pcap \
    --experiment-id DOS_001 \
    --class-id 2 \
    --class-name dos \
    --output nids_dataset/processed/dos.csv \
    --append
```

### Verify PCAP content:

```bash
tcpdump -r nids_dataset/captures/dos/DOS_001.pcap | head -20
tcpdump -r nids_dataset/captures/dos/DOS_001.pcap | wc -l   # packet count
```

---

## 📋 Checklist Before Training

- [ ] ≥4 experiment runs per class (for train/val/test split)
- [ ] Each class has flows in `processed/<class>.csv`
- [ ] `experiments.csv` has start_time and end_time for all experiments
- [ ] `merge_dataset.py` has been run → `nids_dataset_splits.csv` exists
- [ ] Validator shows no excessive NaN or constant features
- [ ] Leakage risk columns have been dropped (done automatically by `train_eval.py`)
- [ ] You understand which classes may have low F1 and why

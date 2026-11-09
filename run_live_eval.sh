#!/usr/bin/env bash
# =============================================================================
# run_live_eval.sh — Test all attacks live against the model
# =============================================================================

cd /home/mayank/Desktop/DATACOLLECTION
source venv/bin/activate

# Make sure background services are running
python3 services/start_http_service.py > /dev/null 2>&1 &
python3 services/start_auth_service.py > /dev/null 2>&1 &
sleep 2

ATTACKS=("benign" "port_scan" "dos" "ddos" "web_attack")
DURATION=10

echo "=========================================================="
echo "  LIVE INFERENCE TEST ACROSS ALL CLASSES"
echo "=========================================================="

for attack in "${ATTACKS[@]}"; do
    echo -e "\n----------------------------------------------------------"
    echo " [1] Generating live traffic for: $attack (${DURATION}s)"
    echo "----------------------------------------------------------"
    
    # Run the standard experiment runner for 10 seconds (using ID 999)
    sudo ./run_experiment.sh "$attack" 999 "$DURATION" > /dev/null 2>&1 || true
    
    PCAP_FILE="nids_dataset/captures/$attack/${attack^^}_999.pcap"
    
    echo " [2] Running Inference on $PCAP_FILE..."
    python3 ml/predict_pcap.py "$PCAP_FILE" || true
done

echo -e "\n=========================================================="
echo "  LIVE EVALUATION COMPLETE"
echo "=========================================================="

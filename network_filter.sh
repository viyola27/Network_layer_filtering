#!/bin/bash
#Suricata with custom rules to filter malicious traffic and applies thresholding to reduce false positives for detected attacks (such as ICMP flood or TCP SYN flood).
#Make it an executable: chmod +x network-layer-filtering.sh
#Then execute: sudo ./network-layer-filtering.sh

# Define variables
SURICATA_RULES_DIR="/var/lib/suricata/rules"
SURICATA_CONF="/etc/suricata/suricata.yaml"
CUSTOM_RULES_FILE="$SURICATA_RULES_DIR/custom.rules"
THRESHOLDS_FILE="/etc/suricata/threshold.config"
LOG_DIR="/var/log/suricata"
LOG_FILE="$LOG_DIR/eve.json"

# Step 1: Check if Suricata is installed
if ! command -v suricata &> /dev/null; then
    echo "Suricata is not installed. Installing now..."
    sudo apt update
    sudo apt install -y suricata
fi

# Step 2: Create custom rule file if it doesn't exist
if [ ! -f "$CUSTOM_RULES_FILE" ]; then
    sudo touch "$CUSTOM_RULES_FILE"
fi


# Step 3: Add custom rule to detect network layer attacks (ICMP flood, SYN flood)
echo "Adding custom rules for ICMP flood and TCP SYN flood..."

sudo bash -c "cat <<EOF > $CUSTOM_RULES_FILE
# Detect ICMP Flood (Ping Flood) - multiple ICMP echo-requests
alert icmp any any -> any any (msg:\"ICMP Flood Detected\"; itype:8; threshold:type both, track by_src, count 10, seconds 1; sid:100001; rev:1;)

# Detect TCP SYN Flood - excessive SYN packets
alert tcp any any -> any any (msg:\"TCP SYN Flood Detected\"; flags:S; threshold:type both, track by_src, count 10, seconds 1; sid:100002; rev:1;)
EOF"

# Step 4: Configure thresholding in Suricata (to avoid too many alerts for frequent attacks)
echo "Configuring thresholding to limit alert spam..."

sudo bash -c "cat <<EOF > $THRESHOLDS_FILE
# Threshold rule for ICMP Flood (limit 5 alerts per source IP every 10 seconds)
threshold gen_id 1, sig_id 100001, type limit, track by_src, count 5, seconds 10

# Threshold rule for TCP SYN Flood (limit 5 alerts per source IP every 10 seconds)
threshold gen_id 1, sig_id 100002, type limit, track by_src, count 5, seconds 10
EOF"

# Step 5: Enable the custom rule file in Suricata configuration
echo "Ensuring the custom rule file is enabled in Suricata..."

if ! grep -q "custom.rules" "$SURICATA_CONF"; then
    sudo sed -i '/rule-files:/a \ \ - custom.rules' "$SURICATA_CONF"
fi

# Step 6: Test Suricata configuration to ensure rules are valid
echo "Testing Suricata configuration..."
sudo suricata -T -c "$SURICATA_CONF"

if [ $? -ne 0 ]; then
    echo "Suricata configuration test failed. Please check your settings."
    exit 1
fi

# Step 7: Restart Suricata to apply new rules and thresholds
echo "Restarting Suricata..."
sudo systemctl restart suricata

# Step 8: Monitor Suricata alerts (optional)
echo "Monitoring Suricata alerts (press Ctrl+C to exit)..."
tail -f "$LOG_FILE"

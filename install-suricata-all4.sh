#!/usr/bin/env bash
##############################################################################
# install-suricata-all4.sh
# Implements all 4 Suricata detection methods on Ubuntu 22.04 / 24.04
#   1. DNS detection
#   2. HTTP inspection
#   3. TLS/SNI detection
#   4. IP Reputation / Threat Intel
#
# Run as root: sudo bash install-suricata-all4.sh
# Estimated total time: 15-30 minutes (depending on internet speed)
##############################################################################

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
step()  { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
CONF="/etc/suricata/suricata.yaml"
RULES="/etc/suricata/rules"
LOG="/var/log/suricata"

##############################################################################
# PHASE 1 — INSTALL (≈ 5 minutes)
##############################################################################
step "PHASE 1: Installing Suricata [~5 min]"

info "Adding Suricata PPA (latest stable)..."
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -qq

info "Installing Suricata + tools..."
apt-get install -y suricata suricata-update jq python3-pip curl dnsutils

info "Verifying installation..."
suricata --version
info "Suricata installed on interface: $IFACE"


##############################################################################
# PHASE 2 — BASE CONFIG (≈ 5 minutes)
##############################################################################
step "PHASE 2: Configuring suricata.yaml [~5 min]"

info "Backing up default config..."
cp "$CONF" "${CONF}.bak"

info "Setting HOME_NET to local subnets..."
LOCAL_NETS=$(ip -o -f inet addr show | awk '/scope global/{print $4}' | paste -sd,)
sed -i "s|HOME_NET:.*|HOME_NET: \"[$LOCAL_NETS]\"|" "$CONF"

info "Setting capture interface to: $IFACE"
sed -i "s|interface: eth0|interface: $IFACE|g" "$CONF"

info "Enabling community-id (for SIEM correlation)..."
sed -i 's/community-id: false/community-id: true/' "$CONF"

info "Enabling payload logging on alerts..."
sed -i '/- alert:/{n;s/payload: no/payload: yes/}' "$CONF" || true

info "Setting rule path..."
mkdir -p "$RULES"

info "Pointing suricata.yaml at rule directory..."
grep -q "default-rule-path" "$CONF" \
  && sed -i "s|default-rule-path:.*|default-rule-path: $RULES|" "$CONF" \
  || echo "default-rule-path: $RULES" >> "$CONF"


##############################################################################
# PHASE 3 — METHOD 1: DNS DETECTION (≈ 3 minutes)
##############################################################################
step "PHASE 3: Method 1 — DNS Detection [~3 min]"

info "Verifying DNS app-layer parser is enabled..."
grep -A2 "dns:" "$CONF" | grep -q "enabled: yes" \
  && info "DNS parser already enabled." \
  || sed -i '/^  dns:/,/enabled:/{s/enabled: no/enabled: yes/}' "$CONF"

info "Writing DNS detection rules..."
cat > "$RULES/dns-detection.rules" << 'EOF'
# ── DNS Detection Rules ───────────────────────────────────────────────────────

alert dns $HOME_NET any -> any 53 (
    msg:"DNS - known malicious domain lookup";
    dns.query; content:"malicious-site.com"; nocase;
    classtype:trojan-activity; sid:9000001; rev:1;)

alert dns $HOME_NET any -> any 53 (
    msg:"DNS - phishing keyword in domain";
    dns.query;
    pcre:"/(?:verify|update|signin|login)-(?:corp|office|microsoft|google)/i";
    classtype:social-engineering; sid:9000002; rev:1;)

alert dns $HOME_NET any -> any 53 (
    msg:"DNS - suspicious new TLD phishing pattern";
    dns.query;
    pcre:"/(?:login|verify|secure)\.[^.]+\.(?:xyz|top|click|live|tk|ml)$/i";
    classtype:social-engineering; sid:9000003; rev:1;)

alert dns $HOME_NET any -> any 53 (
    msg:"DNS - high frequency queries possible DGA";
    dns.query; pcre:"/^[a-z0-9]{12,}\.(?:com|net|org)$/";
    threshold:type both, track by_src, count 20, seconds 10;
    classtype:trojan-activity; sid:9000004; rev:1;)
EOF
info "DNS rules written: $RULES/dns-detection.rules"


##############################################################################
# PHASE 4 — METHOD 2: HTTP INSPECTION (≈ 3 minutes)
##############################################################################
step "PHASE 4: Method 2 — HTTP Inspection [~3 min]"

info "Verifying HTTP app-layer parser is enabled..."
grep -A3 "^    http:" "$CONF" | grep -q "enabled: yes" \
  && info "HTTP parser already enabled." \
  || sed -i '/^    http:/,/enabled:/{s/enabled: no/enabled: yes/}' "$CONF"

info "Writing HTTP inspection rules..."
cat > "$RULES/http-inspection.rules" << 'EOF'
# ── HTTP Inspection Rules ─────────────────────────────────────────────────────

alert http $HOME_NET any -> $EXTERNAL_NET 80 (
    msg:"HTTP - known malicious host access";
    flow:established,to_server;
    http.host; content:"malicious-site.com"; nocase;
    classtype:trojan-activity; sid:9001001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET 80 (
    msg:"HTTP - credential harvest URI";
    flow:established,to_server;
    http.uri;
    pcre:"/\/(verify|validate|confirm|update|signin|login)\?/i";
    classtype:social-engineering; sid:9001002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET 80 (
    msg:"HTTP - credential POST to external host";
    flow:established,to_server;
    http.method; content:"POST";
    http.request_body;
    pcre:"/(?:username|password|passwd|email)=/i";
    classtype:social-engineering; sid:9001003; rev:1;)

alert http $EXTERNAL_NET 80 -> $HOME_NET any (
    msg:"HTTP - executable file delivered";
    flow:established,to_client;
    file.data; content:"MZ"; depth:2;
    classtype:trojan-activity; sid:9001004; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET 80 (
    msg:"HTTP - URL shortener redirect (possible phishing delivery)";
    flow:established,to_server;
    http.host;
    pcre:"/^(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|rb\.gy|cutt\.ly)$/i";
    classtype:social-engineering; sid:9001005; rev:1;)
EOF
info "HTTP rules written: $RULES/http-inspection.rules"


##############################################################################
# PHASE 5 — METHOD 3: TLS/SNI DETECTION (≈ 3 minutes)
##############################################################################
step "PHASE 5: Method 3 — TLS/SNI Detection [~3 min]"

info "Verifying TLS app-layer parser is enabled..."
grep -A3 "^    tls:" "$CONF" | grep -q "enabled: yes" \
  && info "TLS parser already enabled." \
  || sed -i '/^    tls:/,/enabled:/{s/enabled: no/enabled: yes/}' "$CONF"

info "Writing TLS/SNI rules..."
cat > "$RULES/tls-sni-detection.rules" << 'EOF'
# ── TLS/SNI Detection Rules ───────────────────────────────────────────────────

alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"TLS/SNI - known malicious domain over HTTPS";
    flow:established,to_server;
    tls.sni; content:"malicious-site.com"; nocase;
    classtype:trojan-activity; sid:9002001; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"TLS/SNI - C2 beacon known domain";
    flow:established,to_server;
    tls.sni; pcre:"/(?:c2panel|botnet|rat-server|cnc-host)/i";
    classtype:trojan-activity; sid:9002002; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"TLS/SNI - phishing over HTTPS";
    flow:established,to_server;
    tls.sni;
    pcre:"/(?:verify|update|signin)-(?:corp|office|microsoft|google)/i";
    classtype:social-engineering; sid:9002003; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"TLS/SNI - self-signed cert from external host (suspicious)";
    flow:established,to_server;
    tls.cert_issuer; content:!"Let's Encrypt";
    tls.cert_issuer; content:!"DigiCert";
    tls.cert_issuer; content:!"GlobalSign";
    tls.cert_subject;
    pcre:"/CN=(?:localhost|example|test|homelab)/i";
    classtype:trojan-activity; sid:9002004; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"TLS/SNI - high frequency connections possible C2 beaconing";
    flow:established,to_server;
    tls.sni; content:!"google.com";
    tls.sni; content:!"microsoft.com";
    threshold:type both, track by_src, count 15, seconds 60;
    classtype:trojan-activity; sid:9002005; rev:1;)
EOF
info "TLS/SNI rules written: $RULES/tls-sni-detection.rules"


##############################################################################
# PHASE 6 — METHOD 4: IP REPUTATION (≈ 5 minutes)
##############################################################################
step "PHASE 6: Method 4 — IP Reputation & Threat Intel [~5 min]"

info "Creating IP reputation directory..."
mkdir -p /etc/suricata/iprep

info "Pulling live threat intel feeds..."

# Emerging Threats known C2 IP list
curl -fsSL "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" \
  | grep -v "^#" | grep -v "^$" \
  > /etc/suricata/iprep/emerging-block.txt \
  && info "Emerging Threats IP blocklist downloaded." \
  || warn "Could not fetch ET blocklist (needs subscription). Skipping."

# AbuseCH Feodo Tracker (C2 IPs)
curl -fsSL "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
  | grep -v "^#" | grep -v "^$" \
  > /etc/suricata/iprep/feodo-c2.txt \
  && info "AbuseCH Feodo C2 IPs downloaded ($(wc -l < /etc/suricata/iprep/feodo-c2.txt) entries)." \
  || warn "Could not fetch Feodo feed. Check connectivity."

# Create iprep CSV format: ip,category,score (1-100)
info "Building iprep database from downloaded feeds..."
python3 - << 'PYEOF'
import os, ipaddress

iprep_path = "/etc/suricata/iprep/iprep.csv"
sources = [
    ("/etc/suricata/iprep/feodo-c2.txt",      "CnC",     90),
    ("/etc/suricata/iprep/emerging-block.txt", "Malware", 80),
]

entries = []
for filepath, category, score in sources:
    if not os.path.exists(filepath):
        continue
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line.split("/")[0])
                entries.append(f"{line},{category},{score}")
            except ValueError:
                pass

with open(iprep_path, "w") as out:
    out.write("# ip,category,score\n")
    out.write("\n".join(entries))

print(f"iprep.csv written: {len(entries)} entries")
PYEOF

info "Enabling iprep in suricata.yaml..."
cat >> "$CONF" << 'YAML'

# IP Reputation
reputation:
  enabled: yes
  iprep-files:
    - /etc/suricata/iprep/iprep.csv
  default-reputation-path: /etc/suricata/iprep
YAML

info "Writing IP reputation rules..."
cat > "$RULES/ip-reputation.rules" << 'EOF'
# ── IP Reputation Rules ───────────────────────────────────────────────────────

alert ip $HOME_NET any -> $EXTERNAL_NET any (
    msg:"IPREP - outbound connection to known C2 IP";
    iprep:dst,CnC,>,70;
    classtype:trojan-activity; sid:9003001; rev:1;)

alert ip $HOME_NET any -> $EXTERNAL_NET any (
    msg:"IPREP - outbound connection to known malware IP";
    iprep:dst,Malware,>,60;
    classtype:trojan-activity; sid:9003002; rev:1;)

alert ip $HOME_NET any -> $EXTERNAL_NET any (
    msg:"IPREP - large outbound transfer to suspicious IP";
    iprep:dst,CnC,>,50;
    threshold:type both, track by_src, count 1, seconds 300;
    classtype:trojan-activity; sid:9003003; rev:1;)
EOF
info "IP reputation rules written."


##############################################################################
# PHASE 7 — LOAD ET OPEN RULESETS (≈ 5 minutes)
##############################################################################
step "PHASE 7: Loading Emerging Threats Open rulesets [~5 min]"

info "Running suricata-update..."
suricata-update update-sources
suricata-update enable-source et/open
suricata-update enable-source abuse.ch/urlhaus     # Malicious URLs
suricata-update enable-source abuse.ch/sslbl       # TLS certificate blocklist
suricata-update --suricata-conf "$CONF" --output "$RULES"
info "ET Open rules loaded."


##############################################################################
# PHASE 8 — REGISTER CUSTOM RULES & VALIDATE (≈ 2 minutes)
##############################################################################
step "PHASE 8: Registering custom rules & validating [~2 min]"

info "Adding custom rule files to suricata.yaml..."
for rulefile in dns-detection http-inspection tls-sni-detection ip-reputation; do
    grep -q "$rulefile.rules" "$CONF" \
      || echo "  - $rulefile.rules" >> "$CONF"
done

info "Validating full config..."
suricata -T -c "$CONF" -v && info "Config validation PASSED." \
  || error "Config validation FAILED. Check output above."


##############################################################################
# PHASE 9 — SYSTEMD + AUTO-UPDATE (≈ 2 minutes)
##############################################################################
step "PHASE 9: Enabling systemd service + daily rule updates [~2 min]"

info "Enabling and starting Suricata..."
systemctl enable suricata
systemctl restart suricata
sleep 3
systemctl is-active --quiet suricata \
  && info "Suricata service is running." \
  || error "Suricata failed to start. Check: journalctl -u suricata -n 50"

info "Setting up daily rule auto-update (2am cron)..."
cat > /etc/cron.d/suricata-update << 'CRON'
0 2 * * * root suricata-update && kill -USR2 $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null
CRON
info "Daily update scheduled."


##############################################################################
# PHASE 10 — SMOKE TESTS
##############################################################################
step "PHASE 10: Running smoke tests"

sleep 5  # Let Suricata fully start

info "Test 1 — DNS: querying known pattern domain..."
dig +short verify-corp-login.xyz @8.8.8.8 &>/dev/null || true
sleep 2

info "Test 2 — HTTP: sending test request with phishing URI..."
curl -s -o /dev/null --max-time 3 \
  "http://example.com/verify?username=test&password=test123" || true
sleep 2

info "Test 3 — Checking fast.log for alerts..."
if [ -f "$LOG/fast.log" ] && [ -s "$LOG/fast.log" ]; then
    info "Alerts found in fast.log:"
    tail -5 "$LOG/fast.log"
else
    warn "No alerts yet — Suricata may still be warming up. Check in 30s."
fi


##############################################################################
# SUMMARY
##############################################################################
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}${BOLD}All 4 detection methods deployed successfully${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Interface:  $IFACE"
echo "  Config:     $CONF"
echo "  Rules dir:  $RULES"
echo "  Logs:       $LOG"
echo ""
echo "  Rule files deployed:"
echo "    $RULES/dns-detection.rules"
echo "    $RULES/http-inspection.rules"
echo "    $RULES/tls-sni-detection.rules"
echo "    $RULES/ip-reputation.rules"
echo ""
echo "  Monitoring commands:"
echo ""
echo "  # Live alerts"
echo "  tail -f $LOG/fast.log"
echo ""
echo "  # JSON alerts (SIEM-ready)"
echo "  tail -f $LOG/eve.json | jq 'select(.event_type==\"alert\")'"
echo ""
echo "  # Filter by detection method"
echo "  tail -f $LOG/eve.json | jq 'select(.event_type==\"alert\") | {sig: .alert.signature, src: .src_ip, dst: .dest_ip}'"
echo ""
echo "  # Reload rules without restart"
echo "  kill -USR2 \$(cat /var/run/suricata.pid)"
echo ""
echo "  # Status check"
echo "  systemctl status suricata"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

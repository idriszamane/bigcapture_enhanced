#!/bin/bash
# BIG CAPTURE: NETWORK PACKET ANALYZER TOOL
# By: Idris Yahaya
# Enhanced version with real-time attack display

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print colored messages
print_critical() { echo -e "${RED}🔴 [CRITICAL] $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  [WARNING] $1${NC}"; }
print_success() { echo -e "${GREEN}✅ [SUCCESS] $1${NC}"; }
print_info() { echo -e "${CYAN}📊 [INFO] $1${NC}"; }
print_attack() { echo -e "${PURPLE}⚔️  [ATTACK] $1${NC}"; }
print_file() { echo -e "${BLUE}📁 [FILE] $1${NC}"; }
print_error() { echo -e "${RED}[!] $1${NC}"; }

# Global variables
REPORT_DIR="./bigcapture_reports_$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$REPORT_DIR/logs"
EXPORT_DIR="$REPORT_DIR/exports"
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"
PCAP=""
START_TS=""

# Create directories
mkdir -p "$REPORT_DIR" "$LOG_DIR" "$EXPORT_DIR"

# Banner
print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           BIG CAPTURE: NETWORK PACKET ANALYZER           ║"
    echo "║                   By: Idris Yahaya                       ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ==================== SAVE PROMPT SYSTEM ====================
prompt_keep_new_artifacts(){
  echo ""
  read -p "Save the generated outputs? (y/N): " ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    find "$LOG_DIR" -type f -newermt "$START_TS" -delete 2>/dev/null
    find "$REPORT_DIR" -type f -newermt "$START_TS" -delete 2>/dev/null
    find "$EXPORT_DIR" -type f -newermt "$START_TS" -delete 2>/dev/null
    print_info "Outputs discarded"
  else
    print_success "Outputs saved under Case ID: $CASE_ID"
  fi
}

# ==================== PCAP SELECTION ====================
select_pcap(){
  echo ""
  echo "=== SEARCHING FOR PCAP FILES ==="
  echo "1) Search entire system (slow)"
  echo "2) Search home directory (recommended)"
  echo "3) Search Downloads only (fast)"
  read -p "Choose search scope: " scope

  case $scope in
    1) SEARCH_PATH="/" ;;
    2) SEARCH_PATH="$HOME" ;;
    3) SEARCH_PATH="$HOME/Downloads" ;;
    *)
      print_error "Invalid option"
      return 1
      ;;
  esac

  print_info "Searching for PCAP files in $SEARCH_PATH ..."
  mapfile -t PCAP_FILES < <(
    find "$SEARCH_PATH" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) 2>/dev/null
  )

  if [[ ${#PCAP_FILES[@]} -eq 0 ]]; then
    print_error "No PCAP files found"
    return 1
  fi

  echo ""
  echo "Found ${#PCAP_FILES[@]} PCAP files:"
  echo "--------------------------------"

  for i in "${!PCAP_FILES[@]}"; do
    printf "%3d) %s\n" $((i+1)) "${PCAP_FILES[$i]}"
  done

  echo ""
  read -p "Select PCAP number: " choice

  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#PCAP_FILES[@]} )); then
    print_error "Invalid selection"
    return 1
  fi

  PCAP="${PCAP_FILES[$((choice-1))]}"
  print_success "PCAP selected: $PCAP"
  export PCAP
}

# ==================== CAPTURING NETWORK TRAFFIC USING TSHARK ===============
capture_traffic(){
  if ! command -v tshark &>/dev/null; then
    print_error "tshark is not installed"
    return 1
  fi

  echo ""
  echo "=== LIVE PCAP CAPTURE ==="
  tshark -D
  echo ""

  read -p "Select interface number: " IFACE_NUM
  IFACE=$(tshark -D | sed -n "${IFACE_NUM}p" | awk '{print $2}' | tr -d ',')

  [[ -z "$IFACE" ]] && print_error "Invalid interface" && return 1
  
  read -p "Capture duration in seconds (default 100): " DURATION
  DURATION=${DURATION:-100}

  PCAP="$REPORT_DIR/live_capture_$(date +%d%m%Y_%H%M%S).pcap"

  print_info "Capturing on $IFACE for $DURATION seconds..."
  tshark -i "$IFACE" -a duration:"$DURATION" -w "$PCAP"

  if [[ -f "$PCAP" ]]; then
    print_success "Capture saved: $PCAP"
  else
    print_error "Capture failed"
    return 1
  fi
}

# ==================== QUICK ANALYSIS ====================
quick_analysis(){
  local p="$1"
  START_TS=$(date '+%Y-%m-%d %H:%M:%S')
  local out="$LOG_DIR/quick.txt"
  echo "=== QUICK ANALYSIS [$CASE_ID] ===" | tee "$out"
  capinfos "$p" | tee -a "$out"
  tshark -r "$p" -q -z io,phs | head -20 | tee -a "$out"
  prompt_keep_new_artifacts
}

# ==================== FULL ANALYSIS =======================
full_analysis(){
  local PCAP_FILE="$1"
  print_info "Starting analysis of: $PCAP_FILE"
  echo ""

  # REAL-TIME ATTACK DETECTION FUNCTION
  detect_attacks() {
    print_attack "🔍 REAL-TIME ATTACK DETECTION IN PROGRESS..."
    echo "════════════════════════════════════════════════════════════"
    
    # Initialize attack counters
    local ATTACK_COUNT=0
    local CRITICAL_COUNT=0
    
    # 1. DETECT PORT SCANNING
    print_info "Scanning for port scanning activity..."
    local SYN_SCAN=$(tshark -r "$PCAP_FILE" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
        -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn)
    
    if [ -n "$SYN_SCAN" ]; then
      echo "$SYN_SCAN" | while read -r line; do
        local COUNT=$(echo $line | awk '{print $1}')
        local IP=$(echo $line | awk '{print $2}')
        if [ "$COUNT" -gt 50 ]; then
          print_attack "PORT SCANNING DETECTED!"
          echo "   Attacker IP: $IP"
          echo "   SYN packets sent: $COUNT"
          echo "   Type: SYN Scan"
          echo "   🎯 Target: Multiple ports from single source"
          echo ""
          ATTACK_COUNT=$((ATTACK_COUNT + 1))
          echo "$IP|Port Scanning|$COUNT SYN packets" >> "$REPORT_DIR/attackers.txt"
        fi
      done <<< "$SYN_SCAN"
    fi
    
    # 2. DETECT BRUTE FORCE ATTACKS
    print_info "Scanning for brute force attacks..."
    
    # SSH brute force
    local SSH_FAILED=$(tshark -r "$PCAP_FILE" -Y "ssh" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -10)
    
    if [ -n "$SSH_FAILED" ]; then
      echo "$SSH_FAILED" | while read -r line; do
        local COUNT=$(echo $line | awk '{print $1}')
        local IP=$(echo $line | awk '{print $2}')
        if [ "$COUNT" -gt 10 ]; then
          print_attack "SSH BRUTE FORCE DETECTED!"
          echo "   Attacker IP: $IP"
          echo "   Attempts: $COUNT"
          echo "   Service: SSH (port 22)"
          echo "   🎯 Target: Username/password guessing"
          echo ""
          ATTACK_COUNT=$((ATTACK_COUNT + 1))
          echo "$IP|SSH Brute Force|$COUNT attempts" >> "$REPORT_DIR/attackers.txt"
        fi
      done <<< "$SSH_FAILED"
    fi
    
    # FTP brute force
    local FTP_FAILED=$(tshark -r "$PCAP_FILE" -Y "ftp" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -10)
    
    if [ -n "$FTP_FAILED" ]; then
      echo "$FTP_FAILED" | while read -r line; do
        local COUNT=$(echo $line | awk '{print $1}')
        local IP=$(echo $line | awk '{print $2}')
        if [ "$COUNT" -gt 5 ]; then
          print_attack "FTP BRUTE FORCE DETECTED!"
          echo "   Attacker IP: $IP"
          echo "   Connections: $COUNT"
          echo "   Service: FTP (port 21)"
          echo ""
          ATTACK_COUNT=$((ATTACK_COUNT + 1))
          echo "$IP|FTP Brute Force|$COUNT connections" >> "$REPORT_DIR/attackers.txt"
        fi
      done <<< "$FTP_FAILED"
    fi
    
    # 3. DETECT FILE UPLOADS/TRANSFERS
    print_info "Scanning for file transfers..."
    
    # FTP file uploads
    local FTP_STOR=$(tshark -r "$PCAP_FILE" -Y "ftp" -T fields -e ip.src 2>/dev/null | head -5)
    
    if [ -n "$FTP_STOR" ]; then
      print_file "FTP FILE UPLOADS DETECTED:"
      echo "$FTP_STOR" | while read -r IP; do
        if [ -n "$IP" ]; then
          print_file "   Upload from: $IP"
          echo "   Protocol: FTP"
          echo ""
          echo "$IP|File Upload|FTP" >> "$REPORT_DIR/file_transfers.txt"
        fi
      done
    fi
    
    # 4. DETECT SQL INJECTION ATTEMPTS
    print_info "Scanning for SQL injection attacks..."
    local SQL_PATTERNS=("union select" "1=1" "sleep(" "benchmark(" "' OR '1'='1" "drop table" 
                  "insert into" "update set" "information_schema")
    
    for pattern in "${SQL_PATTERNS[@]}"; do
      local SQL_ATTACKS=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e ip.src -e ip.dst 2>/dev/null | head -5)
      
      if [ -n "$SQL_ATTACKS" ]; then
        print_attack "SQL INJECTION DETECTED!"
        echo "   Pattern: '$pattern'"
        echo "$SQL_ATTACKS" | head -5 | while read -r line; do
          local SRC_IP=$(echo $line | awk '{print $1}')
          local DST_IP=$(echo $line | awk '{print $2}')
          if [ -n "$SRC_IP" ] && [ -n "$DST_IP" ]; then
            echo "   Attacker: $SRC_IP → Target: $DST_IP"
            ATTACK_COUNT=$((ATTACK_COUNT + 1))
            echo "$SRC_IP|SQL Injection|$pattern on $DST_IP" >> "$REPORT_DIR/attackers.txt"
          fi
        done
        echo ""
      fi
    done
    
    # 5. DETECT XSS ATTACKS
    print_info "Scanning for XSS attacks..."
    local XSS_PATTERNS=("<script>" "javascript:" "onload=" "onerror=" "alert(" "document.cookie")
    
    for pattern in "${XSS_PATTERNS[@]}"; do
      local XSS_ATTACKS=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e ip.src -e ip.dst 2>/dev/null | head -5)
      
      if [ -n "$XSS_ATTACKS" ]; then
        print_attack "XSS ATTACK DETECTED!"
        echo "   Pattern: '$pattern'"
        echo "$XSS_ATTACKS" | head -3 | while read -r line; do
          local SRC_IP=$(echo $line | awk '{print $1}')
          local DST_IP=$(echo $line | awk '{print $2}')
          if [ -n "$SRC_IP" ] && [ -n "$DST_IP" ]; then
            echo "   Attacker: $SRC_IP → Target: $DST_IP"
            ATTACK_COUNT=$((ATTACK_COUNT + 1))
            echo "$SRC_IP|XSS Attack|$pattern on $DST_IP" >> "$REPORT_DIR/attackers.txt"
          fi
        done
        echo ""
      fi
    done
    
    # 6. DETECT COMMAND INJECTION
    print_info "Scanning for command injection..."
    local CMD_PATTERNS=("; ls" "| cat" "&& whoami" "\`id\`" "\$(id)" "system(" "exec(" "popen(")
    
    for pattern in "${CMD_PATTERNS[@]}"; do
      local CMD_ATTACKS=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e ip.src -e ip.dst 2>/dev/null | head -5)
      
      if [ -n "$CMD_ATTACKS" ]; then
        print_attack "COMMAND INJECTION DETECTED!"
        echo "   Pattern: '$pattern'"
        echo "$CMD_ATTACKS" | head -3 | while read -r line; do
          local SRC_IP=$(echo $line | awk '{print $1}')
          local DST_IP=$(echo $line | awk '{print $2}')
          if [ -n "$SRC_IP" ] && [ -n "$DST_IP" ]; then
            echo "   Attacker: $SRC_IP → Target: $DST_IP"
            ATTACK_COUNT=$((ATTACK_COUNT + 1))
            echo "$SRC_IP|Command Injection|$pattern on $DST_IP" >> "$REPORT_DIR/attackers.txt"
          fi
        done
        echo ""
      fi
    done
    
    # 7. DETECT MALWARE COMMUNICATION
    print_info "Scanning for malware C2 communication..."
    
    # Known malicious domains/patterns (simplified)
    local MALICIOUS_PATTERNS=("pastebin.com" "transfer.sh" "anonfiles.com" "ip-api.com" 
                        "checkip.amazonaws.com" "api.ipify.org")
    
    for pattern in "${MALICIOUS_PATTERNS[@]}"; do
      local MAL_DNS=$(tshark -r "$PCAP_FILE" -Y "dns" -T fields -e ip.src 2>/dev/null | sort | uniq | head -5)
      
      if [ -n "$MAL_DNS" ]; then
        print_critical "MALWARE C2 COMMUNICATION DETECTED!"
        echo "   C2 Domain: $pattern"
        echo "$MAL_DNS" | while read -r IP; do
          if [ -n "$IP" ]; then
            echo "   Infected Host: $IP"
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            echo "$IP|Malware C2|Contacting $pattern" >> "$REPORT_DIR/attackers.txt"
          fi
        done
        echo ""
      fi
    done
    
    # 8. DETECT DATA EXFILTRATION
    print_info "Scanning for data exfiltration..."
    
    # Large DNS queries (DNS tunneling)
    local DNS_EXFIL=$(tshark -r "$PCAP_FILE" -Y "dns" -T fields -e ip.src -e dns.qry.name 2>/dev/null | head -5)
    
    if [ -n "$DNS_EXFIL" ]; then
      print_critical "DATA EXFILTRATION DETECTED (DNS Tunneling)!"
      echo "$DNS_EXFIL" | while read -r line; do
        local IP=$(echo $line | awk '{print $1}')
        local DOMAIN=$(echo $line | awk '{print $2}')
        if [ -n "$IP" ]; then
          echo "   Source IP: $IP"
          echo "   Long DNS query: $DOMAIN"
          CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
          echo "$IP|Data Exfiltration|DNS tunneling: $DOMAIN" >> "$REPORT_DIR/attackers.txt"
        fi
      done
      echo ""
    fi
    
    # 9. SHOW ATTACKER SUMMARY
    echo "════════════════════════════════════════════════════════════"
    print_info "ATTACK DETECTION SUMMARY:"
    echo ""
    echo "   Total attacks detected: $ATTACK_COUNT"
    echo "   Critical findings: $CRITICAL_COUNT"
    echo ""
    
    if [ -f "$REPORT_DIR/attackers.txt" ]; then
      print_info "TOP ATTACKERS (by activity):"
      cat "$REPORT_DIR/attackers.txt" 2>/dev/null | cut -d'|' -f1 | \
        sort | uniq -c | sort -rn | head -5 | while read -r line; do
        local COUNT=$(echo $line | awk '{print $1}')
        local IP=$(echo $line | awk '{print $2}')
        echo "   $COUNT attacks from: $IP"
      done
    fi
    
    if [ -f "$REPORT_DIR/file_transfers.txt" ]; then
      local FILE_COUNT=$(wc -l < "$REPORT_DIR/file_transfers.txt" 2>/dev/null || echo "0")
      echo "   File transfers detected: $FILE_COUNT"
    fi
    echo ""
  }

  # BASIC NETWORK ANALYSIS
  basic_analysis() {
    print_info "📊 BASIC NETWORK ANALYSIS"
    echo "════════════════════════════════════════════════════════════"
    
    # Total packets
    local PACKET_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
    print_info "Total packets: $PACKET_COUNT"
    
    # Top talkers
    print_info "Top 5 Talkers:"
    tshark -r "$PCAP_FILE" -T fields -e ip.src 2>/dev/null | \
      grep -v "^$" | sort | uniq -c | sort -rn | head -5 | while read -r line; do
      local COUNT=$(echo $line | awk '{print $1}')
      local IP=$(echo $line | awk '{print $2}')
      echo "   $IP ($COUNT packets)"
    done
    
    # Most targeted ports
    print_info "Most Targeted Ports:"
    tshark -r "$PCAP_FILE" -T fields -e tcp.dstport -e udp.dstport 2>/dev/null | \
      grep -v "^$" | sort | uniq -c | sort -rn | head -5 | while read -r line; do
      local COUNT=$(echo $line | awk '{print $1}')
      local PORT=$(echo $line | awk '{print $2}')
      local SERVICE="unknown"
      if [ -f /etc/services ]; then
        SERVICE=$(grep -w "^$PORT/" /etc/services 2>/dev/null | head -1 | awk '{print $1}' || echo "unknown")
      fi
      echo "   Port $PORT ($SERVICE): $COUNT connections"
    done
    
    echo ""
  }

  # VULNERABILITY SCAN
  vulnerability_scan() {
    print_info "🔓 VULNERABILITY SCAN"
    echo "════════════════════════════════════════════════════════════"
    
    # Plaintext protocols
    print_info "Checking plaintext protocols..."
    
    local PROTOCOLS=("http" "ftp" "telnet" "smtp" "pop3")
    for proto in "${PROTOCOLS[@]}"; do
      local COUNT=$(tshark -r "$PCAP_FILE" -Y "$proto" 2>/dev/null | wc -l)
      if [ "$COUNT" -gt 0 ]; then
        print_warning "Plaintext $proto detected: $COUNT packets"
      fi
    done
    
    # Weak SSL/TLS
    print_info "Checking SSL/TLS security..."
    
    # Default credentials
    print_info "Checking for default credentials..."
    
    echo ""
  }

  # FILE ANALYSIS
  file_analysis() {
    print_info "📁 FILE TRANSFER ANALYSIS"
    echo "════════════════════════════════════════════════════════════"
    
    # Extract files from PCAP
    print_info "Attempting to extract files from traffic..."
    
    # Create directory for extracted files
    local EXTRACT_DIR="$REPORT_DIR/extracted_files"
    mkdir -p "$EXTRACT_DIR"
    
    # List potential file transfers
    print_info "File transfer attempts found:"
    
    # HTTP downloads
    local HTTP_DOWNLOADS=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e ip.src -e ip.dst 2>/dev/null | head -5)
    
    if [ -n "$HTTP_DOWNLOADS" ]; then
      print_info "HTTP File Downloads:"
      echo "$HTTP_DOWNLOADS" | while read -r line; do
        local SRC=$(echo $line | awk '{print $1}')
        local DST=$(echo $line | awk '{print $2}')
        if [ -n "$SRC" ] && [ -n "$DST" ]; then
          echo "   From: $SRC → To: $DST"
        fi
      done
    fi
    
    # FTP transfers
    local FTP_FILES=$(tshark -r "$PCAP_FILE" -Y "ftp" -T fields -e ip.src 2>/dev/null | head -5)
    
    if [ -n "$FTP_FILES" ]; then
      print_info "FTP File Transfers:"
      echo "$FTP_FILES" | while read -r IP; do
        if [ -n "$IP" ]; then
          echo "   IP: $IP - FTP Activity"
        fi
      done
    fi
    
    echo ""
  }

  # Run analyses
  basic_analysis
  detect_attacks
  vulnerability_scan
  file_analysis
  
  # GENERATE FINAL REPORT
  print_success "🎉 ANALYSIS COMPLETE!"
  echo ""
  print_info "📁 REPORT DIRECTORY: $REPORT_DIR/"
  echo ""
  
  # Show directory contents
  print_info "📄 GENERATED FILES:"
  ls -la "$REPORT_DIR/" | tail -n +2 | while read -r line; do
    echo "   $line"
  done
  
  echo ""
  print_info "🔍 QUICK ACCESS COMMANDS:"
  echo ""
  echo "   View attackers:        cat $REPORT_DIR/attackers.txt 2>/dev/null"
  echo "   View file transfers:   cat $REPORT_DIR/file_transfers.txt 2>/dev/null"
  echo "   View full log:         cat $REPORT_DIR/analysis.log 2>/dev/null"
  echo "   View extracted files:  ls -la $REPORT_DIR/extracted_files/ 2>/dev/null"
  echo ""
  print_info "⚡ RECOMMENDED ACTIONS:"
  echo ""
  
  # Check if we found attacks
  if [ -f "$REPORT_DIR/attackers.txt" ] && [ -s "$REPORT_DIR/attackers.txt" ]; then
    print_critical "IMMEDIATE ACTION REQUIRED:"
    echo "   1. Block identified attacker IPs"
    echo "   2. Change compromised credentials"
    echo "   3. Scan systems for malware"
    echo "   4. Review firewall rules"
  else
    print_success "No critical attacks detected. Review logs for warnings."
  fi
  
  echo ""
  echo "════════════════════════════════════════════════════════════"
}

# ==================== MAIN MENU ====================
main_menu(){
  print_banner
  
  echo ""
  echo "=============================================="
  echo "ADVANCED PCAP ANALYZER"
  echo "Case ID: $CASE_ID"
  echo "Output Directory: $REPORT_DIR"
  echo "=============================================="
  echo "1. Capture Network Traffic (tshark)"
  echo "2. Quick Analysis"
  echo "3. Full Analysis"
  echo "0. Exit"
  echo "=============================================="
  read -p "Choose: " ch

  case $ch in
    1) capture_traffic ;;
    2) select_pcap && quick_analysis "$PCAP" ;;
    3) select_pcap && full_analysis "$PCAP" ;;
    0) exit 0 ;;
    *) main_menu ;;
  esac
  
  # Return to menu after operation
  echo ""
  read -p "Press Enter to continue..."
  main_menu
}

# ==================== START ====================
# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  # Check for required tools
  if ! command -v tshark &>/dev/null; then
    print_error "tshark is not installed. Please install wireshark-cli."
    exit 1
  fi
  
  # Start main menu
  main_menu
fi

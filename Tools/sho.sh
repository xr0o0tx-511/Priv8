#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get domain from command line parameter
if [ $# -lt 1 ]; then
    echo -e "${RED}Error: Domain parameter required${NC}"
    echo -e "${YELLOW}Usage: $0 <domain>${NC}"
    echo -e "${YELLOW}Example: $0 dhl.com${NC}"
    exit 1
fi

DOMAIN=$1

# Set up base directory
BASE_DIR="/root/recon/${DOMAIN}"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR" || exit 1

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  SHODAN RECONNAISSANCE FRAMEWORK${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "${YELLOW}[*] Starting reconnaissance for ${DOMAIN}${NC}"
echo -e "${YELLOW}[*] Target Directory: ${BASE_DIR}${NC}"
echo ""

# Step 1: Shodan search for SSL certificates
echo -e "${YELLOW}[*] Step 1: Searching Shodan for SSL certificates...${NC}"
if shodan search "ssl.cert.subject.CN:\"${DOMAIN}\"" --fields ip_str 2>/dev/null | anew shodan.txt 2>/dev/null; then
    SHODAN_COUNT=$(wc -l < shodan.txt)
    if [ "$SHODAN_COUNT" -gt 0 ]; then
        echo -e "${GREEN}[+] Shodan results saved to shodan.txt${NC}"
        echo -e "${GREEN}[+] Found ${SHODAN_COUNT} unique IP addresses${NC}"
    else
        echo -e "${RED}[-] No IPs found in Shodan results${NC}"
        exit 1
    fi
else
    echo -e "${RED}[-] Shodan search failed (check API key)${NC}"
    exit 1
fi

echo ""

# Step 2: Port scanning with naabu
echo -e "${YELLOW}[*] Step 2: Running port scan with naabu (top 1000 ports)...${NC}"
echo -e "${YELLOW}[*] Using parallel scanning for speed...${NC}"
if cat shodan.txt | naabu -top-ports 1000 -silent -c 50 -rate 10000 2>/dev/null | anew shodan_ports.txt 2>/dev/null; then
    PORTS_COUNT=$(wc -l < shodan_ports.txt)
    if [ "$PORTS_COUNT" -gt 0 ]; then
        echo -e "${GREEN}[+] Port scan results saved to shodan_ports.txt${NC}"
        echo -e "${GREEN}[+] Found ${PORTS_COUNT} endpoints with open ports${NC}"
        echo ""
        echo -e "${BLUE}Sample endpoints found:${NC}"
        head -10 shodan_ports.txt | sed 's/^/  /'
        if [ "$PORTS_COUNT" -gt 10 ]; then
            echo -e "  ${CYAN}... and $((PORTS_COUNT - 10)) more${NC}"
        fi
    else
        echo -e "${RED}[-] No open ports found${NC}"
        exit 1
    fi
else
    echo -e "${RED}[-] Port scanning failed${NC}"
    exit 1
fi

echo ""

# Step 3: HTTP/HTTPS probing with httpx
echo -e "${YELLOW}[*] Step 3: Probing with httpx (status code, title, tech detection)...${NC}"
echo -e "${YELLOW}[*] Running parallel probes for speed...${NC}"
if httpx -l shodan_ports.txt -silent -sc -title -tech-detect -o shodan_live.txt -threads 100 -timeout 10 2>/dev/null; then
    LIVE_COUNT=$(grep -c "^http" shodan_live.txt 2>/dev/null || echo 0)
    if [ "$LIVE_COUNT" -gt 0 ]; then
        echo -e "${GREEN}[+] HTTPX results saved to shodan_live.txt${NC}"
        echo -e "${GREEN}[+] Found ${LIVE_COUNT} live HTTP/HTTPS services${NC}"
        echo ""
        echo -e "${BLUE}Live services detected:${NC}"
        head -15 shodan_live.txt | sed 's/^/  /'
        if [ "$LIVE_COUNT" -gt 15 ]; then
            echo -e "  ${CYAN}... and $((LIVE_COUNT - 15)) more${NC}"
        fi
    else
        echo -e "${YELLOW}[!] No live HTTP/HTTPS services found${NC}"
    fi
else
    echo -e "${RED}[-] HTTPX probing failed${NC}"
    exit 1
fi

echo ""

# Step 4: Extract and clean URLs
echo -e "${YELLOW}[*] Step 4: Extracting and cleaning results...${NC}"
if grep -E "^https?://" shodan_live.txt 2>/dev/null | cut -d' ' -f1 | sed 's|https\?://||' | cut -d'/' -f1 | sort -u > shodan_final.txt 2>/dev/null; then
    FINAL_COUNT=$(wc -l < shodan_final.txt)
    echo -e "${GREEN}[+] Final results saved to shodan_final.txt${NC}"
    echo -e "${GREEN}[+] Extracted ${FINAL_COUNT} unique host domains/IPs${NC}"
else
    echo -e "${RED}[-] Failed to process results${NC}"
    exit 1
fi

echo ""

# Display comprehensive summary
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}[+] RECONNAISSANCE COMPLETE${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

echo -e "${BLUE}📊 STATISTICS:${NC}"
echo -e "  • Shodan IPs:              ${GREEN}${SHODAN_COUNT}${NC}"
echo -e "  • Open Port Endpoints:     ${GREEN}${PORTS_COUNT}${NC}"
echo -e "  • Live HTTP/HTTPS:         ${GREEN}${LIVE_COUNT}${NC}"
echo -e "  • Unique Hosts:            ${GREEN}${FINAL_COUNT}${NC}"
echo ""

echo -e "${BLUE}📁 FILES GENERATED:${NC}"
echo -e "  • ${CYAN}shodan.txt${NC}           - IP addresses from Shodan (${SHODAN_COUNT} IPs)"
echo -e "  • ${CYAN}shodan_ports.txt${NC}     - Endpoints with open ports (${PORTS_COUNT} endpoints)"
echo -e "  • ${CYAN}shodan_live.txt${NC}      - Live hosts with status/title/tech (${LIVE_COUNT} live)"
echo -e "  • ${CYAN}shodan_final.txt${NC}     - Final unique hosts (${FINAL_COUNT} hosts)"
echo ""

echo -e "${BLUE}📍 DIRECTORY:${NC}"
echo -e "  ${CYAN}${BASE_DIR}${NC}"
echo ""

echo -e "${BLUE}🎯 FINAL RESULTS - UNIQUE HOSTS:${NC}"
echo ""
if [ "$FINAL_COUNT" -gt 0 ]; then
    cat shodan_final.txt | nl -w2 -s'. ' | sed 's/^/  /'
    echo ""
    echo -e "${GREEN}[+] All results saved to: ${CYAN}${BASE_DIR}/shodan_final.txt${NC}"
else
    echo -e "${YELLOW}[!] No final results to display${NC}"
fi

echo ""
echo -e "${CYAN}========================================${NC}"

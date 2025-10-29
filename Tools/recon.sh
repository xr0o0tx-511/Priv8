#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_DIR="$HOME/recon"
WORDLIST_DIR="/opt/wordlists"
MAX_THREADS=50
TIMEOUT=30
VERBOSE=false
CUSTOM_OUTPUT_DIR=""
WORK_DIR=""

# Banner
show_banner() {
    echo -e "${BLUE}"
    echo "██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Advanced Reconnaissance Tool v2.1${NC}"
    echo -e "${CYAN}Subdomain, JavaScript & Parameter Discovery${NC}"
    echo ""
}

# Usage function
usage() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 -d <domain>    # Subdomain enumeration"
    echo "  $0 -j <domain>    # JavaScript analysis and URL extraction"
    echo "  $0 -p <domain>    # Parameter discovery with GAU, ParamSpider & GF"
    echo "  $0 -s <domain>    # Secrets & sensitive data discovery"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -t <threads>      # Number of threads (default: 50)"
    echo "  -o <output_dir>   # Custom output directory"
    echo "  -v                # Verbose output"
    echo "  -h                # Show this help"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 -d example.com"
    echo "  $0 -j example.com -t 30"
    echo "  $0 -p example.com -v"
    echo "  $0 -s example.com -o /tmp/recon"
    exit 1
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    [[ "$VERBOSE" == "true" ]] && echo -e "${PURPLE}[VERBOSE]${NC} $1"
}

# Check if tools are installed
check_tools() {
    local required_tools=("curl" "jq" "sort" "uniq" "grep" "sed" "awk")
    local recon_tools=("subfinder" "httpx" "assetfinder" "amass" "gospider" "gau" "paramspider" "gf")
    local missing_tools=()
    
    log_info "Checking required tools..."
    
    # Check basic tools
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check recon tools (warn but don't exit)
    local missing_recon_tools=()
    for tool in "${recon_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_recon_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Install missing tools and try again"
        exit 1
    fi
    
    if [ ${#missing_recon_tools[@]} -ne 0 ]; then
        log_warning "Missing optional tools: ${missing_recon_tools[*]}"
        log_warning "Some features may be limited"
    fi
    
    log_success "Tool check completed!"
}

# Setup working directory
setup_workdir() {
    local domain=$1
    local custom_dir=$2
    
    if [[ -n "$custom_dir" ]]; then
        WORK_DIR="$custom_dir/$domain"
    else
        WORK_DIR="$RECON_DIR/$domain"
    fi
    
    mkdir -p "$WORK_DIR"/{subdomains,javascript,secrets,parameters}
    cd "$WORK_DIR" || exit 1
    
    log_info "Working directory: $WORK_DIR"
    
    # Create session log
    echo "=== RECON SESSION ===" > session.log
    echo "Domain: $domain" >> session.log
    echo "Start Time: $(date)" >> session.log
    echo "Working Directory: $WORK_DIR" >> session.log
    echo "===================" >> session.log
}

# Subdomain enumeration function
subdomain_enum() {
    local domain=$1
    
    log_info "Starting comprehensive subdomain enumeration for $domain"
    
    cd "$WORK_DIR/subdomains" || exit 1
    
    # Phase 1: Passive enumeration
    log_info "Phase 1: Passive subdomain discovery"
    
    # Subfinder
    if command -v subfinder &> /dev/null; then
        log_verbose "Running subfinder..."
        subfinder -d "$domain" -all -silent -o subfinder.txt 2>/dev/null &
    fi
    
    # Certificate transparency
    log_verbose "Checking certificate transparency logs..."
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\*\.//g' | sort -u > crt.txt &
    
    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        log_verbose "Running assetfinder..."
        assetfinder --subs-only "$domain" > assetfinder.txt 2>/dev/null &
    fi
    
    wait
    
    # Combine passive results
    cat subfinder.txt crt.txt assetfinder.txt 2>/dev/null | \
        sort -u | grep -E "^[a-zA-Z0-9.-]+\.$domain$" > passive_subs.txt
    
    log_info "Passive discovery found: $(wc -l < passive_subs.txt) subdomains"
    
    # Phase 2: Active enumeration with httpx
    log_info "Phase 2: Active subdomain validation with httpx"
    
    if command -v httpx &> /dev/null; then
        httpx -l passive_subs.txt -silent -sc -title -tech-detect -threads "$MAX_THREADS" \
            -timeout "$TIMEOUT" -o live_results.txt 2>/dev/null
        
        grep -E "^https?://" live_results.txt | cut -d' ' -f1 | \
            sed 's|https\?://||' | cut -d'/' -f1 | sort -u > live_subs.txt
    else
        cp passive_subs.txt live_subs.txt
    fi
    
    log_info "Live subdomains after httpx: $(wc -l < live_subs.txt)"
    
    # Phase 3: Deep enumeration with Amass
    if command -v amass &> /dev/null; then
        log_info "Phase 3: Deep enumeration with Amass"
        timeout 600 amass enum -passive -d "$domain" -o amass_subs.txt 2>/dev/null || true
        
        if [[ -f amass_subs.txt ]]; then
            local amass_count=$(wc -l < amass_subs.txt)
            log_info "Amass discovered: $amass_count subdomains"
            
            # Run httpx on amass results
            log_info "Running httpx on amass results..."
            if command -v httpx &> /dev/null; then
                httpx -l amass_subs.txt -silent -sc -title -tech-detect -threads "$MAX_THREADS" \
                    -timeout "$TIMEOUT" -o amass_live_results.txt 2>/dev/null
                
                grep -E "^https?://" amass_live_results.txt | cut -d' ' -f1 | \
                    sed 's|https\?://||' | cut -d'/' -f1 | sort -u > amass_live_subs.txt
                
                log_info "Live subdomains from amass: $(wc -l < amass_live_subs.txt)"
                
                # Merge with existing live_subs and remove duplicates
                cat live_subs.txt amass_live_subs.txt | sort -u > final_subs.txt
            else
                # If httpx not available, just merge amass results
                cat live_subs.txt amass_subs.txt | sort -u > final_subs.txt
            fi
        else
            cp live_subs.txt final_subs.txt
        fi
    else
        cp live_subs.txt final_subs.txt
    fi
    
    # Create summary
    local total_subs=$(wc -l < final_subs.txt)
    local live_count=$(wc -l < final_subs.txt)
    
    log_success "Subdomain enumeration complete!"
    log_success "Total unique live subdomains: $total_subs"
    
    # Save detailed summary
    {
        echo "=== SUBDOMAIN ENUMERATION SUMMARY ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo "Passive subdomains found: $(wc -l < passive_subs.txt)"
        echo "Live subdomains (initial): $(wc -l < live_subs.txt 2>/dev/null || echo 0)"
        echo "Amass subdomains found: $(wc -l < amass_subs.txt 2>/dev/null || echo 0)"
        echo "Live subdomains (amass): $(wc -l < amass_live_subs.txt 2>/dev/null || echo 0)"
        echo "Total unique live subdomains: $total_subs"
        echo "======================================"
        echo ""
        echo "=== FINAL SUBDOMAIN LIST ==="
        cat final_subs.txt
    } > summary.txt
    
    cd "$WORK_DIR" || exit 1
}

# Advanced JavaScript analysis function (like Burp Suite JS Miner)
js_analysis() {
    local domain=$1
    
    log_info "Starting Advanced JavaScript Mining for $domain"
    log_info "Analyzing JS like Burp Suite JS Miner..."
    
    cd "$WORK_DIR/javascript" || exit 1
    
    # Create organized subdirectories
    mkdir -p {downloads,analysis,credentials,subdomains,endpoints,secrets,comments,variables}
    
    # Check if we have subdomains
    if [[ ! -f "../subdomains/final_subs.txt" ]]; then
        log_warning "No live subdomains found. Running quick subdomain scan..."
        if command -v subfinder &> /dev/null && command -v httpx &> /dev/null; then
            subfinder -d "$domain" -silent | httpx -silent > temp_subs.txt
            SUBS_FILE="temp_subs.txt"
        else
            echo "https://$domain" > temp_subs.txt
            SUBS_FILE="temp_subs.txt"
        fi
    else
        sed 's|^|https://|' "../subdomains/final_subs.txt" > temp_subs.txt
        SUBS_FILE="temp_subs.txt"
    fi
    
    # Phase 1: Comprehensive JavaScript Discovery
    log_info "Phase 1: Deep JavaScript File Discovery"
    
    if command -v gospider &> /dev/null; then
        log_verbose "Using gospider for deep crawling..."
        cat "$SUBS_FILE" | gospider -c 10 -d 3 --js -q --timeout "$TIMEOUT" \
            --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg 2>/dev/null | \
            grep -E "\.js(\?|$)" | sort -u > js_files.txt
    else
        log_verbose "Using alternative JS discovery..."
        while read -r url; do
            curl -s --max-time "$TIMEOUT" "$url" 2>/dev/null | \
                grep -oP 'src=["\047]\K[^"\047]*\.js[^"\047]*' | \
                sed "s|^//|https://|" | sed "s|^/|$url/|"
        done < "$SUBS_FILE" | sort -u > js_files.txt
    fi
    
    # Also extract inline JavaScript
    log_verbose "Extracting inline JavaScript..."
    while read -r url; do
        curl -s --max-time "$TIMEOUT" "$url" 2>/dev/null | \
            grep -oP '<script[^>]*>(.*?)</script>' || true
    done < "$SUBS_FILE" > inline_js.txt
    
    local js_count=$(wc -l < js_files.txt)
    log_info "JavaScript files discovered: $js_count"
    
    if [[ $js_count -eq 0 ]]; then
        log_warning "No JavaScript files found"
        return
    fi
    
    # Phase 2: Download and Beautify JavaScript
    log_info "Phase 2: Downloading and Processing JavaScript Files"
    
    head -200 js_files.txt | while read -r js_url; do
        if [[ -n "$js_url" ]]; then
            filename=$(basename "$js_url" | cut -d'?' -f1)
            [[ -z "$filename" || "$filename" == "/" ]] && filename="$(echo "$js_url" | md5sum | cut -d' ' -f1).js"
            
            log_verbose "Downloading: $js_url"
            curl -s --max-time "$TIMEOUT" "$js_url" -o "downloads/${filename}" 2>/dev/null || true
            
            # Store source URL mapping
            echo "$js_url|downloads/${filename}" >> js_file_mapping.txt
        fi
    done
    
    # Phase 3: Extract All Subdomains (Enhanced)
    log_info "Phase 3: Mining Subdomains from JavaScript"
    
    {
        find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
            [[ -f "$file" ]] || continue
            
            # Method 1: Standard subdomain pattern
            grep -oP '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.'"${domain//./\\.}" "$file" 2>/dev/null || true
            
            # Method 2: From URLs
            grep -oP 'https?://[a-zA-Z0-9\-\.]+\.'"${domain//./\\.}" "$file" 2>/dev/null | \
                sed 's|https\?://||' | cut -d'/' -f1 || true
            
            # Method 3: From strings and variables
            grep -oP '["\047]([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.'"${domain//./\\.}"'["\047]' "$file" 2>/dev/null | \
                tr -d '"' | tr -d "'" || true
        done
    } | sort -u | grep -v "^$" | grep -v '\*' > subdomains/all_subdomains_raw.txt
    
    # Clean and validate subdomains
    grep -E "^[a-zA-Z0-9.-]+\.$domain$" subdomains/all_subdomains_raw.txt > subdomains/all_subdomains_clean.txt 2>/dev/null || true
    
    # Validate live subdomains
    if [[ -s subdomains/all_subdomains_clean.txt ]] && command -v httpx &> /dev/null; then
        log_info "Validating discovered subdomains..."
        httpx -l subdomains/all_subdomains_clean.txt -silent -threads "$MAX_THREADS" \
            -title -tech-detect -sc -cl > subdomains/live_subdomains.txt 2>/dev/null
        
        grep -oP '^https?://\K[^/\s]+' subdomains/live_subdomains.txt | sort -u > subdomains/live_hosts.txt
        local live_count=$(wc -l < subdomains/live_hosts.txt)
        log_success "Live subdomains from JS: $live_count"
    fi
    
    # Phase 4: Extract Credentials and Secrets (Enhanced) - FIXED
    log_info "Phase 4: Mining Credentials and Secrets"
    
    find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
        [[ -f "$file" ]] || continue
        filename=$(basename "$file")
        
        {
            echo "=========================================="
            echo "File: $filename"
            echo "Source: $(grep "$filename" js_file_mapping.txt | cut -d'|' -f1)"
            echo "=========================================="
            echo ""
            
            # API Keys (Enhanced patterns)
            echo "=== API KEYS ==="
            grep -iEo '(api[_-]?key|apikey|api_key_id)["\047\s:=]+["\047]?[a-zA-Z0-9_\-]{20,}' "$file" 2>/dev/null | head -20 || true
            grep -iEo 'key["\047\s:=]+["\047][a-zA-Z0-9_\-]{32,}["\047]' "$file" 2>/dev/null | head -20 || true
            echo ""
            
            # AWS Keys
            echo "=== AWS CREDENTIALS ==="
            grep -Eo '(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}' "$file" 2>/dev/null || true
            grep -iEo 'aws[_-]?secret[_-]?access[_-]?key["\047\s:=]+["\047]?[a-zA-Z0-9/+=]{40}' "$file" 2>/dev/null || true
            echo ""
            
            # Google API Keys
            echo "=== GOOGLE API KEYS ==="
            grep -Eo 'AIza[0-9A-Za-z\-_]{35}' "$file" 2>/dev/null || true
            echo ""
            
            # GitHub Tokens
            echo "=== GITHUB TOKENS ==="
            grep -Eo 'ghp_[a-zA-Z0-9]{36}' "$file" 2>/dev/null || true
            grep -Eo 'gho_[a-zA-Z0-9]{36}' "$file" 2>/dev/null || true
            grep -Eo 'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}' "$file" 2>/dev/null || true
            echo ""
            
            # Slack Tokens
            echo "=== SLACK TOKENS ==="
            grep -Eo 'xox[baprs]-[0-9a-zA-Z\-]{10,}' "$file" 2>/dev/null || true
            echo ""
            
            # Generic Secrets and Tokens
            echo "=== SECRETS & TOKENS ==="
            grep -iEo '(secret|token|password|passwd|pwd)["\047\s:=]+["\047]?[a-zA-Z0-9_\-!@#$%^&*]{10,}' "$file" 2>/dev/null | head -30 || true
            echo ""
            
            # Authentication Headers
            echo "=== AUTH HEADERS ==="
            grep -iEo 'authorization["\047\s:=]+["\047]?(Bearer |Basic )?[a-zA-Z0-9_\-\.=+/]{20,}' "$file" 2>/dev/null | head -20 || true
            grep -iEo 'x-api-key["\047\s:=]+["\047]?[a-zA-Z0-9_\-]{20,}' "$file" 2>/dev/null | head -20 || true
            echo ""
            
            # Database Credentials
            echo "=== DATABASE CREDENTIALS ==="
            grep -iEo '(mysql|postgres|mongodb|redis|oracle)://[^"\047\s<>]+' "$file" 2>/dev/null || true
            grep -iEo 'jdbc:[^"\047\s<>]+' "$file" 2>/dev/null || true
            grep -iEo 'mongodb\+srv://[^"\047\s<>]+' "$file" 2>/dev/null || true
            echo ""
            
            # Firebase URLs
            echo "=== FIREBASE ==="
            grep -Eo '[a-zA-Z0-9\-]+\.firebaseio\.com' "$file" 2>/dev/null || true
            grep -Eo '[a-zA-Z0-9\-]+\.firebaseapp\.com' "$file" 2>/dev/null || true
            echo ""
            
            # Private Keys
            echo "=== PRIVATE KEYS ==="
            grep -i 'BEGIN.*PRIVATE KEY' "$file" 2>/dev/null || true
            grep -i 'BEGIN RSA PRIVATE KEY' "$file" 2>/dev/null || true
            echo ""
            
            # Email addresses
            echo "=== EMAIL ADDRESSES ==="
            grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$file" 2>/dev/null | sort -u | head -20 || true
            echo ""
            
            # IP Addresses (Internal)
            echo "=== INTERNAL IPS ==="
            grep -Eo '(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}' "$file" 2>/dev/null | sort -u || true
            echo ""
            
            echo ""
        } > "credentials/${filename%.js}_secrets.txt"
    done
    
    # Consolidate all secrets
    cat credentials/*_secrets.txt > credentials/ALL_SECRETS.txt 2>/dev/null || true
    log_success "Secrets analysis saved to credentials/"
    
    # Phase 5: Extract All Endpoints and URLs
    log_info "Phase 5: Mining Endpoints and URLs"
    
    {
        find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
            [[ -f "$file" ]] || continue
            
            # Full URLs
            grep -oE 'https?://[a-zA-Z0-9./?=_\-&%#]+' "$file" 2>/dev/null || true
            
            # API endpoints
            grep -oE '["'\''`]/api/[a-zA-Z0-9/_\-{}:]+["'\''`]' "$file" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '`' || true
            grep -oE '["'\''`]/v[0-9]+/[a-zA-Z0-9/_\-{}:]+["'\''`]' "$file" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '`' || true
            
            # Relative paths
            grep -oE '["'\''`]/[a-zA-Z0-9/_\-{}:]+\.(php|asp|aspx|jsp|json|xml|do|action)["'\''`]' "$file" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '`' || true
            
            # GraphQL endpoints
            grep -oE '["'\''`]/graphql[a-zA-Z0-9/_\-]*["'\''`]' "$file" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '`' || true
            
            # REST endpoints
            grep -oE '["'\''`]/(rest|api|service|ws)[a-zA-Z0-9/_\-{}:]*["'\''`]' "$file" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '`' || true
        done
    } | sort -u > endpoints/all_endpoints.txt
    
    # Categorize endpoints
    grep -i 'api' endpoints/all_endpoints.txt > endpoints/api_endpoints.txt 2>/dev/null || true
    grep -i 'admin' endpoints/all_endpoints.txt > endpoints/admin_endpoints.txt 2>/dev/null || true
    grep -i 'graphql' endpoints/all_endpoints.txt > endpoints/graphql_endpoints.txt 2>/dev/null || true
    grep -E '\.(php|asp|aspx|jsp)' endpoints/all_endpoints.txt > endpoints/backend_endpoints.txt 2>/dev/null || true
    
    log_success "Endpoints extracted: $(wc -l < endpoints/all_endpoints.txt)"
    
    # Phase 6: Extract Comments and Documentation
    log_info "Phase 6: Mining Comments and Documentation"
    
    find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
        [[ -f "$file" ]] || continue
        filename=$(basename "$file")
        
        {
            echo "=== File: $filename ==="
            echo ""
            
            # Single line comments
            grep -oP '//.*' "$file" 2>/dev/null || true
            
            # Multi-line comments
            sed -n '/\/\*/,/\*\//p' "$file" 2>/dev/null || true
            
            echo ""
        } >> comments/all_comments.txt
    done
    
    # Phase 7: Extract Variable and Function Names
    log_info "Phase 7: Mining Variables and Functions"
    
    {
        find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
            [[ -f "$file" ]] || continue
            
            # Function declarations
            grep -oP 'function\s+\K[a-zA-Z_$][a-zA-Z0-9_$]*' "$file" 2>/dev/null || true
            
            # Variable declarations
            grep -oP '(var|let|const)\s+\K[a-zA-Z_$][a-zA-Z0-9_$]*' "$file" 2>/dev/null || true
            
            # Object properties with sensitive names
            grep -oP '["\047]?(api|key|token|secret|password|credential|auth)[a-zA-Z0-9_]*["\047]?\s*:' "$file" 2>/dev/null | \
                sed 's/["\047:]//g' || true
        done
    } | sort | uniq -c | sort -rn > variables/interesting_variables.txt
    
    # Phase 8: Extract Configuration Objects
    log_info "Phase 8: Mining Configuration Objects"
    
    {
        find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
            [[ -f "$file" ]] || continue
            
            # Look for config objects
            grep -A 10 -iE '(config|settings|options)\s*=\s*\{' "$file" 2>/dev/null || true
            
            # Environment variables
            grep -oP 'process\.env\.[A-Z_]+' "$file" 2>/dev/null || true
            
        done
    } > analysis/configurations.txt
    
    # Phase 9: Extract S3 Buckets and Cloud Storage
    log_info "Phase 9: Mining Cloud Storage References"
    
    {
        find downloads/ -name "*.js" -type f 2>/dev/null | while read -r file; do
            [[ -f "$file" ]] || continue
            
            # S3 buckets
            grep -Eo '[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com' "$file" 2>/dev/null || true
            grep -Eo 's3://[a-zA-Z0-9.\-/]+' "$file" 2>/dev/null || true
            grep -Eo 's3-[a-z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9.\-]+' "$file" 2>/dev/null || true
            
            # Google Cloud Storage
            grep -Eo '[a-zA-Z0-9.\-]+\.storage\.googleapis\.com' "$file" 2>/dev/null || true
            grep -Eo 'gs://[a-zA-Z0-9.\-/]+' "$file" 2>/dev/null || true
            
            # Azure Storage
            grep -Eo '[a-zA-Z0-9]+\.blob\.core\.windows\.net' "$file" 2>/dev/null || true
            
        done
    } | sort -u > secrets/cloud_storage.txt
    
    log_success "Cloud storage references: $(wc -l < secrets/cloud_storage.txt)"
    
    # Phase 10: Generate Comprehensive Report
    log_info "Phase 10: Generating Comprehensive Report"
    
    {
        echo "=========================================="
        echo "   JAVASCRIPT MINING REPORT"
        echo "   (Burp Suite JS Miner Style)"
        echo "=========================================="
        echo "Domain: $domain"
        echo "Analysis Date: $(date)"
        echo "=========================================="
        echo ""
        
        echo "=== DISCOVERY SUMMARY ==="
        echo "JavaScript files found: $(wc -l < js_files.txt)"
        echo "JavaScript files analyzed: $(find downloads/ -name "*.js" 2>/dev/null | wc -l)"
        echo "Inline JavaScript blocks: $(wc -l < inline_js.txt 2>/dev/null || echo 0)"
        echo ""
        
        echo "=== SUBDOMAINS ==="
        echo "Total subdomains discovered: $(wc -l < subdomains/all_subdomains_clean.txt 2>/dev/null || echo 0)"
        echo "Live subdomains verified: $(wc -l < subdomains/live_hosts.txt 2>/dev/null || echo 0)"
        echo "Top 10 subdomains:"
        head -10 subdomains/live_hosts.txt 2>/dev/null || echo "None"
        echo ""
        
        echo "=== CREDENTIALS & SECRETS ==="
        echo "Secret files analyzed: $(ls -1 credentials/*_secrets.txt 2>/dev/null | wc -l)"
        echo "Potential API keys found: $(grep -c 'API KEYS' credentials/ALL_SECRETS.txt 2>/dev/null || echo 0)"
        echo "AWS credentials found: $(grep -c 'AWS CREDENTIALS' credentials/ALL_SECRETS.txt 2>/dev/null || echo 0)"
        echo "Tokens found: $(grep -c 'TOKENS' credentials/ALL_SECRETS.txt 2>/dev/null || echo 0)"
        echo ""
        
        echo "=== ENDPOINTS ==="
        echo "Total endpoints: $(wc -l < endpoints/all_endpoints.txt 2>/dev/null || echo 0)"
        echo "API endpoints: $(wc -l < endpoints/api_endpoints.txt 2>/dev/null || echo 0)"
        echo "Admin endpoints: $(wc -l < endpoints/admin_endpoints.txt 2>/dev/null || echo 0)"
        echo "GraphQL endpoints: $(wc -l < endpoints/graphql_endpoints.txt 2>/dev/null || echo 0)"
        echo "Backend endpoints: $(wc -l < endpoints/backend_endpoints.txt 2>/dev/null || echo 0)"
        echo ""
        
        echo "=== CLOUD STORAGE ==="
        echo "S3 buckets found: $(grep -c 's3' secrets/cloud_storage.txt 2>/dev/null || echo 0)"
        echo "Google Storage found: $(grep -c 'googleapis' secrets/cloud_storage.txt 2>/dev/null || echo 0)"
        echo "Azure Storage found: $(grep -c 'azure' secrets/cloud_storage.txt 2>/dev/null || echo 0)"
        echo ""
        
        echo "=== ANALYSIS FILES ==="
        echo "📁 subdomains/live_hosts.txt - Verified live subdomains"
        echo "📁 credentials/ALL_SECRETS.txt - All discovered secrets"
        echo "📁 endpoints/all_endpoints.txt - All extracted endpoints"
        echo "📁 endpoints/api_endpoints.txt - API-specific endpoints"
        echo "📁 endpoints/admin_endpoints.txt - Admin panel endpoints"
        echo "📁 secrets/cloud_storage.txt - Cloud storage URLs"
        echo "📁 comments/all_comments.txt - Code comments"
        echo "📁 variables/interesting_variables.txt - Sensitive variables"
        echo "📁 analysis/configurations.txt - Configuration objects"
        echo ""
        
        echo "=========================================="
        echo "          CRITICAL FINDINGS"
        echo "=========================================="
        
        # Highlight critical findings
        if [[ -f credentials/ALL_SECRETS.txt ]]; then
            echo ""
            echo "🔴 POTENTIAL CREDENTIALS FOUND:"
            grep -i 'password\|secret\|token' credentials/ALL_SECRETS.txt 2>/dev/null | head -20 || echo "None"
        fi
        
        echo ""
        echo "=========================================="
        
    } > JAVASCRIPT_MINING_REPORT.txt
    
    log_success "JavaScript Mining Complete!"
    log_success "Report saved: $WORK_DIR/javascript/JAVASCRIPT_MINING_REPORT.txt"
    
    # Display quick summary
    echo ""
    echo -e "${CYAN}=== QUICK RESULTS ===${NC}"
    echo -e "${GREEN}✓ Subdomains:${NC} $(wc -l < subdomains/live_hosts.txt 2>/dev/null || echo 0) live"
    echo -e "${GREEN}✓ Endpoints:${NC} $(wc -l < endpoints/all_endpoints.txt 2>/dev/null || echo 0) discovered"
    echo -e "${GREEN}✓ Secrets:${NC} Check credentials/ALL_SECRETS.txt"
    echo -e "${GREEN}✓ Full Report:${NC} JAVASCRIPT_MINING_REPORT.txt"
    echo ""
    
    cd "$WORK_DIR" || exit 1
}

# Parameter discovery function
parameter_discovery() {
    local domain=$1
    
    log_info "Starting parameter discovery for $domain"
    
    cd "$WORK_DIR/parameters" || exit 1
    
    # Check if we have subdomains
    if [[ -f "../subdomains/final_subs.txt" ]]; then
        cp "../subdomains/final_subs.txt" subdomains.txt
    else
        echo "$domain" > subdomains.txt
    fi
    
    # Phase 1: URL collection with GAU (GetAllUrls)
    log_info "Phase 1: Collecting URLs with GAU"
    
    if command -v gau &> /dev/null; then
        log_verbose "Running GAU for URL collection..."
        
        # Use GAU to collect URLs from multiple sources
        cat subdomains.txt | while read -r subdomain; do
            log_verbose "GAU scanning: $subdomain"
            echo "$subdomain" | gau --threads "$MAX_THREADS" --timeout "$TIMEOUT" 2>/dev/null
        done | tee gau_urls.txt | wc -l | xargs -I {} log_info "GAU collected: {} URLs"
        
        # Remove duplicates and filter
        sort -u gau_urls.txt | grep -E '\?' > gau_urls_with_params.txt
        log_info "URLs with parameters from GAU: $(wc -l < gau_urls_with_params.txt)"
    else
        log_warning "GAU not found, skipping URL collection"
        touch gau_urls.txt gau_urls_with_params.txt
    fi
    
    # Phase 2: Parameter discovery with ParamSpider
    log_info "Phase 2: Parameter discovery with ParamSpider"
    
    if command -v paramspider &> /dev/null; then
        log_verbose "Running ParamSpider..."
        
        cat subdomains.txt | head -10 | while read -r subdomain; do
            log_verbose "ParamSpider scanning: $subdomain"
            timeout 600 paramspider -d "$subdomain" --level high --quiet 2>/dev/null || true
        done
        
        # Collect ParamSpider results
        find . -name "*$domain*.txt" -path "*/output/*" 2>/dev/null | while read -r file; do
            [[ -f "$file" ]] && cat "$file" >> paramspider_raw.txt
        done 2>/dev/null || true
        
        # Clean and deduplicate ParamSpider results
        if [[ -f paramspider_raw.txt ]]; then
            grep -E 'https?://.*\?' paramspider_raw.txt | sort -u > paramspider_urls.txt
            log_info "ParamSpider found: $(wc -l < paramspider_urls.txt) URLs with parameters"
        else
            touch paramspider_urls.txt
            log_warning "No ParamSpider results found"
        fi
    else
        log_warning "ParamSpider not found, skipping parameter spider"
        touch paramspider_urls.txt
    fi
    
    # Phase 3: Combine and process all URLs
    log_info "Phase 3: Combining and processing URLs"
    
    # Combine all URL sources
    cat gau_urls_with_params.txt paramspider_urls.txt 2>/dev/null | sort -u > all_urls_with_params.txt
    
    local total_param_urls=$(wc -l < all_urls_with_params.txt)
    log_info "Total URLs with parameters: $total_param_urls"
    
    # Extract parameters from URLs
    if [[ $total_param_urls -gt 0 ]]; then
        # Extract parameter names
        grep -oP '\?[^&\s]*|&[^&\s]*' all_urls_with_params.txt | \
            sed 's/[?&]//g' | cut -d'=' -f1 | sort -u > parameter_names.txt
        
        # Extract parameter values (for analysis)
        grep -oP '\?[^&\s]*|&[^&\s]*' all_urls_with_params.txt | \
            sed 's/[?&]//g' | sort -u > parameter_pairs.txt
        
        log_success "Unique parameters found: $(wc -l < parameter_names.txt)"
    fi
    
    # Phase 4: GF pattern matching
    log_info "Phase 4: Pattern matching with GF"
    
    if command -v gf &> /dev/null && [[ -f all_urls_with_params.txt ]]; then
        log_verbose "Running GF pattern matching..."
        
        # Common GF patterns for parameter discovery
        local gf_patterns=("xss" "sqli" "ssrf" "lfi" "rce" "redirect" "idor" "debug")
        
        for pattern in "${gf_patterns[@]}"; do
            if gf -list | grep -q "^$pattern$" 2>/dev/null; then
                log_verbose "Applying GF pattern: $pattern"
                cat all_urls_with_params.txt | gf "$pattern" > "gf_${pattern}.txt" 2>/dev/null || true
                
                if [[ -s "gf_${pattern}.txt" ]]; then
                    log_success "GF $pattern: $(wc -l < gf_${pattern}.txt) potential vulnerabilities"
                fi
            fi
        done
        
        # Combine all GF results
        cat gf_*.txt 2>/dev/null | sort -u > gf_all_patterns.txt
        log_info "Total GF pattern matches: $(wc -l < gf_all_patterns.txt 2>/dev/null || echo 0)"
    else
        log_warning "GF not found or no URLs to process"
        touch gf_all_patterns.txt
    fi
    
    # Create summary
    {
        echo "=== PARAMETER DISCOVERY SUMMARY ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo "Total subdomains processed: $(wc -l < subdomains.txt)"
        echo "URLs collected by GAU: $(wc -l < gau_urls.txt 2>/dev/null || echo 0)"
        echo "URLs with parameters (GAU): $(wc -l < gau_urls_with_params.txt 2>/dev/null || echo 0)"
        echo "URLs with parameters (ParamSpider): $(wc -l < paramspider_urls.txt 2>/dev/null || echo 0)"
        echo "Total unique URLs with parameters: $(wc -l < all_urls_with_params.txt 2>/dev/null || echo 0)"
        echo "Unique parameter names: $(wc -l < parameter_names.txt 2>/dev/null || echo 0)"
        echo "GF pattern matches: $(wc -l < gf_all_patterns.txt 2>/dev/null || echo 0)"
        echo "==================================="
    } > summary.txt
    
    log_success "Parameter discovery complete!"
    
    cd "$WORK_DIR" || exit 1
}

# Secrets and sensitive data discovery
secrets_discovery() {
    local domain=$1
    
    log_info "Starting secrets and sensitive data discovery for $domain"
    
    cd "$WORK_DIR/secrets" || exit 1
    
    # Phase 1: GitHub/GitLab search (requires API keys)
    log_info "Phase 1: Repository search (requires API configuration)"
    
    # Phase 2: S3 bucket enumeration
    log_info "Phase 2: S3 bucket enumeration"
    
    # Common S3 bucket naming patterns
    {
        echo "$domain"
        echo "${domain/./-}"
        echo "${domain/./_}"
        echo "www-$domain"
        echo "dev-$domain"
        echo "test-$domain"
        echo "staging-$domain"
        echo "prod-$domain"
        echo "backup-$domain"
        echo "assets-$domain"
        echo "static-$domain"
        echo "files-$domain"
        echo "uploads-$domain"
        echo "downloads-$domain"
    } > s3_candidates.txt
    
    log_verbose "Testing S3 bucket candidates..."
    while read -r bucket; do
        if curl -s --max-time 10 "https://${bucket}.s3.amazonaws.com/" 2>/dev/null | grep -q "ListBucketResult\|AccessDenied"; then
            echo "$bucket" >> s3_buckets_found.txt
            log_success "S3 bucket found: $bucket"
        fi
    done < s3_candidates.txt
    
    # Phase 3: Sensitive file discovery
    log_info "Phase 3: Sensitive file discovery"
    
    if [[ -f "../subdomains/final_subs.txt" ]]; then
        # Common sensitive files
        local sensitive_files=(
            "/.env"
            "/.git/config"
            "/config.json"
            "/config.php"
            "/wp-config.php"
            "/database.yml"
            "/.htaccess"
            "/robots.txt"
            "/sitemap.xml"
            "/crossdomain.xml"
            "/.well-known/security.txt"
            "/backup.sql"
            "/dump.sql"
            "/.DS_Store"
        )
        
        while read -r url; do
            for file in "${sensitive_files[@]}"; do
                full_url="https://${url}${file}"
                response=$(curl -s -w "%{http_code}" --max-time 10 "$full_url" 2>/dev/null)
                http_code="${response: -3}"
                
                if [[ "$http_code" == "200" ]]; then
                    echo "$full_url" >> sensitive_files_found.txt
                    log_success "Sensitive file found: $full_url"
                fi
            done
        done < "../subdomains/final_subs.txt"
    fi
    
    # Create summary
    {
        echo "=== SECRETS DISCOVERY SUMMARY ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo "S3 buckets found: $(wc -l < s3_buckets_found.txt 2>/dev/null || echo 0)"
        echo "Sensitive files found: $(wc -l < sensitive_files_found.txt 2>/dev/null || echo 0)"
        echo "================================"
    } > summary.txt
    
    log_success "Secrets discovery complete!"
    
    cd "$WORK_DIR" || exit 1
}

# Extract domain from arguments
extract_domain() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|-o)
                shift 2
                ;;
            -v|-h)
                shift
                ;;
            -d|-j|-p|-s)
                if [[ -n "$2" && "$2" != -* ]]; then
                    echo "$2"
                    return
                fi
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
}

# Main script logic
if [ $# -eq 0 ]; then
    usage
fi

# Show banner
show_banner

# Parse initial options for verbose and output directory
while getopts "t:o:vh" opt; do
    case $opt in
        t)
            MAX_THREADS=$OPTARG
            ;;
        o)
            CUSTOM_OUTPUT_DIR=$OPTARG
            ;;
        v)
            VERBOSE=true
            ;;
        h)
            usage
            ;;
    esac
done

# Check tools first
check_tools

# Extract domain from arguments
DOMAIN=$(extract_domain "$@")

# Setup working directory if we have a domain
if [[ -n "$DOMAIN" ]]; then
    setup_workdir "$DOMAIN" "$CUSTOM_OUTPUT_DIR"
else
    log_error "No domain specified"
    usage
fi

# Reset getopts for main parsing
OPTIND=1

# Parse and execute main command
while getopts "d:j:p:s:t:o:vh" opt; do
    case $opt in
        d)
            subdomain_enum "$OPTARG"
            ;;
        j)
            js_analysis "$OPTARG"
            ;;
        p)
            parameter_discovery "$OPTARG"
            ;;
        s)
            secrets_discovery "$OPTARG"
            ;;
        t|o|v|h)
            # Already handled above
            ;;
        \?)
            log_error "Invalid option: -$OPTARG"
            usage
            ;;
    esac
done

# Final completion message
echo ""
log_success "RECON script execution completed!"
echo -e "${YELLOW}Results saved in: ${WORK_DIR:-$RECON_DIR}${NC}"
echo ""

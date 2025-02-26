#!/bin/bash
# Enhanced Automated Recon Script - Ethical Hacking
# Features: Subdomain Enumeration, Takeover Checks, Port Scanning, Security Headers Analysis, DNS & WHOIS Lookup, Screenshot Capture

# Install dependencies if not present
install_tools() {
    echo "[+] Checking for required tools..."
    local tools=("subfinder" "amass" "nmap" "nuclei" "curl" "jq" "whois" "gowitness")
    local go_tools=("github.com/haccer/subjack" "github.com/projectdiscovery/naabu/v2/cmd/naabu" "github.com/tomnomnom/httprobe")

    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo "[+] Installing $tool..."
            sudo apt install -y $tool
        else
            echo "[+] $tool is already installed."
        fi
    done

    for go_tool in "${go_tools[@]}"; do
        if ! go list -m $go_tool &> /dev/null; then
            echo "[+] Installing $go_tool..."
            go install $go_tool@latest
        else
            echo "[+] $go_tool is already installed."
        fi
    done

    export PATH=$HOME/go/bin:$PATH
}

# Subdomain Enumeration
enumerate_subdomains() {
    local domain=$1
    if [ -f subdomains.txt ]; then
        echo "[+] subdomains.txt already exists, skipping enumeration."
        return
    fi
    echo "[+] Enumerating subdomains for the domain: $domain..."
    subfinder -d $domain -o subdomains.txt
    amass enum -passive -d $domain >> subdomains.txt
    sort -u subdomains.txt -o subdomains.txt
}


# Subdomain Takeover Check
check_takeover() {
    if [ -f takeover_results.txt ]; then
        echo "[+] takeover_results.txt already exists, skipping takeover check."
        return
    fi
    echo "[+] Checking for potential subdomain takeovers..."
    subjack -w subdomains.txt -o takeover_results.txt -ssl -v
}


# Port Scanning
scan_ports() {
    if [ -f open_ports.txt ] && [ -f nmap_results.txt ]; then
        echo "[+] open_ports.txt and nmap_results.txt already exist, skipping port scanning."
        return
    fi
    echo "[+] Scanning open ports on live subdomains..."
    naabu -list subdomains.txt -o open_ports.txt
    nmap -iL open_ports.txt -Pn -A -oN nmap_results.txt
}


# Security Headers Analysis
check_security_headers() {
    if [ ! -f subdomains.txt ]; then
        echo "[+] subdomains.txt does not exist, skipping security headers analysis."
        return
    fi
    echo "[+] Analyzing security headers..."
    for url in $(cat subdomains.txt); do
        echo "Checking $url"
        curl -I --silent https://$url | grep -E "Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Content-Security-Policy"
    done
}


# DNS and WHOIS Lookup
perform_dns_whois() {
    if [ ! -f subdomains.txt ]; then
        echo "[+] subdomains.txt does not exist, skipping DNS and WHOIS lookups."
        return
    fi
    echo "[+] Executing DNS and WHOIS lookups..."
    while read subdomain; do
        echo "[+] DNS Records for $subdomain"
        dig $subdomain ANY +short
        echo "[+] WHOIS Lookup for $subdomain"
        whois $subdomain | head -20
    done < subdomains.txt
}


# Screenshot Capture
capture_screenshots() {
    if [ ! -d screenshots/ ]; then
        echo "[+] screenshots/ directory does not exist, skipping screenshot capture."
        return
    fi
    echo "[+] Capturing screenshots for live subdomains..."
    cat subdomains.txt | httprobe | gowitness scan --threads 5 --output screenshots/
}


# Main Execution
main() {
    if [ -z "$1" ]; then
        echo "Usage: $0 <domain>"
        exit 1
    fi
    install_tools
    enumerate_subdomains "$1"
    check_takeover
    scan_ports
    check_security_headers
    perform_dns_whois
    capture_screenshots
    echo "[+] Reconnaissance completed successfully. Check the output files for results."
}

main "$1"

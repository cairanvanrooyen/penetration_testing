# Nmap Reference Guide

## Introduction

Nmap (Network Mapper) is one of the most powerful and versatile network discovery and security auditing tools in penetration testing. It's used for network discovery, port scanning, service enumeration, operating system detection, and vulnerability assessment.

This comprehensive guide covers essential Nmap techniques from basic host discovery to advanced scripting and evasion techniques. Nmap is indispensable for reconnaissance and enumeration phases of penetration testing.

## Basic Scanning Techniques

### Host Discovery

| Command | Description |
|---------|-------------|
| `nmap 10.129.42.253` | Scan 1,000 most common ports |
| `nmap -sn 192.168.1.0/24` | Ping scan (host discovery only) |
| `nmap -Pn 10.129.42.253` | Skip ping (treat host as alive) |
| `nmap -PS22,80,443 10.129.42.253` | TCP SYN ping on specific ports |
| `nmap -PA22,80,443 10.129.42.253` | TCP ACK ping on specific ports |
| `nmap -PU53,161,162 10.129.42.253` | UDP ping on specific ports |
| `nmap -PE 10.129.42.253` | ICMP echo ping |
| `nmap -PP 10.129.42.253` | ICMP timestamp ping |

### Port Scanning Methods

| Command | Description |
|---------|-------------|
| `nmap -sS 10.129.42.253` | TCP SYN scan (stealth scan) |
| `nmap -sT 10.129.42.253` | TCP connect scan |
| `nmap -sU 10.129.42.253` | UDP scan |
| `nmap -sA 10.129.42.253` | TCP ACK scan |
| `nmap -sW 10.129.42.253` | TCP Window scan |
| `nmap -sM 10.129.42.253` | TCP Maimon scan |
| `nmap -sN 10.129.42.253` | TCP Null scan |
| `nmap -sF 10.129.42.253` | TCP FIN scan |
| `nmap -sX 10.129.42.253` | TCP Xmas scan |

## Port Specification

### Port Range Options

| Command | Description |
|---------|-------------|
| `nmap -p 80 10.129.42.253` | Scan specific port |
| `nmap -p 80,443,8080 10.129.42.253` | Scan multiple specific ports |
| `nmap -p 1-1000 10.129.42.253` | Scan port range |
| `nmap -p- 10.129.42.253` | Scan all 65,535 ports |
| `nmap -p U:53,T:22,80 10.129.42.253` | Scan UDP and TCP ports |
| `nmap --top-ports 100 10.129.42.253` | Scan top 100 most common ports |
| `nmap --top-ports 1000 10.129.42.253` | Scan top 1000 most common ports |
| `nmap -p http,https,ssh 10.129.42.253` | Scan by service name |

## Service and Version Detection

### Service Enumeration

| Command | Description |
|---------|-------------|
| `nmap -sV 10.129.42.253` | Version detection scan |
| `nmap -sC 10.129.42.253` | Default script scan |
| `nmap -sV -sC 10.129.42.253` | Version detection + default scripts |
| `nmap -sV -sC -p- 10.129.42.253` | Full port scan with scripts and versions |
| `nmap -A 10.129.42.253` | Aggressive scan (OS, version, script, traceroute) |
| `nmap -O 10.129.42.253` | Operating system detection |
| `nmap --version-intensity 9 10.129.42.253` | Maximum version detection intensity |
| `nmap --version-light 10.129.42.253` | Light version detection |

### Banner Grabbing

| Command | Description |
|---------|-------------|
| `nmap -sV --script=banner 10.129.42.253` | Banner grabbing scan |
| `nmap --script banner -p 21,22,23,25,53,80,110,443,993,995 10.129.42.253` | Banner grab on common ports |

## Nmap Scripting Engine (NSE)

### Script Categories

| Command | Description |
|---------|-------------|
| `nmap --script default 10.129.42.253` | Run default scripts |
| `nmap --script safe 10.129.42.253` | Run safe scripts only |
| `nmap --script intrusive 10.129.42.253` | Run intrusive scripts |
| `nmap --script vuln 10.129.42.253` | Run vulnerability scripts |
| `nmap --script discovery 10.129.42.253` | Run discovery scripts |
| `nmap --script brute 10.129.42.253` | Run brute force scripts |
| `nmap --script malware 10.129.42.253` | Run malware detection scripts |

### Common Script Examples

| Command | Description |
|---------|-------------|
| `nmap --script smb-os-discovery.nse -p445 10.129.42.253` | SMB OS discovery |
| `nmap --script smb-enum-shares -p445 10.129.42.253` | Enumerate SMB shares |
| `nmap --script http-enum 10.129.42.253` | HTTP enumeration |
| `nmap --script http-methods 10.129.42.253` | HTTP methods discovery |
| `nmap --script ssl-enum-ciphers -p443 10.129.42.253` | SSL cipher enumeration |
| `nmap --script dns-zone-transfer -p53 10.129.42.253` | DNS zone transfer |
| `nmap --script ftp-anon -p21 10.129.42.253` | FTP anonymous login |
| `nmap --script ssh-auth-methods -p22 10.129.42.253` | SSH authentication methods |

### Script Management

| Command | Description |
|---------|-------------|
| `locate scripts/citrix` | List available nmap scripts |
| `nmap --script-help vuln` | Get help for script category |
| `nmap --script-help smb-os-discovery` | Get help for specific script |
| `ls /usr/share/nmap/scripts/ \| grep smb` | Find SMB-related scripts |
| `nmap --script-updatedb` | Update script database |

## Target Specification

### Single and Multiple Targets

| Command | Description |
|---------|-------------|
| `nmap 192.168.1.1` | Single IP address |
| `nmap google.com` | Domain name |
| `nmap 192.168.1.1 192.168.1.2` | Multiple IPs |
| `nmap 192.168.1.1-10` | IP range |
| `nmap 192.168.1.0/24` | CIDR notation |
| `nmap -iL targets.txt` | Input from file |
| `nmap 192.168.1.*` | Wildcard |
| `nmap 192.168.1.1-255` | Range specification |

### Excluding Targets

| Command | Description |
|---------|-------------|
| `nmap 192.168.1.0/24 --exclude 192.168.1.1` | Exclude single host |
| `nmap 192.168.1.0/24 --exclude 192.168.1.1-10` | Exclude range |
| `nmap 192.168.1.0/24 --excludefile exclude.txt` | Exclude from file |

## Timing and Performance

### Timing Templates

| Command | Description |
|---------|-------------|
| `nmap -T0 10.129.42.253` | Paranoid timing (very slow) |
| `nmap -T1 10.129.42.253` | Sneaky timing (slow) |
| `nmap -T2 10.129.42.253` | Polite timing |
| `nmap -T3 10.129.42.253` | Normal timing (default) |
| `nmap -T4 10.129.42.253` | Aggressive timing |
| `nmap -T5 10.129.42.253` | Insane timing (very fast) |

### Custom Timing

| Command | Description |
|---------|-------------|
| `nmap --min-parallelism 100 10.129.42.253` | Minimum parallel probes |
| `nmap --max-parallelism 256 10.129.42.253` | Maximum parallel probes |
| `nmap --min-hostgroup 50 10.129.42.253` | Minimum hosts per group |
| `nmap --max-hostgroup 100 10.129.42.253` | Maximum hosts per group |
| `nmap --min-rate 1000 10.129.42.253` | Minimum packet rate |
| `nmap --max-rate 5000 10.129.42.253` | Maximum packet rate |

## Firewall Evasion

### Fragmentation and Decoys

| Command | Description |
|---------|-------------|
| `nmap -f 10.129.42.253` | Fragment packets |
| `nmap -ff 10.129.42.253` | Fragment packets more |
| `nmap --mtu 24 10.129.42.253` | Specify MTU size |
| `nmap -D RND:10 10.129.42.253` | Use random decoys |
| `nmap -D decoy1,decoy2,ME 10.129.42.253` | Specify decoy addresses |
| `nmap -S 192.168.1.5 10.129.42.253` | Spoof source address |
| `nmap --spoof-mac 0 10.129.42.253` | Spoof MAC address |

### Advanced Evasion

| Command | Description |
|---------|-------------|
| `nmap --data-length 25 10.129.42.253` | Append random data |
| `nmap --scan-delay 1s 10.129.42.253` | Delay between probes |
| `nmap --max-scan-delay 10s 10.129.42.253` | Maximum scan delay |
| `nmap --randomize-hosts 192.168.1.0/24` | Randomize target order |
| `nmap --badsum 10.129.42.253` | Use invalid checksums |

## Output Options

### Output Formats

| Command | Description |
|---------|-------------|
| `nmap -oN normal.txt 10.129.42.253` | Normal output to file |
| `nmap -oX xml.xml 10.129.42.253` | XML output to file |
| `nmap -oG greppable.txt 10.129.42.253` | Greppable output to file |
| `nmap -oA all_formats 10.129.42.253` | All formats (normal, XML, greppable) |
| `nmap -oS script_kiddie.txt 10.129.42.253` | Script kiddie output |
| `nmap --append-output 10.129.42.253` | Append to existing files |

### Verbosity and Debugging

| Command | Description |
|---------|-------------|
| `nmap -v 10.129.42.253` | Verbose output |
| `nmap -vv 10.129.42.253` | Very verbose output |
| `nmap -d 10.129.42.253` | Debug output |
| `nmap -dd 10.129.42.253` | More debug output |
| `nmap --reason 10.129.42.253` | Show reason for port state |
| `nmap --open 10.129.42.253` | Show only open ports |
| `nmap --packet-trace 10.129.42.253` | Show all packets sent/received |

## Advanced Scanning Techniques

### Idle Scan

| Command | Description |
|---------|-------------|
| `nmap -sI zombie_host target_host` | Idle scan using zombie host |
| `nmap -sI 192.168.1.100 10.129.42.253` | Idle scan example |

### IPv6 Scanning

| Command | Description |
|---------|-------------|
| `nmap -6 fe80::1` | IPv6 scan |
| `nmap -6 2001:db8::/32` | IPv6 network scan |

### FTP Bounce Scan

| Command | Description |
|---------|-------------|
| `nmap -b ftp_server target_host` | FTP bounce scan |
| `nmap -b anonymous:pass@ftp.server.com target` | FTP bounce with credentials |

## Common Scan Combinations

### Quick Scans

| Command | Description |
|---------|-------------|
| `nmap -sS -O -sV --script=default -oA quick 10.129.42.253` | Quick comprehensive scan |
| `nmap -T4 -A -v 10.129.42.253` | Fast aggressive scan |
| `nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY --source-port 53 10.129.42.253` | Comprehensive scan |

### Stealth Scans

| Command | Description |
|---------|-------------|
| `nmap -sS -T1 -f 10.129.42.253` | Slow stealth scan |
| `nmap -sN -T0 10.129.42.253` | Very slow null scan |
| `nmap -sF -T1 --scan-delay 10s 10.129.42.253` | Slow FIN scan with delay |

### Network Discovery

| Command | Description |
|---------|-------------|
| `nmap -sn 192.168.1.0/24` | Network discovery |
| `nmap -sn --traceroute 192.168.1.0/24` | Discovery with traceroute |
| `nmap -PR -sn 192.168.1.0/24` | ARP discovery on local network |

## Service-Specific Scanning

### Web Services

| Command | Description |
|---------|-------------|
| `nmap -p 80,443 --script http-enum 10.129.42.253` | HTTP enumeration |
| `nmap -p 443 --script ssl-cert,ssl-enum-ciphers 10.129.42.253` | SSL analysis |
| `nmap -p 80,443 --script http-methods,http-headers 10.129.42.253` | HTTP methods and headers |

### SMB/NetBIOS

| Command | Description |
|---------|-------------|
| `nmap -p 445 --script smb-enum-shares,smb-enum-users 10.129.42.253` | SMB enumeration |
| `nmap -p 139,445 --script smb-vuln-* 10.129.42.253` | SMB vulnerability scan |
| `nmap -p 137 --script nbstat 10.129.42.253` | NetBIOS information |

### Database Services

| Command | Description |
|---------|-------------|
| `nmap -p 3306 --script mysql-info,mysql-enum 10.129.42.253` | MySQL enumeration |
| `nmap -p 1433 --script ms-sql-info,ms-sql-enum 10.129.42.253` | SQL Server enumeration |
| `nmap -p 5432 --script pgsql-brute 10.129.42.253` | PostgreSQL brute force |

### SSH Services

| Command | Description |
|---------|-------------|
| `nmap -p 22 --script ssh-hostkey,ssh-auth-methods 10.129.42.253` | SSH information |
| `nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst 10.129.42.253` | SSH brute force |

## Post-Scan Analysis

### Result Processing

| Command | Description |
|---------|-------------|
| `grep "open" scan_results.txt` | Filter open ports |
| `grep -E "(80\|443\|8080)" scan_results.xml` | Find web ports |
| `nmap --resume scan_results.xml` | Resume interrupted scan |

### Useful Grep Patterns

| Command | Description |
|---------|-------------|
| `grep "Nmap scan report" results.txt` | Extract target IPs |
| `grep -A 5 "PORT.*STATE.*SERVICE" results.txt` | Extract port information |
| `grep "open" results.txt \| wc -l` | Count open ports |

This comprehensive Nmap reference guide covers essential scanning techniques, from basic host discovery to advanced evasion and scripting for effective network reconnaissance during penetration testing engagements.
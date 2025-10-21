# Subdomain Enumeration and Discovery

Techniques and tools for discovering subdomains and expanding the attack surface during reconnaissance.

## Overview

Subdomain enumeration is a critical reconnaissance technique that helps discover additional attack vectors by identifying subdomains of target domains. This process can reveal hidden services, development environments, and forgotten systems that may be more vulnerable than main production systems.

## Subdomain Discovery Methods

### Passive Enumeration

| Method | Description | Tools |
|--------|-------------|-------|
| **Certificate Transparency** | Public SSL certificate logs | crt.sh, Censys |
| **DNS Records** | Public DNS information | dig, nslookup |
| **Search Engines** | Indexed subdomain references | Google dorking |
| **Threat Intelligence** | Security databases | VirusTotal, PassiveDNS |

### Active Enumeration

| Method | Description | Tools |
|--------|-------------|-------|
| **DNS Brute Force** | Dictionary-based discovery | gobuster, ffuf |
| **Zone Transfer** | DNS zone file requests | dig, dnsrecon |
| **Recursive Scanning** | Multi-level discovery | amass, subfinder |
| **Permutation** | Pattern-based generation | altdns, dnsgen |

## Essential Tools

### Amass
```bash
# Basic subdomain enumeration
amass enum -d target.com

# Passive enumeration only
amass enum -passive -d target.com

# Active enumeration with brute force
amass enum -active -d target.com

# Output to file
amass enum -d target.com -o subdomains.txt

# Use specific data sources
amass enum -src -d target.com
```

### Subfinder
```bash
# Basic enumeration
subfinder -d target.com

# Multiple domains
subfinder -dL domains.txt

# Output to file
subfinder -d target.com -o subdomains.txt

# Use all sources
subfinder -d target.com -all

# Silent mode
subfinder -d target.com -silent
```

### Gobuster DNS Mode
```bash
# Basic DNS brute force
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt

# Specify DNS server
gobuster dns -d target.com -w wordlist.txt -r 8.8.8.8

# Increase threads
gobuster dns -d target.com -w wordlist.txt -t 50

# Show IP addresses
gobuster dns -d target.com -w wordlist.txt -i
```

### ffuf for DNS
```bash
# DNS subdomain fuzzing
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.target.com

# Filter by response size
ffuf -w wordlist.txt -u http://FUZZ.target.com -fs 1024

# Match HTTP status codes
ffuf -w wordlist.txt -u http://FUZZ.target.com -mc 200,301,302
```

## Manual Techniques

### Certificate Transparency
```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Using Censys
# Requires API key - web interface available
```

### DNS Zone Transfer
```bash
# Identify DNS servers
dig NS target.com

# Attempt zone transfer
dig @dns-server.target.com target.com AXFR

# Test all discovered DNS servers
for server in $(dig +short NS target.com); do
    echo "Testing $server"
    dig @$server target.com AXFR
done
```

### Google Dorking
```
site:target.com -www
site:*.target.com
site:target.com filetype:pdf
site:target.com inurl:login
site:target.com intitle:"dashboard"
```

## Advanced Techniques

### Recursive Discovery
```bash
# Using amass for recursive enumeration
amass enum -d target.com -brute -min-for-recursive 3

# Multi-level discovery with subfinder
subfinder -d target.com -silent | subfinder -dL - -silent
```

### Permutation-Based Discovery
```bash
# Generate permutations with altdns
altdns -i subdomains.txt -o permutations.txt -w words.txt

# Resolve permutations
altdns -i subdomains.txt -o permutations.txt -w words.txt -r -s resolved.txt

# Using dnsgen
cat subdomains.txt | dnsgen - | shuffledns -d target.com -r resolvers.txt
```

### API-Based Discovery
```bash
# Using multiple sources with subfinder
subfinder -d target.com -config config.yaml -all

# Security Trails API
curl -H "APIKEY: your-api-key" "https://api.securitytrails.com/v1/domain/target.com/subdomains"

# VirusTotal API
curl -H "x-apikey: your-api-key" "https://www.virustotal.com/vtapi/v2/domain/report?domain=target.com"
```

## Subdomain Validation

### DNS Resolution
```bash
# Bulk resolution with shuffledns
cat subdomains.txt | shuffledns -d target.com -r resolvers.txt

# Using massdns
massdns -r resolvers.txt -t A subdomains.txt -o S -w results.txt

# Python script for validation
import socket
def resolve_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return f"{subdomain}: {ip}"
    except:
        return None
```

### HTTP Probing
```bash
# Using httpx
cat subdomains.txt | httpx -silent

# Probe with specific ports
cat subdomains.txt | httpx -ports 80,443,8080,8443

# Include response size and status
cat subdomains.txt | httpx -content-length -status-code

# Screenshot with aquatone
cat subdomains.txt | aquatone
```

## Data Sources and APIs

### Free Sources

| Source | Type | Access Method |
|--------|------|---------------|
| **Certificate Transparency** | CT logs | Web/API |
| **DNS aggregators** | Passive DNS | Web queries |
| **Search engines** | Web indexing | Dorking |
| **Public databases** | Open sources | Various APIs |

### Premium Sources

| Source | Specialization | Cost Model |
|--------|---------------|------------|
| **SecurityTrails** | DNS history | Subscription |
| **Censys** | Internet scanning | Freemium |
| **Shodan** | Device discovery | Credits |
| **PassiveTotal** | Threat intelligence | Enterprise |

## Subdomain Classification

### Service Categories

| Category | Examples | Security Implications |
|----------|----------|----------------------|
| **Development** | dev.*, staging.*, test.* | Often less secure |
| **Administrative** | admin.*, panel.*, dashboard.* | High-value targets |
| **API endpoints** | api.*, rest.*, service.* | Potential data exposure |
| **Legacy systems** | old.*, legacy.*, archive.* | Outdated software |

### Risk Assessment

| Risk Level | Indicators | Examples |
|------------|------------|----------|
| **High** | Admin interfaces, APIs | admin.target.com |
| **Medium** | Development environments | dev.target.com |
| **Low** | Static content, CDNs | cdn.target.com |
| **Unknown** | Non-responsive subdomains | abandoned.target.com |

## Automation and Workflow

### Discovery Pipeline
```bash
#!/bin/bash
# Comprehensive subdomain discovery

DOMAIN=$1
OUTPUT_DIR="recon_$DOMAIN"

mkdir -p $OUTPUT_DIR

# Passive enumeration
echo "[+] Running passive enumeration"
subfinder -d $DOMAIN -all -silent > $OUTPUT_DIR/passive.txt
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/amass_passive.txt

# Active enumeration
echo "[+] Running active enumeration"
gobuster dns -d $DOMAIN -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -q > $OUTPUT_DIR/gobuster.txt

# Combine and deduplicate
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

# Validate subdomains
echo "[+] Validating subdomains"
shuffledns -d $DOMAIN -list $OUTPUT_DIR/all_subdomains.txt -r resolvers.txt -o $OUTPUT_DIR/valid_subdomains.txt

# HTTP probing
echo "[+] HTTP probing"
cat $OUTPUT_DIR/valid_subdomains.txt | httpx -silent > $OUTPUT_DIR/http_subdomains.txt

echo "[+] Discovery complete. Results in $OUTPUT_DIR/"
```

## Security Considerations

### Legal and Ethical Guidelines

- Only enumerate subdomains for authorized targets
- Respect rate limits and avoid overwhelming DNS servers
- Follow responsible disclosure for discovered vulnerabilities
- Document all discovery activities for audit purposes
- Be aware of potential DNS amplification effects

### Detection Avoidance

| Technique | Purpose | Implementation |
|-----------|---------|---------------|
| **Rate limiting** | Avoid detection | Throttle requests |
| **Distributed resolution** | Load spreading | Multiple resolvers |
| **User agent rotation** | Blend with normal traffic | Random headers |
| **Timing variation** | Avoid patterns | Random delays |

## Defensive Measures

### DNS Security

| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Zone transfer restrictions** | Prevent bulk disclosure | Access controls |
| **DNS monitoring** | Detect enumeration | Log analysis |
| **Subdomain hiding** | Reduce exposure | Internal DNS |
| **Rate limiting** | Prevent abuse | DNS server config |

### Asset Management

| Practice | Benefit | Implementation |
|----------|---------|---------------|
| **Subdomain inventory** | Complete visibility | Regular audits |
| **Certificate monitoring** | Detect new services | CT log monitoring |
| **DNS hygiene** | Reduce attack surface | Remove unused records |
| **Access controls** | Secure admin interfaces | Authentication |

## Additional Resources

- [OWASP Testing Guide - Subdomain Enumeration](https://owasp.org/www-project-web-security-testing-guide/)
- [Subdomain Enumeration Wordlists - SecLists](https://github.com/danielmiessler/SecLists)
- [Certificate Transparency - crt.sh](https://crt.sh/)
- [Amass User Guide](https://github.com/OWASP/Amass/blob/master/doc/user_guide.md)
# Web and Host Reconnaissance

Comprehensive techniques for gathering information about target websites and host systems during the reconnaissance phase.

## Overview

Web and host reconnaissance involves identifying and analyzing target systems, validating domains, discovering subdomains, fingerprinting technologies, and researching data breaches. This phase provides crucial intelligence for subsequent penetration testing activities.

## Target Validation

### Domain and IP Information

| Tool | Command | Purpose |
|------|---------|---------|
| **WHOIS** | `whois domain.com` | Domain registration information |
| **nslookup** | `nslookup domain.com` | DNS record lookup |
| **dig** | `dig domain.com` | Advanced DNS queries |
| **host** | `host domain.com` | Simple DNS lookup |

### DNS Reconnaissance

| Record Type | Command | Information Revealed |
|-------------|---------|---------------------|
| **A Record** | `dig A domain.com` | IPv4 addresses |
| **AAAA Record** | `dig AAAA domain.com` | IPv6 addresses |
| **MX Record** | `dig MX domain.com` | Mail servers |
| **NS Record** | `dig NS domain.com` | Name servers |
| **TXT Record** | `dig TXT domain.com` | Text records, SPF, DKIM |
| **CNAME** | `dig CNAME subdomain.domain.com` | Canonical names |

### Advanced DNS Tools

| Tool | Command | Capabilities |
|------|---------|-------------|
| **dnsrecon** | `dnsrecon -d domain.com` | Comprehensive DNS enumeration |
| **fierce** | `fierce -dns domain.com` | DNS brute forcing |
| **dnsenum** | `dnsenum domain.com` | DNS information gathering |

## Subdomain Discovery

### Passive Subdomain Enumeration

| Tool | Command | Description |
|------|---------|-------------|
| **Sublist3r** | `sublist3r -d domain.com` | OSINT subdomain discovery |
| **crt.sh** | Visit https://crt.sh/?q=domain.com | Certificate transparency logs |
| **Google Dorking** | `site:*.domain.com` | Search engine enumeration |
| **Amass** | `amass enum -d domain.com` | Advanced OSINT enumeration |

### Active Subdomain Discovery

| Tool | Command | Method |
|------|---------|--------|
| **Bluto** | `bluto -t domain.com` | DNS brute force |
| **Gobuster** | `gobuster dns -d domain.com -w wordlist.txt` | DNS brute forcing |
| **ffuf** | `ffuf -w wordlist.txt -u http://FUZZ.domain.com` | HTTP fuzzing |
| **dnscan** | `dnscan.py -d domain.com -w subdomains.txt` | DNS scanning |

### Subdomain Wordlists

| Wordlist | Size | Description |
|----------|------|-------------|
| **SecLists DNS** | ~100K | Comprehensive subdomain list |
| **Fierce hostlist** | ~2K | Common subdomains |
| **Custom lists** | Variable | Organization-specific patterns |

## Technology Fingerprinting

### Browser Extensions

| Extension | Platform | Capabilities |
|-----------|----------|-------------|
| **Wappalyzer** | Chrome/Firefox | Technology stack identification |
| **BuiltWith** | Chrome/Firefox | Detailed tech profiling |
| **retire.js** | Chrome/Firefox | Vulnerable JS library detection |

### Command Line Tools

| Tool | Command | Purpose |
|------|---------|---------|
| **WhatWeb** | `whatweb http://domain.com` | Technology fingerprinting |
| **Netcat** | `nc domain.com 80` | Banner grabbing |
| **Nmap** | `nmap -sV domain.com` | Service version detection |
| **curl** | `curl -I http://domain.com` | HTTP header analysis |

### Technology Categories

| Category | Examples | Security Implications |
|----------|----------|----------------------|
| **Web Servers** | Apache, Nginx, IIS | Version vulnerabilities |
| **Programming Languages** | PHP, Python, Java | Language-specific attacks |
| **Frameworks** | WordPress, Django, Laravel | Framework vulnerabilities |
| **Databases** | MySQL, PostgreSQL, MongoDB | Database-specific exploits |
| **CDNs** | Cloudflare, AWS CloudFront | Bypass techniques |

## HTTP Analysis

### Header Enumeration

| Header | Information | Security Relevance |
|--------|-------------|-------------------|
| **Server** | Web server type/version | Version vulnerabilities |
| **X-Powered-By** | Backend technology | Technology stack |
| **Set-Cookie** | Session management | Cookie security |
| **X-Frame-Options** | Clickjacking protection | Security posture |
| **Content-Security-Policy** | XSS protection | Security controls |

### Response Analysis

```bash
# Comprehensive HTTP analysis
curl -v -H "User-Agent: Mozilla/5.0" http://domain.com
curl -X OPTIONS http://domain.com
curl -I http://domain.com
```

## Data Breach Research

### Breach Databases

| Service | URL | Information Available |
|---------|-----|---------------------|
| **HaveIBeenPwned** | https://haveibeenpwned.com | Email breach notifications |
| **Breach-Parse** | Local database | Downloaded breach data |
| **WeLeakInfo** | (Defunct) | Historical breach service |
| **Dehashed** | https://dehashed.com | Breach search service |

### Credential Intelligence

| Source | Data Type | Usage |
|--------|-----------|-------|
| **Public dumps** | Plaintext passwords | Password pattern analysis |
| **Hash databases** | Password hashes | Hash cracking |
| **Combo lists** | Username:password pairs | Credential stuffing |

### Breach Analysis Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **breach-parse** | Local breach parsing | `./breach-parse.sh @domain.com` |
| **h8mail** | Email breach lookup | `h8mail -t email@domain.com` |
| **sherlock** | Username enumeration | `sherlock username` |

## Automated Reconnaissance

### Reconnaissance Frameworks

| Framework | Command | Capabilities |
|-----------|---------|-------------|
| **recon-ng** | `recon-ng` | Modular reconnaissance |
| **theHarvester** | `theHarvester -d domain.com -b all` | OSINT automation |
| **SpiderFoot** | Web-based interface | Automated intelligence gathering |
| **Maltego** | GUI application | Visual link analysis |

### Custom Automation Scripts

```bash
#!/bin/bash
# Basic web reconnaissance script
domain=$1

echo "[+] Starting reconnaissance for $domain"

# DNS enumeration
echo "[+] DNS enumeration"
dig ANY $domain
dnsrecon -d $domain

# Subdomain discovery
echo "[+] Subdomain discovery"
sublist3r -d $domain -o subdomains.txt

# Technology fingerprinting
echo "[+] Technology fingerprinting"
whatweb http://$domain

# Port scanning
echo "[+] Port scanning"
nmap -sV -T4 $domain

echo "[+] Reconnaissance complete"
```

## OSINT Sources

### Search Engines

| Engine | Specialization | Search Techniques |
|--------|---------------|------------------|
| **Google** | General web search | Advanced operators |
| **Bing** | Microsoft integration | Different indexing |
| **Shodan** | Internet-connected devices | IoT and services |
| **Censys** | Internet scanning | Certificate data |

### Social Media Intelligence

| Platform | Information Type | Collection Method |
|----------|-----------------|------------------|
| **LinkedIn** | Professional information | Profile enumeration |
| **Twitter** | Real-time updates | Hashtag/mention monitoring |
| **GitHub** | Code repositories | Organization repositories |
| **Pastebin** | Code/data dumps | Keyword searching |

## Security Considerations

### Legal and Ethical Guidelines

- Obtain proper authorization before conducting reconnaissance
- Respect rate limits and terms of service
- Avoid aggressive scanning that could impact services
- Use findings only for authorized security testing
- Follow responsible disclosure practices

### Operational Security

| Practice | Purpose | Implementation |
|----------|---------|----------------|
| **VPN usage** | Hide source IP | Commercial VPN services |
| **User agent rotation** | Avoid detection | Randomized headers |
| **Request throttling** | Prevent rate limiting | Delayed requests |
| **Proxy chaining** | Additional anonymity | Multiple proxy layers |

## Defensive Measures

### Domain Protection

| Control | Purpose | Implementation |
|---------|---------|----------------|
| **Domain monitoring** | Detect reconnaissance | DNS monitoring services |
| **Certificate monitoring** | Track subdomain creation | CT log monitoring |
| **Rate limiting** | Prevent brute forcing | Web application firewalls |
| **Honeypots** | Detect attackers | Fake subdomains/services |

### Information Minimization

| Practice | Benefit | Examples |
|----------|---------|----------|
| **Header hardening** | Reduce fingerprinting | Remove version information |
| **Error page customization** | Limit information disclosure | Generic error messages |
| **Subdomain cleanup** | Reduce attack surface | Remove unused subdomains |
| **WHOIS privacy** | Protect registration data | Privacy protection services |

## Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS OSINT Resources](https://www.sans.org/white-papers/36872/)
# Web Enumeration Reference

## Introduction

Web enumeration is a critical phase in penetration testing that involves discovering and analyzing web applications, directories, subdomains, and various web technologies. This comprehensive guide covers essential tools and techniques for thorough web application reconnaissance.

Web enumeration helps identify potential attack vectors, hidden content, misconfigurations, and valuable information that can be used in subsequent exploitation phases.

## HTTP Status Codes Reference

Understanding HTTP status codes is crucial for interpreting enumeration results:

| Status Code | Category | Description |
|-------------|----------|-------------|
| `200` | Success | Request successful |
| `301` | Redirection | Moved permanently |
| `302` | Redirection | Found (temporary redirect) |
| `403` | Client Error | Forbidden access |
| `404` | Client Error | Not found |
| `500` | Server Error | Internal server error |
| `503` | Server Error | Service unavailable |

For complete reference: [List of HTTP status codes](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)

## Directory and File Enumeration

### Gobuster - Directory Brute Forcing

| Command | Description |
|---------|-------------|
| `gobuster dir -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/common.txt` | Basic directory enumeration |
| `gobuster dir -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/big.txt` | Extended directory enumeration |
| `gobuster dir -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` | Large directory wordlist |
| `gobuster dir -u http://target/ -w wordlist.txt -x php,html,txt` | Enumerate with file extensions |
| `gobuster dir -u http://target/ -w wordlist.txt -s "200,204,301,302,307,403"` | Filter by status codes |
| `gobuster dir -u http://target/ -w wordlist.txt -o results.txt` | Save output to file |
| `gobuster dir -u http://target/ -w wordlist.txt -t 50` | Use 50 threads |
| `gobuster dir -u http://target/ -w wordlist.txt -k` | Skip SSL verification |

### Dirbuster - GUI Directory Enumeration

| Command | Description |
|---------|-------------|
| `dirbuster` | Launch GUI tool |
| `dirb http://target/` | Basic directory scan |
| `dirb http://target/ /usr/share/dirb/wordlists/common.txt` | Custom wordlist |
| `dirb http://target/ /usr/share/dirb/wordlists/big.txt -X .php,.html` | With extensions |

### Feroxbuster - Fast Content Discovery

| Command | Description |
|---------|-------------|
| `feroxbuster -u http://target/` | Basic scan |
| `feroxbuster -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` | Custom wordlist |
| `feroxbuster -u http://target/ -x php,html,txt,js` | File extensions |
| `feroxbuster -u http://target/ -t 200` | High thread count |

## Subdomain Enumeration

### DNS Subdomain Discovery

| Command | Description |
|---------|-------------|
| `gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/namelist.txt` | Basic DNS enumeration |
| `gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Top subdomains |
| `amass enum -d target.com` | Comprehensive subdomain enumeration |
| `amass enum -d target.com -o subdomains.txt` | Save results |
| `sublist3r -d target.com` | Sublist3r enumeration |
| `subfinder -d target.com` | Subfinder tool |

### Virtual Host Discovery

| Command | Description |
|---------|-------------|
| `gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Virtual host enumeration |
| `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://target.com -H "Host: FUZZ.target.com"` | FFUF vhost fuzzing |

### Subdomain Validation

| Command | Description |
|---------|-------------|
| `httprobe < subdomains.txt` | Check if subdomains are live |
| `cat subdomains.txt \| httprobe -s -p https:443` | HTTPS probe |
| `cat subdomains.txt \| httprobe > live_subdomains.txt` | Save live subdomains |

### SecLists Installation

| Command | Description |
|---------|-------------|
| `sudo apt install seclists -y` | Install via apt |
| `git clone https://github.com/danielmiessler/SecLists` | Clone repository |

## Web Technology Identification

### Banner Grabbing

| Command | Description |
|---------|-------------|
| `curl -I http://target/` | Basic header information |
| `curl -IL https://target/` | Follow redirects |
| `curl -A "Custom-Agent" http://target/` | Custom user agent |
| `curl -H "Host: target.com" http://ip/` | Custom host header |
| `wget --server-response --spider http://target/` | Wget headers |

### Technology Stack Identification

| Command | Description |
|---------|-------------|
| `whatweb http://target/` | Basic technology identification |
| `whatweb --no-errors 10.10.10.0/24` | Network range scan |
| `whatweb -v http://target/` | Verbose output |
| `whatweb --aggression 3 http://target/` | Aggressive scan |
| `wappalyzer http://target/` | Browser extension analysis |

### Specialized Scanners

| Command | Description |
|---------|-------------|
| `nikto -h http://target/` | Vulnerability scanner |
| `nikto -h http://target/ -p 80,443,8080` | Multiple ports |
| `nmap --script http-enum http://target/` | Nmap HTTP enumeration |
| `nmap --script http-methods http://target/` | HTTP methods |

## SSL/TLS Certificate Analysis

### Certificate Information

| Command | Description |
|---------|-------------|
| `openssl s_client -connect target.com:443` | SSL connection details |
| `openssl s_client -connect target.com:443 \| openssl x509 -noout -text` | Certificate details |
| `sslscan target.com` | SSL/TLS scanner |
| `sslyze target.com` | SSL configuration analyzer |

### Certificate Transparency

| Resource | Description |
|----------|-------------|
| `https://crt.sh/?q=target.com` | Certificate transparency logs |
| `https://transparencyreport.google.com/https/certificates` | Google certificate transparency |

## Common Web Files and Directories

### Important Files to Check

| File/Directory | Description |
|----------------|-------------|
| `/robots.txt` | Reveals private files and admin pages |
| `/sitemap.xml` | Site structure information |
| `/.well-known/` | RFC 5785 well-known URIs |
| `/admin/` | Admin panel |
| `/login/` | Login pages |
| `/backup/` | Backup files |
| `/.git/` | Git repository |
| `/.env` | Environment variables |
| `/config/` | Configuration files |
| `/api/` | API endpoints |

### File Extensions to Enumerate

| Extension | Description |
|-----------|-------------|
| `.php` | PHP files |
| `.html` | HTML files |
| `.txt` | Text files |
| `.js` | JavaScript files |
| `.css` | Stylesheets |
| `.json` | JSON files |
| `.xml` | XML files |
| `.bak` | Backup files |
| `.old` | Old files |
| `.zip` | Archive files |

## Content Management System (CMS) Enumeration

### WordPress

| Command | Description |
|---------|-------------|
| `wpscan --url http://target/wordpress/` | Basic WordPress scan |
| `wpscan --url http://target/wordpress/ --enumerate u` | Enumerate users |
| `wpscan --url http://target/wordpress/ --enumerate p` | Enumerate plugins |
| `wpscan --url http://target/wordpress/ --enumerate t` | Enumerate themes |
| `wpscan --url http://target/wordpress/ --enumerate vp` | Vulnerable plugins |

### Drupal

| Command | Description |
|---------|-------------|
| `droopescan scan drupal -u http://target/` | Drupal scanner |
| `drupwn --target http://target/` | Drupal enumeration |

### Joomla

| Command | Description |
|---------|-------------|
| `joomscan -u http://target/` | Joomla scanner |
| `droopescan scan joomla -u http://target/` | Alternative Joomla scan |

## Advanced Enumeration Techniques

### Parameter Discovery

| Command | Description |
|---------|-------------|
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://target/page?FUZZ=test` | Parameter fuzzing |
| `arjun -u http://target/` | Parameter discovery tool |
| `paramspider -d target.com` | Parameter spider |

### Fuzzing Techniques

| Command | Description |
|---------|-------------|
| `ffuf -w wordlist.txt -u http://target/FUZZ` | Basic fuzzing |
| `ffuf -w wordlist.txt -u http://target/FUZZ -mc 200` | Match status codes |
| `ffuf -w wordlist.txt -u http://target/FUZZ -fs 1234` | Filter by size |
| `wfuzz -c -z file,wordlist.txt http://target/FUZZ` | Wfuzz directory fuzzing |

### API Enumeration

| Command | Description |
|---------|-------------|
| `gobuster dir -u http://target/api/ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt` | API endpoint discovery |
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u http://target/api/FUZZ` | API fuzzing |

## Wordlist Resources

### Common Wordlist Locations

| Wordlist | Description |
|----------|-------------|
| `/usr/share/seclists/Discovery/Web-Content/common.txt` | Common directories |
| `/usr/share/seclists/Discovery/Web-Content/big.txt` | Large directory list |
| `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` | RAFT directories |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Top subdomains |
| `/usr/share/dirb/wordlists/common.txt` | Dirb common |
| `/usr/share/wordlists/rockyou.txt` | Common passwords |

## Manual Enumeration Techniques

### Browser-Based Reconnaissance

| Technique | Description |
|-----------|-------------|
| `View Page Source (Ctrl+U)` | Examine HTML source code |
| `Developer Tools (F12)` | Inspect elements and network |
| `Burp Suite Proxy` | Intercept and analyze requests |
| `Browser Extensions` | Wappalyzer, BuiltWith |

### Information Gathering

| Target | Method |
|--------|---------|
| `Comments in source` | Look for developer comments |
| `JavaScript files` | Analyze for endpoints and secrets |
| `Error messages` | Trigger errors for information disclosure |
| `HTTP headers` | Analyze security headers |
| `Cookies` | Examine cookie structure |

## Output and Reporting

### Save Results

| Command | Description |
|---------|-------------|
| `gobuster dir -u http://target/ -w wordlist.txt -o results.txt` | Save to file |
| `gobuster dir -u http://target/ -w wordlist.txt \| tee results.txt` | Display and save |
| `whatweb http://target/ > tech_stack.txt` | Technology results |

### Result Analysis

| Command | Description |
|---------|-------------|
| `grep "Status: 200" results.txt` | Filter successful requests |
| `sort -u subdomains.txt` | Remove duplicate subdomains |
| `cat results.txt \| grep -E "(200\|301\|302)"` | Filter interesting status codes |

This comprehensive web enumeration guide provides structured techniques for discovering web application attack surfaces, hidden content, and technology stacks during penetration testing engagements.


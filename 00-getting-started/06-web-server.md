# Web Servers

HTTP/HTTPS servers that handle client requests and serve web content, typically running on ports 80 and 443.

## Overview

Web servers are critical infrastructure components that handle HTTP traffic from client browsers, route requests to appropriate pages, and respond with web content. They're common targets during penetration testing due to their public exposure and potential for various vulnerabilities.

## Common Web Servers

| Server | Description | Default Config Location |
|--------|-------------|------------------------|
| **Apache** | Most popular open-source server | `/etc/apache2/` or `/etc/httpd/` |
| **Nginx** | High-performance reverse proxy/server | `/etc/nginx/` |
| **IIS** | Microsoft Internet Information Services | `C:\inetpub\wwwroot\` |
| **Tomcat** | Java servlet container | `/opt/tomcat/` |
| **Lighttpd** | Lightweight server for speed | `/etc/lighttpd/` |

## Basic Web Server Information

| Port | Protocol | Description |
|------|----------|-------------|
| **80** | HTTP | Unencrypted web traffic |
| **443** | HTTPS | SSL/TLS encrypted traffic |
| **8080** | HTTP Alt | Alternative HTTP port |
| **8443** | HTTPS Alt | Alternative HTTPS port |
| **8000** | HTTP Dev | Development server port |

## Quick HTTP Server Setup

### Python HTTP Server

| Command | Description | Port |
|---------|-------------|------|
| `python3 -m http.server` | Start HTTP server | 8000 |
| `python3 -m http.server 80` | Start on port 80 | 80 |
| `python3 -m http.server --bind 0.0.0.0` | Bind to all interfaces | 8000 |

### PHP Development Server

```bash
# Start PHP development server
php -S localhost:8000
php -S 0.0.0.0:8080
```

### Node.js HTTP Server

```bash
# Using http-server package
npm install -g http-server
http-server -p 8080
```

## Web Server Enumeration

### Basic Information Gathering

| Command | Description | Example |
|---------|-------------|---------|
| `curl -I http://target` | Get HTTP headers | `curl -I http://192.168.1.100` |
| `curl -X OPTIONS http://target` | Check allowed methods | `curl -X OPTIONS http://192.168.1.100` |
| `whatweb target` | Web technology fingerprinting | `whatweb 192.168.1.100` |
| `nikto -h target` | Web vulnerability scanner | `nikto -h 192.168.1.100` |

### HTTP Headers Analysis

| Header | Information Revealed |
|--------|---------------------|
| `Server` | Web server type and version |
| `X-Powered-By` | Backend technology (PHP, ASP.NET) |
| `X-Frame-Options` | Clickjacking protection |
| `Content-Security-Policy` | XSS protection policies |
| `Set-Cookie` | Session management details |

## Common Web Vulnerabilities

### OWASP Top 10 Categories

| Rank | Vulnerability | Description |
|------|---------------|-------------|
| **A01** | Broken Access Control | Authorization flaws |
| **A02** | Cryptographic Failures | Weak encryption/hashing |
| **A03** | Injection | SQL, NoSQL, LDAP injection |
| **A04** | Insecure Design | Security design flaws |
| **A05** | Security Misconfiguration | Default/poor configurations |
| **A06** | Vulnerable Components | Outdated libraries/frameworks |
| **A07** | Authentication Failures | Weak authentication |
| **A08** | Software Integrity Failures | Unsigned/unverified code |
| **A09** | Logging/Monitoring Failures | Insufficient detection |
| **A10** | Server-Side Request Forgery | SSRF attacks |

### Quick Vulnerability Tests

| Test | Command | Purpose |
|------|---------|---------|
| **Directory listing** | `curl http://target/` | Check for exposed directories |
| **Common files** | `curl http://target/robots.txt` | Find hidden content |
| **SQL injection** | `'` in parameters | Test for database errors |
| **XSS** | `<script>alert(1)</script>` | Test for script execution |

## Configuration Security

### Apache Security Headers

```apache
# Enable security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000"
```

### Nginx Security Headers

```nginx
# Add security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000" always;
```

## Security Considerations

- Keep web servers updated with latest security patches
- Disable unnecessary modules and services
- Implement proper access controls and authentication
- Use HTTPS with strong SSL/TLS configurations
- Monitor access logs for suspicious activity
- Implement Web Application Firewalls (WAF) where appropriate

## Penetration Testing Notes

- Always enumerate web technologies and versions
- Check for default credentials and configurations
- Test for common vulnerabilities (OWASP Top 10)
- Look for backup files, configuration files, and sensitive data
- Test file upload functionality for potential exploitation

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Apache Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [Nginx Security Controls](https://www.nginx.com/blog/nginx-security-controls/)
- [Web Application Security Testing](https://owasp.org/www-project-web-security-testing-guide/)

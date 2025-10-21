# Nessus Vulnerability Scanner

Enterprise-grade vulnerability assessment tool for identifying security weaknesses in networks, systems, and applications.

## Overview

Nessus is a comprehensive vulnerability scanner developed by Tenable that identifies vulnerabilities, configuration issues, and malware in networks and systems. It's widely used in penetration testing for automated vulnerability assessment and compliance checking.

## Installation

### Nessus Essentials (Free)

```bash
# Download from Tenable website
wget https://www.tenable.com/downloads/nessus
# Install on Ubuntu/Debian
sudo dpkg -i Nessus-[version]-ubuntu[version]_amd64.deb
# Start Nessus service
sudo systemctl start nessusd
```

### Web Interface Access

| URL | Port | Purpose |
|-----|------|---------|
| `https://localhost:8834` | 8834 | Web management interface |

## Basic Configuration

### Initial Setup

| Step | Action | Description |
|------|--------|-------------|
| **1** | Navigate to web interface | `https://localhost:8834` |
| **2** | Create admin account | Set username and password |
| **3** | Register product | Enter license key |
| **4** | Download plugins | Wait for plugin compilation |

### User Management

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Administrator** | Full access, user management | System administration |
| **Standard User** | Create and run scans | Regular scanning operations |
| **Scan Operator** | Limited scan capabilities | Controlled access |

## Scan Types

### Basic Network Scan

| Scan Type | Description | Use Case |
|-----------|-------------|----------|
| **Basic Network Scan** | Standard vulnerability assessment | General network testing |
| **Advanced Scan** | Customizable comprehensive scan | Detailed security assessment |
| **Web Application Tests** | Web-specific vulnerabilities | Web application security |
| **Malware Scan** | Malware detection | System compromise assessment |

### Advanced Scan Templates

| Template | Focus Area | Typical Use |
|----------|------------|-------------|
| **PCI DSS** | Payment card compliance | Financial systems |
| **Internal Network Scan** | Internal infrastructure | Network security audit |
| **External Network Scan** | Internet-facing systems | Perimeter security |
| **Web Application Scan** | Web vulnerabilities | Application security |

## Scan Configuration

### Target Specification

| Format | Example | Description |
|--------|---------|-------------|
| **Single IP** | `192.168.1.100` | Individual host |
| **IP Range** | `192.168.1.1-100` | Range of addresses |
| **CIDR Notation** | `192.168.1.0/24` | Network subnet |
| **Hostname** | `example.com` | DNS resolvable name |

### Credentials Configuration

```bash
# SSH credentials for authenticated scans
Username: root
Password: [password]
# Or use SSH key authentication
Private Key: [path/to/private/key]
```

### Advanced Options

| Setting | Purpose | Impact |
|---------|---------|--------|
| **Port Range** | Limit scan ports | Faster, focused scanning |
| **Timing Template** | Control scan speed | Balance speed vs. stealth |
| **Safe Checks** | Avoid service disruption | Production environment safety |
| **Plugin Selection** | Choose vulnerability checks | Customize scan scope |

## Vulnerability Assessment

### Severity Levels

| Level | Color | Description | Priority |
|-------|-------|-------------|----------|
| **Critical** | Purple | Immediate exploitation risk | Urgent |
| **High** | Red | Significant security risk | High |
| **Medium** | Orange | Moderate security concern | Medium |
| **Low** | Yellow | Minor security issue | Low |
| **Info** | Blue | Informational finding | Reference |

### Common Vulnerability Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| **Remote Code Execution** | Buffer overflows, injection flaws | Critical |
| **Authentication Bypass** | Default credentials, weak passwords | High |
| **Information Disclosure** | Directory listing, sensitive files | Medium |
| **Cross-Site Scripting** | Reflected/stored XSS | Medium |
| **Configuration Issues** | Unnecessary services, weak settings | Low-Medium |

## Reporting

### Report Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| **HTML** | Web-viewable report | Executive presentation |
| **PDF** | Printable document | Formal documentation |
| **CSV** | Spreadsheet format | Data analysis |
| **Nessus** | Native format | Further analysis in Nessus |

### Report Customization

| Section | Content | Purpose |
|---------|---------|---------|
| **Executive Summary** | High-level findings | Management overview |
| **Vulnerability Details** | Technical information | Technical team remediation |
| **Remediation** | Fix recommendations | Action planning |
| **Compliance** | Regulatory alignment | Audit requirements |

## Integration with Penetration Testing

### Workflow Integration

| Phase | Nessus Role | Output |
|-------|-------------|--------|
| **Reconnaissance** | Network discovery | Asset inventory |
| **Vulnerability Assessment** | Automated scanning | Vulnerability list |
| **Exploitation Planning** | Priority targeting | Attack surface analysis |
| **Reporting** | Evidence gathering | Professional documentation |

### Manual Verification

```bash
# Verify critical findings manually
nmap -sC -sV target_ip -p vulnerable_port
# Test specific vulnerabilities
curl -X GET "http://target/vulnerable_path"
```

## Advanced Features

### Plugin Management

| Action | Command/Process | Purpose |
|--------|----------------|---------|
| **Update Plugins** | Automatic/manual update | Latest vulnerability checks |
| **Custom Plugins** | NASL scripting | Organization-specific tests |
| **Plugin Families** | Enable/disable categories | Focused scanning |

### API Integration

```python
# Nessus API example
import requests

def start_scan(scan_id):
    url = f"https://localhost:8834/scans/{scan_id}/launch"
    headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
    response = requests.post(url, headers=headers, verify=False)
    return response.json()
```

## Security Considerations

- Nessus scans can impact system performance
- Some plugins may cause service interruption
- Always obtain proper authorization before scanning
- Use authenticated scans for comprehensive assessment
- Be cautious with DoS plugins in production environments
- Secure Nessus installation with strong authentication

## Best Practices

| Practice | Benefit | Implementation |
|----------|---------|----------------|
| **Regular Updates** | Latest vulnerability coverage | Automatic plugin updates |
| **Authenticated Scans** | Deeper vulnerability assessment | Configure credentials |
| **Baseline Scanning** | Track security posture changes | Scheduled scans |
| **Risk Prioritization** | Focus on critical issues | CVSS scoring |

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|---------|
| **Slow scans** | Network congestion | Adjust timing templates |
| **Authentication failures** | Wrong credentials | Verify account settings |
| **Plugin errors** | Outdated plugins | Update plugin feed |
| **Service crashes** | Resource constraints | Increase system resources |

## Alternative Vulnerability Scanners

| Scanner | Type | Licensing |
|---------|------|-----------|
| **OpenVAS** | Open source | Free |
| **Qualys** | Cloud-based | Commercial |
| **Rapid7 Nexpose** | Enterprise | Commercial |
| **Nuclei** | Command-line | Open source |

## Additional Resources

- [Nessus Documentation](https://docs.tenable.com/nessus/)
- [NASL Plugin Development](https://docs.tenable.com/nessus/Content/NASL.htm)
- [Tenable University](https://university.tenable.com/)

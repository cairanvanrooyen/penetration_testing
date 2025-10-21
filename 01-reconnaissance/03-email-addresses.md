
# Email Address Enumeration

Techniques and tools for discovering email addresses associated with target organizations during reconnaissance.

## Overview

Email enumeration is a crucial first step in penetration testing that helps identify potential targets for social engineering, credential attacks, and understanding organizational structure. Email addresses often follow predictable patterns and can reveal valuable information about the target.

## Email Discovery Platforms

| Platform | URL | Description |
|----------|-----|-------------|
| **Hunter.io** | https://hunter.io | Domain-based email discovery |
| **Phonebook.cz** | https://phonebook.cz | Search engine for email addresses |
| **VoiletNoBear** | https://voiletno bear.com | Email and domain intelligence |
| **Clearbit Connect** | Gmail extension | LinkedIn email discovery |

## Command Line Tools

### theHarvester

| Command | Description | Example |
|---------|-------------|---------|
| `theHarvester -d domain -b all` | Search all sources | `theHarvester -d example.com -b all` |
| `theHarvester -d domain -b google` | Google search only | `theHarvester -d example.com -b google` |
| `theHarvester -d domain -l 500` | Limit results | `theHarvester -d example.com -l 500 -b all` |

### Maltego

```bash
# Commercial OSINT tool with email discovery transforms
# Provides visual link analysis of email relationships
maltego
```

### Additional Tools

| Tool | Command | Purpose |
|------|---------|---------|
| **recon-ng** | `use recon/domains-contacts/whois_pocs` | Domain contact extraction |
| **Sherlock** | `sherlock username` | Username enumeration across platforms |
| **holehe** | `holehe email@domain.com` | Check email account existence |

## Email Pattern Analysis

### Common Email Formats

| Pattern | Example | Usage |
|---------|---------|-------|
| firstname.lastname | john.doe@company.com | Most common |
| firstname_lastname | john_doe@company.com | Alternative format |
| firstinitial.lastname | j.doe@company.com | Space-saving |
| firstname | john@company.com | Small organizations |
| lastname.firstname | doe.john@company.com | Some organizations |

### Pattern Testing

```bash
# Test email patterns with tools like:
# - Email verification APIs
# - SMTP verification
# - Response timing analysis
```

## OSINT Email Sources

### Search Engines

| Source | Search Query | Example |
|--------|--------------|---------|
| **Google** | `site:company.com "@company.com"` | Find email addresses on site |
| **Bing** | `"@company.com" site:linkedin.com` | LinkedIn employee emails |
| **DuckDuckGo** | `"company.com" filetype:pdf` | Documents with emails |

### Social Media Platforms

| Platform | Information Available |
|----------|---------------------|
| **LinkedIn** | Employee names, job titles, company structure |
| **Twitter** | Public profiles, contact information |
| **Facebook** | Personal/business contact details |
| **GitHub** | Developer email addresses in commits |

### Public Documents

| Document Type | Potential Email Sources |
|---------------|------------------------|
| **PDF Reports** | Contact information, signatures |
| **WHOIS Records** | Administrative contacts |
| **Job Postings** | HR and hiring manager contacts |
| **Press Releases** | PR and executive contacts |

## Email Verification

### Verification Methods

| Method | Tool/Service | Reliability |
|--------|--------------|-------------|
| **SMTP Verification** | `telnet mail.server.com 25` | High |
| **API Services** | ZeroBounce, NeverBounce | High |
| **Response Analysis** | Manual testing | Medium |
| **Social Media Check** | Manual verification | Medium |

### SMTP Verification Example

```bash
# Manual SMTP verification
telnet mail.company.com 25
HELO attacker.com
MAIL FROM: test@attacker.com
RCPT TO: target@company.com
# Check response codes
QUIT
```

## Automated Collection

### Custom Scripts

```bash
#!/bin/bash
# Simple email harvesting script
domain=$1
echo "Harvesting emails for $domain"

# theHarvester
theHarvester -d $domain -b all -f emails_harvester.txt

# Search in public documents
wget -r -A pdf,doc,docx,txt $domain
grep -r "@$domain" . > emails_documents.txt
```

## Security Considerations

- Always obtain proper authorization before testing
- Be aware of rate limiting on public services
- Respect robots.txt and terms of service
- Consider legal implications of email enumeration
- Use findings responsibly for authorized testing only

## Data Analysis

### Email Intelligence

| Analysis Type | Information Gained |
|---------------|-------------------|
| **Domain patterns** | Organization email structure |
| **Employee hierarchy** | Management vs. staff emails |
| **Department structure** | Different teams and functions |
| **Technology stack** | Email providers and security |

### Reporting Format

```
Target: example.com
Total emails found: 47
Patterns identified:
- firstname.lastname@example.com (35 emails)
- f.lastname@example.com (8 emails)
- department@example.com (4 emails)

High-value targets:
- admin@example.com
- security@example.com
- ceo@example.com
```

## Additional Resources

- [theHarvester Documentation](https://github.com/laramies/theHarvester)
- [OSINT Framework](https://osintframework.com/)
- [Recon-ng Wiki](https://github.com/lanmaster53/recon-ng/wiki)

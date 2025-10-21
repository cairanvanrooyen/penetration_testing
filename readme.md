# Penetration Testing Methodology & Resources

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

A comprehensive, structured collection of penetration testing methodologies, tools, and techniques organized following industry-standard ethical hacking frameworks.

## Repository Structure

```
penetration_testing/
├── 00-getting-started/           # Prerequisites & Essential Tools
├── 01-reconnaissance/            # Information Gathering (Passive & Active)
├── 02-scanning-enumeration/      # Network & Service Discovery
├── 03-exploitation/              # Gaining System Access
├── 04-maintaining-access/        # Post-Exploitation Activities
├── 05-covering-tracks/           # Evidence Removal & Cleanup
├── 90-cheat-sheets/             # Quick Reference Guides
├── 91-linux/                    # Linux-Specific Resources
├── 92-python/                   # Python for Penetration Testing
└── 99-training-boxes/           # Practice Environments
```

## Methodology Overview

This repository follows the standard penetration testing framework:

1. **Reconnaissance** - Passive & active information gathering
2. **Scanning & Enumeration** - Network discovery, port scanning, service enumeration
3. **Exploitation** - Gaining unauthorized access to systems
4. **Maintaining Access** - Establishing persistent access & lateral movement
5. **Covering Tracks** - Evidence removal & cleanup procedures

## Getting Started

1. Start with `00-getting-started/` for essential tool setup
2. Review `90-cheat-sheets/` for quick command references
3. Follow the methodology phases in order: `01-` through `05-`
4. Practice techniques using `99-training-boxes/` environments

## Featured Tools

| Category | Tools | Documentation |
|----------|-------|---------------|
| **Network Scanning** | Nmap, Masscan | `02-scanning-enumeration/02-nmap.md` |
| **Web Testing** | Burp Suite, OWASP ZAP | `01-reconnaissance/04-burp-suite.md` |
| **Password Attacks** | Hydra, John, Hashcat | `03-exploitation/02-password-cracking.md` |
| **Privilege Escalation** | LinPEAS, WinPEAS | `03-exploitation/03-privilege-escalation.md` |

## Contributing

We welcome contributions from the cybersecurity community! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Legal Disclaimer

**⚠️ EDUCATIONAL USE ONLY**

This repository is intended exclusively for:
- Educational learning and skill development
- Authorized penetration testing with explicit written permission
- Security research in controlled environments
- Capture The Flag (CTF) competitions

Users are solely responsible for ensuring compliance with all applicable laws and regulations. Unauthorized access to computer systems is illegal.

## Acknowledgments

This resource was developed with assistance from GitHub Copilot AI for content organization, documentation creation, and quality assurance.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Educational cybersecurity resource | Use responsibly*



## 📋 Table of Contents## Repository StructureProjects



- [🚀 Quick Start](#-quick-start)	Target_1

- [📂 Repository Structure](#-repository-structure)

- [🎯 Methodology Overview](#-methodology-overview)```		evidence

- [📚 Learning Path](#-learning-path)

- [🛠️ Tool References](#️-tool-references)penetration_testing/			credentials

- [🏆 Training Labs](#-training-labs)

- [🤝 Contributing](#-contributing)├── reconnaissance/              # Passive & active information gathering			data

- [⚖️ Legal Disclaimer](#️-legal-disclaimer)

- [🙏 Acknowledgments](#-acknowledgments)│   ├── burp-suite.md           # Burp Suite proxy configuration & usage			screenshots



## 🚀 Quick Start│   ├── email-addresses.md      # Email enumeration techniques		logs



```bash│   ├── physical-and-social.md  # Physical & social engineering methods		scans

# Clone the repository

git clone https://github.com/cairanvanrooyen/penetration_testing.git│   └── web-or-host.md          # Web application & host reconnaissance		scope

cd penetration_testing

├── scanning-enumeration/        # Network & service discovery		tools

# Start with the basics

cd 00-getting-started│   ├── nessus.md               # Vulnerability scanner usage



# Follow the numbered methodology│   ├── nmap.md                 # Network mapping & port scanning

cd 01-reconnaissance

```│   ├── ports.md                # Common ports & services referenceReconnaissance (active and passive)



## 📂 Repository Structure│   ├── smb.md                  # SMB/CIFS enumeration & exploitationScanning and enumeration (Nmap, Nessus, Nikto, etc.)



This repository follows the **industry-standard penetration testing methodology** with numbered folders for logical progression:│   └── web-enumeration.md      # Web application enumerationGaining access ('Explotation')



```├── exploitation/               # Gaining system accessMaintaining access

penetration_testing/

├── 📁 00-getting-started/           # Prerequisites & Essential Tools│   ├── password-cracking.md    # Credential attack techniquesCovering tracks (clean up)

│   ├── 01-vim.md                   # Text editor mastery

│   ├── 02-tmux.md                  # Terminal multiplexer│   ├── privilege-escalation.md # Escalation methodologies

│   ├── 03-ssh.md                   # Secure shell protocols

│   ├── 04-ftp.md                   # File transfer protocols│   └── public-exploits.md      # Public exploit databases & usage

│   ├── 05-netcat.md                # Network utility swiss army knife├── maintaining-access/         # Post-exploitation activities

│   └── 06-web-server.md            # Web server configurations│   └── shells.md              # Shell types & management

│├── covering-tracks/           # Evidence removal & cleanup

├── 🔍 01-reconnaissance/           # Information Gathering (Passive & Active)├── getting-started/           # Essential tools & setup

│   ├── 01-email-addresses.md      # Email enumeration techniques│   ├── ftp.md                 # FTP service interaction

│   ├── 02-physical-and-social.md  # OSINT & social engineering│   ├── netcat.md              # Network utility usage

│   ├── 03-web-or-host.md          # Target reconnaissance│   ├── ssh.md                 # SSH protocols & techniques

│   └── 04-burp-suite.md           # Proxy configuration & usage│   ├── tmux.md                # Terminal multiplexer

││   ├── vim.md                 # Text editor commands

├── 🎯 02-scanning-enumeration/     # Network & Service Discovery│   └── web-server.md          # Web server configurations

│   ├── 01-ports.md                # Port & service reference├── cheat-sheets/              # Quick reference guides

│   ├── 02-nmap.md                 # Network mapping & scanning│   └── getting-started-cheatsheet.md

│   ├── 03-web-enumeration.md      # Web application discovery├── linux/                     # Linux-specific resources

│   ├── 04-smb.md                  # SMB/CIFS enumeration│   ├── kali.md               # Kali Linux tools & setup

│   └── 05-nessus.md               # Vulnerability scanning│   └── linux.md              # Linux commands & techniques

│├── python/                    # Python scripts & resources

├── 💥 03-exploitation/             # Gaining System Access│   └── python.md             # Python reference for pentesters

│   ├── 01-public-exploits.md      # Exploit databases & frameworks└── training-boxes/           # Practice environments

│   ├── 02-password-cracking.md    # Credential attack techniques    ├── tryhackme/            # TryHackMe platform walkthroughs

│   └── 03-privilege-escalation.md # Escalation methodologies    │   └── basic-pentesting.md

│    └── kioptrix/             # Kioptrix VM series

├── 🔒 04-maintaining-access/       # Post-Exploitation Activities        └── l1.md

│   └── 01-shells.md               # Shell types & management```

│

├── 🧹 05-covering-tracks/          # Evidence Removal & Cleanup## Penetration Testing Methodology

│

├── 📖 90-cheat-sheets/            # Quick Reference GuidesThis repository follows the standard pentesting framework:

│   └── 01-getting-started-cheatsheet.md

│1. **Reconnaissance** - Passive & active information gathering

├── 🐧 91-linux/                   # Linux-Specific Resources2. **Scanning & Enumeration** - Network discovery, port scanning, service enumeration

│   ├── 01-linux.md               # Linux commands & techniques3. **Exploitation** - Gaining unauthorized access to systems

│   └── 02-kali.md                # Kali Linux specialized tools4. **Maintaining Access** - Establishing persistent access & lateral movement

│5. **Covering Tracks** - Evidence removal & cleanup procedures

├── 🐍 92-python/                  # Python for Penetration Testing

│   └── 01-python.md              # Python scripting reference## Getting Started

│

└── 🎓 99-training-boxes/          # Practice Environments1. Start with the `getting-started/` directory for essential tool setup

    ├── tryhackme/                 # TryHackMe walkthroughs2. Review `cheat-sheets/` for quick command references

    │   └── 01-basic-pentesting.md3. Follow the methodology phases in order: reconnaissance → scanning → exploitation

    └── kioptrix/                  # Kioptrix VM series4. Practice techniques using the `training-boxes/` environments

        └── 01-l1.md

```## Resources



## 🎯 Methodology Overview- **Bug Bounty**: www.bugcrowd.com

- **Practice Labs**: TryHackMe, Kioptrix VMs

This repository follows the **NIST Cybersecurity Framework** and **OWASP Testing Guide** principles:- **Tool Documentation**: Individual .md files contain comprehensive guides



### Phase 1: 🔍 Reconnaissance (01-reconnaissance/)## Project Structure for Engagements

- **Passive Information Gathering**: OSINT, public records, social media

- **Active Information Gathering**: DNS enumeration, network scanning```

- **Target Profiling**: Infrastructure mapping, technology identificationproject_name/

├── evidence/

### Phase 2: 🎯 Scanning & Enumeration (02-scanning-enumeration/)│   ├── credentials/

- **Network Discovery**: Host identification, port scanning│   ├── data/

- **Service Enumeration**: Service fingerprinting, version detection│   └── screenshots/

- **Vulnerability Assessment**: Automated and manual vulnerability discovery├── logs/

├── scans/

### Phase 3: 💥 Exploitation (03-exploitation/)├── scope/

- **Vulnerability Exploitation**: Proof-of-concept attacks└── tools/

- **Credential Attacks**: Password attacks, hash cracking```

- **Privilege Escalation**: Local and remote privilege escalation

## Contributing

### Phase 4: 🔒 Maintaining Access (04-maintaining-access/)

- **Persistence Mechanisms**: Backdoors, scheduled tasksWhen adding new content:

- **Lateral Movement**: Network traversal, credential harvesting- Use lowercase filenames with hyphens for spaces

- **Data Exfiltration**: Secure data extraction techniques- Follow the existing markdown table format

- Include practical examples and command syntax

### Phase 5: 🧹 Covering Tracks (05-covering-tracks/)- Test all commands before documenting

- **Log Manipulation**: Event log clearing, timestamp modification

- **Artifact Removal**: Tool cleanup, evidence elimination---

- **Steganography**: Covert communication channels

*Last updated: October 2025*
## 📚 Learning Path

### 🌱 Beginner (Start Here)
1. **Prerequisites**: `00-getting-started/` - Master essential tools
2. **Fundamentals**: `90-cheat-sheets/` - Quick reference guides
3. **Linux Basics**: `91-linux/01-linux.md` - Command line proficiency

### 🌿 Intermediate
1. **Methodology**: Follow `01-` through `05-` in sequence
2. **Hands-on Practice**: `99-training-boxes/` environments
3. **Specialized Tools**: `91-linux/02-kali.md`, `92-python/`

### 🌳 Advanced
1. **Custom Exploitation**: Develop custom payloads and scripts
2. **Advanced Persistence**: Rootkit development, firmware attacks
3. **Research**: Contribute new techniques and methodologies

## 🛠️ Tool References

Each folder contains comprehensive tool documentation with:

- ✅ **Installation Instructions**: Platform-specific setup guides
- 📋 **Command Syntax**: Detailed usage examples with parameters
- 🎯 **Use Cases**: Real-world application scenarios  
- ⚠️ **Security Considerations**: Legal and ethical guidelines
- 🔗 **Additional Resources**: Official documentation and tutorials

### Featured Tools by Category

| Category | Tools | Documentation |
|----------|-------|---------------|
| **Network Scanning** | Nmap, Masscan, Zmap | `02-scanning-enumeration/02-nmap.md` |
| **Web Testing** | Burp Suite, OWASP ZAP, Nikto | `01-reconnaissance/04-burp-suite.md` |
| **Password Attacks** | Hydra, John, Hashcat | `03-exploitation/02-password-cracking.md` |
| **Privilege Escalation** | LinPEAS, WinPEAS, PEASS-ng | `03-exploitation/03-privilege-escalation.md` |
| **Post-Exploitation** | Metasploit, Cobalt Strike, Empire | `04-maintaining-access/01-shells.md` |

## 🏆 Training Labs

### Platform Coverage
- 🔴 **TryHackMe**: Guided learning paths with detailed walkthroughs
- 🔵 **Hack The Box**: Advanced machine exploitation techniques  
- 🟡 **VulnHub**: Downloadable vulnerable VMs (Kioptrix series)
- 🟢 **OverTheWire**: Wargames and capture-the-flag challenges

### Lab Environment Setup
```bash
# Recommended setup for safe testing
# 1. Isolated network environment (VMware/VirtualBox)
# 2. Kali Linux attackers machine
# 3. Vulnerable target systems
# 4. Network monitoring tools (Wireshark, tcpdump)
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community! 

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-technique`)
3. **Follow** the numbering convention for new files
4. **Document** all commands with examples and explanations
5. **Test** all procedures in a safe environment
6. **Submit** a pull request with detailed description

### Contribution Guidelines
- ✅ Use professional, educational tone
- ✅ Include practical examples and command syntax
- ✅ Verify all techniques in controlled environments
- ✅ Follow responsible disclosure for new vulnerabilities
- ❌ No illegal activities or malicious code
- ❌ No personally identifiable information (PII)

## ⚖️ Legal Disclaimer

> **⚠️ IMPORTANT LEGAL NOTICE**

This repository is intended **exclusively for educational purposes** and **authorized penetration testing** activities. 

### Authorized Use Only
- ✅ **Educational Learning**: Academic research and skill development
- ✅ **Authorized Testing**: Penetration testing with explicit written permission
- ✅ **Security Research**: Responsible vulnerability research and disclosure
- ✅ **Capture The Flag**: CTF competitions and training environments

### Prohibited Activities  
- ❌ **Unauthorized Access**: Testing without explicit written permission
- ❌ **Malicious Intent**: Any form of cybercrime or illegal activity
- ❌ **Production Systems**: Testing on systems you don't own or control
- ❌ **Data Theft**: Unauthorized data access, modification, or exfiltration

### Legal Responsibility
Users are **solely responsible** for ensuring their activities comply with:
- Local, state, and federal laws
- Organizational policies and procedures  
- International cybersecurity regulations
- Ethical hacking guidelines and standards

**The repository maintainers assume NO liability** for misuse of this information.

## 🙏 Acknowledgments

### 🤖 AI-Assisted Development
This comprehensive penetration testing resource was developed with significant assistance from **GitHub Copilot AI**. The AI contributed to:

- 📋 **Content Organization**: Structured methodology and logical file organization
- 📝 **Documentation Creation**: Comprehensive guides and command references  
- 🔢 **Numbering System**: Industry-standard methodology sequencing
- 🛠️ **Tool Integration**: Cross-referenced techniques and tool relationships
- ✅ **Quality Assurance**: Consistency checks and formatting standardization

The combination of human expertise and AI assistance has created a more comprehensive, accessible, and well-organized learning resource for the cybersecurity community.

### 🌟 Community Contributors
- **Security Researchers**: For sharing techniques and methodologies
- **Open Source Community**: For developing and maintaining essential tools
- **Educational Platforms**: TryHackMe, Hack The Box, VulnHub for practice environments
- **Standards Organizations**: NIST, OWASP, SANS for framework development

### 📚 Educational Resources
- **Bug Bounty Platforms**: [Bugcrowd](https://www.bugcrowd.com), HackerOne for real-world experience
- **Certification Bodies**: EC-Council, (ISC)², CompTIA for professional standards
- **Academic Institutions**: Universities and training centers advancing cybersecurity education

---

## 📞 Contact & Support

- **Repository Issues**: [GitHub Issues](https://github.com/cairanvanrooyen/penetration_testing/issues)
- **Security Vulnerabilities**: Please report responsibly via private communication
- **Educational Questions**: Community discussions welcome in GitHub Discussions

---

**🔐 Happy Ethical Hacking! 🔐**

*Remember: With great power comes great responsibility. Use these skills to make the digital world more secure.*

---

*Last updated: October 2025 | Version: 2.0 | AI-Enhanced Documentation*
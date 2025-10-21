# Network Ports and Protocols2 types of port:

1. Transmission control protocol (TCP) - connection oriented. Needs connection between client and server.

Essential network ports and protocols commonly encountered during penetration testing and security assessments.2. User datagram protocol (UDP) - connectionless. No handshake. No guarantee of delivery



## Overview| Port(s)         | Protocol              |

| --------------- | --------------------- |

Network ports are communication endpoints that applications use to establish connections and exchange data. Understanding common ports and their associated services is fundamental for network reconnaissance, vulnerability assessment, and penetration testing.| `20`/`21` (TCP) | `FTP`                 |

| `22` (TCP)      | `SSH`                 |

## Port Types| `23` (TCP)      | `Telnet`              |

| `25` (TCP)      | `SMTP`                |

| Protocol Type | Description | Characteristics || `80` (TCP)      | `HTTP`                |

|---------------|-------------|-----------------|| `161` (TCP/UDP) | `SNMP`                |

| **TCP (Transmission Control Protocol)** | Connection-oriented protocol | Reliable delivery, error checking, ordered data || `389` (TCP/UDP) | `LDAP`                |

| **UDP (User Datagram Protocol)** | Connectionless protocol | Fast transmission, no delivery guarantee || `443` (TCP)     | `SSL`/`TLS` (`HTTPS`) |

| `445` (TCP)     | `SMB`                 |

### TCP vs UDP| `3389` (TCP)    | `RDP`                 |

Common port cheatlist: 

**TCP Features**:https://www.stationx.net/common-ports-cheat-sheet/

- Connection establishment (3-way handshake)https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf

- Error checking and recoveryTop 1000 TCP and UDP ports: https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
- Flow control and congestion control
- Guaranteed delivery and ordering

**UDP Features**:
- No connection establishment required
- Minimal overhead and faster transmission
- No delivery or ordering guarantees
- Suitable for real-time applications

## Common Network Ports

| Port(s) | Protocol | Service | Description |
|---------|----------|---------|-------------|
| **20/21** | TCP | **FTP** | File Transfer Protocol (20: data, 21: control) |
| **22** | TCP | **SSH** | Secure Shell - encrypted remote access |
| **23** | TCP | **Telnet** | Unencrypted remote terminal access |
| **25** | TCP | **SMTP** | Simple Mail Transfer Protocol |
| **53** | TCP/UDP | **DNS** | Domain Name System |
| **67/68** | UDP | **DHCP** | Dynamic Host Configuration Protocol |
| **69** | UDP | **TFTP** | Trivial File Transfer Protocol |
| **80** | TCP | **HTTP** | Hypertext Transfer Protocol |
| **110** | TCP | **POP3** | Post Office Protocol v3 |
| **143** | TCP | **IMAP** | Internet Message Access Protocol |
| **161/162** | UDP | **SNMP** | Simple Network Management Protocol |
| **389** | TCP/UDP | **LDAP** | Lightweight Directory Access Protocol |
| **443** | TCP | **HTTPS** | HTTP over SSL/TLS |
| **445** | TCP | **SMB** | Server Message Block |
| **993** | TCP | **IMAPS** | IMAP over SSL |
| **995** | TCP | **POP3S** | POP3 over SSL |
| **3389** | TCP | **RDP** | Remote Desktop Protocol |

## Security Implications

### High-Risk Ports

| Port | Service | Security Concerns |
|------|---------|-------------------|
| **21** | FTP | Unencrypted data transfer, anonymous access |
| **23** | Telnet | Plaintext authentication and communication |
| **135** | RPC | Windows RPC vulnerabilities |
| **139/445** | NetBIOS/SMB | Network share enumeration, null sessions |
| **1433** | MSSQL | Database access, injection attacks |
| **3306** | MySQL | Database vulnerabilities |
| **5432** | PostgreSQL | Database security issues |

### Commonly Targeted Ports

**Web Services**:
- 80 (HTTP) - Web application vulnerabilities
- 443 (HTTPS) - SSL/TLS misconfigurations
- 8080/8443 - Alternative web ports

**Remote Access**:
- 22 (SSH) - Brute force attacks, key management
- 3389 (RDP) - Password attacks, vulnerabilities
- 5900+ (VNC) - Weak authentication

**Database Services**:
- 1433 (MSSQL) - SQL injection, weak authentication
- 3306 (MySQL) - Configuration issues
- 5432 (PostgreSQL) - Access control problems

## Port Scanning Implications

### Open Port Discovery

| Discovery Method | Tools | Purpose |
|------------------|-------|---------|
| **TCP Connect Scan** | nmap -sT | Full connection establishment |
| **SYN Scan** | nmap -sS | Stealth scanning technique |
| **UDP Scan** | nmap -sU | Discover UDP services |
| **Service Detection** | nmap -sV | Identify service versions |

### Common Scan Targets

**Top 1000 Ports**: Most frequently scanned ports by default tools
**Well-Known Ports**: 0-1023 (system/privileged ports)
**Registered Ports**: 1024-49151 (user/application ports)
**Dynamic Ports**: 49152-65535 (ephemeral/private ports)

## Security Considerations

### Legal and Ethical Guidelines

- Only scan networks you're authorized to test
- Understand local laws regarding port scanning
- Follow responsible disclosure for discovered vulnerabilities
- Document all scanning activities for audit trails
- Respect network resources and bandwidth

### Best Practices

| Practice | Purpose | Implementation |
|----------|---------|---------------|
| **Rate limiting** | Avoid network disruption | Throttle scan speed |
| **Target specificity** | Minimize scope creep | Define clear boundaries |
| **Service enumeration** | Accurate assessment | Version detection |
| **Documentation** | Audit trail maintenance | Detailed logging |

## Defensive Measures

### Port Security Controls

| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Firewall rules** | Block unnecessary ports | Iptables, pfSense |
| **Service hardening** | Reduce attack surface | Disable unused services |
| **Port monitoring** | Detect unauthorized access | Network monitoring tools |
| **Access controls** | Limit service access | Authentication mechanisms |

## Additional Resources

- [Common Ports Cheat Sheet - StationX](https://www.stationx.net/common-ports-cheat-sheet/)
- [PacketLife Common Ports Reference](https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf)
- [Top 1000 TCP and UDP Ports - NullSec](https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/)
- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/)
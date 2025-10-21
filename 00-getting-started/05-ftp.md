# FTP (File Transfer Protocol)

Network protocol for transferring files between client and server, commonly found on ports 20-21 during penetration testing.

## Overview

FTP is a standard network protocol used for file transfer between systems. During penetration testing, FTP services are often discovered and can provide valuable attack vectors, especially when misconfigured or running with anonymous access.

## Basic FTP Client Usage

| Command | Description | Example |
|---------|-------------|---------|
| `ftp hostname` | Connect to FTP server | `ftp 192.168.1.100` |
| `ftp -p hostname` | Connect using passive mode | `ftp -p 192.168.1.100` |
| `anonymous` | Login as anonymous user | Username: `anonymous` |
| `ls` | List directory contents | `ls -la` |
| `cd directory` | Change directory | `cd /pub` |
| `get filename` | Download file | `get passwords.txt` |
| `put filename` | Upload file | `put exploit.sh` |
| `mget pattern` | Download multiple files | `mget *.txt` |
| `quit` | Exit FTP session | `quit` |

## Common FTP Commands

| Command | Description |
|---------|-------------|
| `pwd` | Print working directory |
| `mkdir dirname` | Create directory |
| `rmdir dirname` | Remove directory |
| `delete filename` | Delete file |
| `rename old new` | Rename file |
| `chmod 755 file` | Change file permissions |
| `binary` | Set binary transfer mode |
| `ascii` | Set ASCII transfer mode |

## Alternative FTP Clients

### lftp (Advanced)

| Command | Description | Example |
|---------|-------------|---------|
| `lftp ftp://user@host` | Connect with URL | `lftp ftp://admin@192.168.1.100` |
| `mirror` | Synchronize directories | `mirror /remote/dir /local/dir` |
| `mput -c *.txt` | Upload with resume | `mput -c *.txt` |
| `parallel 4` | Set parallel connections | `parallel 4` |

### sftp (Secure FTP)

| Command | Description | Example |
|---------|-------------|---------|
| `sftp user@host` | Connect via SSH | `sftp admin@192.168.1.100` |
| `get remote local` | Download securely | `get /etc/passwd ./passwd` |
| `put local remote` | Upload securely | `put exploit.py /tmp/` |

## FTP Enumeration for Penetration Testing

### Service Detection

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -p 21 target` | Check if FTP port is open | `nmap -p 21 192.168.1.0/24` |
| `nmap -sC -sV -p 21 target` | Detect FTP version/info | `nmap -sC -sV -p 21 192.168.1.100` |
| `telnet host 21` | Manual banner grabbing | `telnet 192.168.1.100 21` |

### Anonymous Access Testing

```bash
# Test anonymous login
ftp 192.168.1.100
# Username: anonymous
# Password: (blank or email)
```

### Common Misconfigurations

| Vulnerability | Description | Risk |
|---------------|-------------|------|
| **Anonymous access** | Login without credentials | Information disclosure |
| **Writable directories** | Anonymous upload capability | Malware staging |
| **Directory traversal** | Access to sensitive files | Data exposure |
| **Weak credentials** | Default/weak passwords | Unauthorized access |

## Security Considerations

- FTP transmits credentials in plaintext - avoid on production networks
- Anonymous FTP should be carefully configured if needed
- Use FTPS (FTP over SSL/TLS) or SFTP for secure transfers
- Monitor FTP logs for unauthorized access attempts
- Implement proper access controls and directory restrictions

## Penetration Testing Notes

- Always test for anonymous access first
- Look for writable directories that could host malicious files
- Check for directory traversal vulnerabilities
- Attempt common credential combinations
- Download interesting files for further analysis

## Additional Resources

- [RFC 959 - FTP Protocol](https://tools.ietf.org/html/rfc959)
- [FTP Security Considerations](https://www.sans.org/reading-room/whitepapers/protocols/ftp-security-36192)
- [vsftpd Configuration Guide](https://security.appspot.com/vsftpd.html)

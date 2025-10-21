# Linux Penetration Testing Reference

## Introduction

This comprehensive guide covers essential Linux commands and techniques for penetration testing and cybersecurity professionals. Linux is the foundation of most penetration testing distributions and understanding its command-line interface is crucial for effective security assessments.

This reference is organized into practical sections covering file system navigation, user enumeration, networking, privilege escalation, and system monitoring. Each section includes both modern and legacy commands to ensure compatibility across different Linux distributions and versions.

Whether you're conducting reconnaissance, post-exploitation enumeration, or maintaining persistence, these commands will serve as your go-to reference for Linux-based security testing.

## Essential Resources
- **explainshell.com** - Explains shell commands in detail

## File System Navigation & Management

### Basic File Operations

| Command | Description |
|---------|-------------|
| `ls -la` | List all files (including hidden) |
| `ls --help` | Get help for ls command |
| `pwd` | Print working directory |
| `cd /path/to/directory` | Change directory |
| `cd ~` | Go to home directory |
| `cd -` | Go to previous directory |

### File Search & Location

| Command | Description |
|---------|-------------|
| `updatedb` | Update file database |
| `locate filename` | Locate file in database |
| `find /path -name "*.txt"` | Find files by name pattern |
| `find /path -type f -size +1M` | Find files larger than 1MB |
| `which command` | Find location of command |
| `whereis command` | Find binary, source, manual for command |

### File Permissions & Ownership

#### Understanding File Permissions
File permissions in Linux use a 3-digit octal system where each digit represents permissions for:
- **First digit**: Owner (user) permissions
- **Second digit**: Group permissions  
- **Third digit**: Other (world) permissions

#### Permission Values Table

| Number | Binary | Permissions | Symbol | Description |
|--------|--------|-------------|--------|-------------|
| 0      | 000    | ---         | ---    | No permissions |
| 1      | 001    | --x         | --x    | Execute only |
| 2      | 010    | -w-         | -w-    | Write only |
| 3      | 011    | -wx         | -wx    | Write + Execute |
| 4      | 100    | r--         | r--    | Read only |
| 5      | 101    | r-x         | r-x    | Read + Execute |
| 6      | 110    | rw-         | rw-    | Read + Write |
| 7      | 111    | rwx         | rwx    | Read + Write + Execute |

#### Common Permission Combinations

| chmod | Owner | Group | Other | Use Case |
|-------|-------|-------|-------|----------|
| 644   | rw-   | r--   | r--   | Regular files (documents, configs) |
| 755   | rwx   | r-x   | r-x   | Executable files, directories |
| 700   | rwx   | ---   | ---   | Private files/directories |
| 777   | rwx   | rwx   | rwx   | Full access (security risk) |
| 600   | rw-   | ---   | ---   | Private files (SSH keys) |
| 664   | rw-   | rw-   | r--   | Group-writable files |
| 775   | rwx   | rwx   | r-x   | Group-writable directories |
| 4755  | rwsr-x| r-x   | r-x   | SUID executable |
| 2755  | rwxr-s| r-x   | r-x   | SGID executable |

#### Special Permissions

| Permission | Symbol | Octal | Description |
|------------|--------|-------|-------------|
| SUID       | s (user)| 4000 | Run as file owner |
| SGID       | s (group)| 2000| Run as file group |
| Sticky Bit | t       | 1000 | Only owner can delete |

#### chmod Commands

| Command | Description |
|---------|-------------|
| `chmod 755 file` | Change file permissions (rwxr-xr-x) |
| `chmod 777 file` | Full permissions (rwxrwxrwx) |
| `chmod +x script.sh` | Make file executable |
| `chmod u+x file` | Add execute for owner |
| `chmod g-w file` | Remove write for group |
| `chmod o=r file` | Set other to read only |
| `chmod a+r file` | Add read for all (a=all) |
| `chown user:group file` | Change file ownership |
| `umask 022` | Set default permissions |

### Important Directories for Pentesting
- `/tmp/` - World-writable directory (easy write access)
- `/var/log/` - System logs
- `/etc/passwd` - User accounts
- `/etc/shadow` - Password hashes
- `/etc/sudoers` - Sudo permissions
- `/home/` - User home directories
- `/opt/` - Optional software packages

## User & System Information

### User Management

| Command | Description |
|---------|-------------|
| `whoami` | Current username |
| `id` | User and group IDs |
| `users` | Currently logged in users |
| `w` | Who is logged in and what they're doing |
| `last` | Last logged in users |
| `adduser username` | Add new user |
| `passwd username` | Change user password |
| `su username` | Switch to user |
| `sudo -u username command` | Run command as user |
| `sudo -l` | List sudo permissions |

### System Information

| Command | Description |
|---------|-------------|
| `uname -a` | System information |
| `hostname` | System hostname |
| `uptime` | System uptime and load |
| `ps aux` | Running processes |
| `top` | Real-time process viewer |
| `htop` | Enhanced process viewer |
| `df -h` | Disk space usage |
| `free -h` | Memory usage |
| `lscpu` | CPU information |
| `lsusb` | USB devices |
| `lspci` | PCI devices |

### Important Files for Enumeration

| Command | Description |
|---------|-------------|
| `cat /etc/passwd` | User accounts |
| `cat /etc/group` | Group information |
| `cat /etc/sudoers` | Sudo configuration |
| `cat /etc/crontab` | Scheduled tasks |
| `cat /etc/hosts` | Host file |
| `cat /proc/version` | Kernel version |
| `cat /etc/issue` | OS version |
| `cat /etc/os-release` | Detailed OS information |

## Networking Commands

### Network Configuration

| Command | Description |
|---------|-------------|
| `ip a` | Show all network interfaces (modern) |
| `ip addr show` | Detailed interface information |
| `ifconfig` | Network interfaces (legacy) |
| `iwconfig` | Wireless interfaces |
| `ip link show` | Physical interfaces |

### Network Discovery

| Command | Description |
|---------|-------------|
| `ip n` | Show ARP table (neighbors) |
| `arp -a` | ARP table (legacy) |
| `ip r` | Show routing table |
| `route -n` | Routing table (legacy) |
| `netstat -rn` | Routing table |
| `ss -tuln` | Show listening ports (modern) |
| `netstat -tuln` | Show listening ports (legacy) |

### Network Testing

| Command | Description |
|---------|-------------|
| `ping -c 4 host` | Ping with count limit |
| `ping6 host` | IPv6 ping |
| `traceroute host` | Trace route to host |
| `nslookup domain` | DNS lookup |
| `dig domain` | DNS lookup (detailed) |
| `host domain` | Simple DNS lookup |

### VPN & Remote Connections

| Command | Description |
|---------|-------------|
| `sudo openvpn user.ovpn` | Connect to VPN |
| `ifconfig / ip a` | Show our IP address |
| `netstat -rn` | Show networks accessible via the VPN |
| `ssh user@10.10.10.10` | SSH to a remote server |
| `ftp 10.129.42.253` | FTP to a remote server |

#### Additional Remote Connection Commands

| Command | Description |
|---------|-------------|
| `scp file user@host:/path/` | Copy file to remote host |
| `scp user@host:/path/file .` | Copy file from remote host |
| `rsync -av local/ user@host:remote/` | Sync directories |
| `ssh -L 8080:localhost:80 user@host` | SSH port forwarding |
| `ssh -D 1080 user@host` | SSH SOCKS proxy |
| `telnet host port` | Telnet connection |
| `nc host port` | Netcat connection |

## Text Processing & File Operations

### Text Manipulation

| Command | Description |
|---------|-------------|
| `grep pattern file` | Search for pattern in file |
| `grep -r pattern dir` | Recursive search |
| `grep -i pattern file` | Case-insensitive search |
| `grep -v pattern file` | Invert match (exclude pattern) |
| `cut -d " " -f 4 file` | Cut field 4 using space delimiter |
| `tr -d ":"` | Delete colons from input |
| `sort file` | Sort lines in file |
| `uniq file` | Remove duplicate lines |
| `wc -l file` | Count lines in file |

### File I/O Redirection

| Command | Description |
|---------|-------------|
| `echo "text" > file` | Overwrite file with text |
| `echo "text" >> file` | Append text to file |
| `command > file` | Redirect stdout to file |
| `command 2> file` | Redirect stderr to file |
| `command &> file` | Redirect both stdout and stderr |
| `command \| tee file` | Write to both stdout and file |

### File Creation & Editing

| Command | Description |
|---------|-------------|
| `touch filename` | Create empty file or update timestamp |
| `nano filename` | Simple text editor |
| `vim filename` | Advanced text editor |
| `gedit filename` | GUI text editor |
| `mousepad filename` | Lightweight GUI editor |

## Service Management

### Systemd Services (Modern)

| Command | Description |
|---------|-------------|
| `sudo systemctl start service` | Start service |
| `sudo systemctl stop service` | Stop service |
| `sudo systemctl restart service` | Restart service |
| `sudo systemctl enable service` | Enable service at boot |
| `sudo systemctl disable service` | Disable service at boot |
| `sudo systemctl status service` | Check service status |
| `systemctl list-units --type=service` | List all services |

### Legacy Service Management

| Command | Description |
|---------|-------------|
| `sudo service ssh start` | Start SSH service |
| `sudo service ssh stop` | Stop SSH service |
| `sudo service ssh restart` | Restart SSH service |
| `sudo service ssh status` | Check SSH status |

## Package Management

### Debian/Ubuntu (APT)

| Command | Description |
|---------|-------------|
| `sudo apt update` | Update package list |
| `sudo apt upgrade` | Upgrade packages |
| `sudo apt install package` | Install package |
| `sudo apt remove package` | Remove package |
| `sudo apt search package` | Search for package |
| `dpkg -l` | List installed packages |
| `dpkg -i package.deb` | Install .deb package |

### Red Hat/CentOS (YUM/DNF)

| Command | Description |
|---------|-------------|
| `sudo yum update` | Update packages (RHEL 7) |
| `sudo dnf update` | Update packages (RHEL 8+) |
| `sudo yum install package` | Install package |
| `sudo dnf install package` | Install package (RHEL 8+) |

## Useful Tools & Servers

### Python HTTP Server

| Command | Description |
|---------|-------------|
| `python3 -m http.server 80` | Start HTTP server on port 80 |
| `python3 -m http.server 8000` | Start HTTP server on port 8000 |

### SSH Configuration

| Command | Description |
|---------|-------------|
| `sudo systemctl enable ssh` | Enable SSH service at boot |
| `sudo systemctl start ssh` | Start SSH service |
| `ssh user@host` | Connect to remote host |
| `ssh -p 2222 user@host` | Connect using specific port |
| `scp file user@host:/path/` | Copy file to remote host |

## Scripting & Automation

### Variables and Environment

#### Setting and Using Variables

| Command | Description |
|---------|-------------|
| `IP=10.10.10.100` | Set IP address as variable |
| `TARGET=192.168.1.50` | Set target IP as variable |
| `echo $IP` | Display IP variable value |
| `echo $TARGET` | Display target variable value |
| `ping $IP` | Use IP variable in command |
| `nmap $TARGET` | Use target variable in command |
| `ssh user@$IP` | Use variable in SSH connection |
| `export IP=10.10.10.100` | Export variable for sub-processes |

#### Advanced Variable Usage

| Command | Description |
|---------|-------------|
| `SUBNET=192.168.1` | Set subnet variable |
| `PORT=8080` | Set port variable |
| `USER=administrator` | Set username variable |
| `PASS=password123` | Set password variable |
| `echo "Scanning $IP on port $PORT"` | Use multiple variables |
| `nmap -p $PORT $IP` | Combine variables in commands |
| `smbclient //$IP/C$ -U $USER` | Use variables for SMB connection |
| `gobuster dir -u http://$IP:$PORT/ -w wordlist.txt` | Use variables in web enumeration |

#### Variable Persistence

| Command | Description |
|---------|-------------|
| `echo 'export IP=10.10.10.100' >> ~/.bashrc` | Make variable permanent |
| `source ~/.bashrc` | Reload bash configuration |
| `env \| grep IP` | Check if variable is set |
| `unset IP` | Remove variable |
| `readonly IP=10.10.10.100` | Create read-only variable |

#### Practical Examples for Pentesting

| Command | Description |
|---------|-------------|
| `IP=10.10.10.100; nmap -sC -sV $IP` | Set IP and run Nmap scan |
| `TARGET=example.com; dig $TARGET` | Set domain and run DNS lookup |
| `IP=192.168.1.50; gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/common.txt` | Web directory enumeration |
| `HOST=10.10.10.100; smbclient -L //$HOST -N` | SMB share enumeration |
| `IP=10.10.10.100; PORT=80; curl -I http://$IP:$PORT` | HTTP header check |
| `TARGET=10.10.10.100; hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$TARGET` | SSH brute force |

### Ping Sweep Script
```bash
#!/bin/bash
# File: pingsweep.sh

if [ "$1" == "" ]; then
    echo "Usage: $0 <network_prefix>"
    echo "Example: $0 192.168.1"
    exit 1
fi

echo "Scanning network $1.1-254..."

for ip in $(seq 1 254); do
    ping -c 1 -W 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done

wait
echo "Scan complete."
```

### Usage Examples

| Command | Description |
|---------|-------------|
| `chmod +x pingsweep.sh` | Make script executable |
| `./pingsweep.sh 192.168.1` | Run ping sweep |
| `./pingsweep.sh 192.168.1 > live_hosts.txt` | Save results to file |

## Privilege Escalation Enumeration

### SUID/SGID Files

| Command | Description |
|---------|-------------|
| `find / -perm -4000 -type f 2>/dev/null` | Find SUID files |
| `find / -perm -2000 -type f 2>/dev/null` | Find SGID files |
| `find / -perm -1000 -type d 2>/dev/null` | Find sticky bit directories |

### Writable Files/Directories

| Command | Description |
|---------|-------------|
| `find / -writable -type f 2>/dev/null` | Find writable files |
| `find / -writable -type d 2>/dev/null` | Find writable directories |
| `find /etc -writable -type f 2>/dev/null` | Writable files in /etc |

### Scheduled Tasks

| Command | Description |
|---------|-------------|
| `cat /etc/crontab` | System crontab |
| `ls -la /etc/cron.*` | Cron directories |
| `crontab -l` | Current user's crontab |

### Environment Variables

| Command | Description |
|---------|-------------|
| `env` | Show environment variables |
| `echo $PATH` | Show PATH variable |
| `echo $HOME` | Show home directory |
| `printenv` | Print environment |

## Log Analysis

### Important Log Files

| Command | Description |
|---------|-------------|
| `tail -f /var/log/syslog` | Follow system log |
| `tail -f /var/log/auth.log` | Follow authentication log |
| `tail -f /var/log/apache2/access.log` | Follow Apache access log |
| `grep "Failed password" /var/log/auth.log` | Find failed login attempts |
| `journalctl -f` | Follow systemd logs |
| `journalctl -u ssh` | SSH service logs |

## Network Monitoring

### Active Connections

| Command | Description |
|---------|-------------|
| `ss -tuln` | Show listening ports |
| `ss -tulpn` | Show listening ports with processes |
| `netstat -tuln` | Legacy: show listening ports |
| `netstat -tulpn` | Legacy: show ports with processes |
| `lsof -i` | Show network connections |
| `lsof -i :22` | Show connections on port 22 |

### Process Monitoring

| Command | Description |
|---------|-------------|
| `ps aux \| grep ssh` | Find SSH processes |
| `pgrep ssh` | Get SSH process IDs |
| `pkill process_name` | Kill process by name |
| `kill -9 PID` | Force kill process |
| `jobs` | Show background jobs |
| `nohup command &` | Run command immune to hangups |




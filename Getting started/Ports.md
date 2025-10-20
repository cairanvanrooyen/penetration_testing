2 types of port:
1. Transmission control protocol (TCP) - connection oriented. Needs connection between client and server.
2. User datagram protocol (UDP) - connectionless. No handshake. No guarantee of delivery

| Port(s)         | Protocol              |
| --------------- | --------------------- |
| `20`/`21` (TCP) | `FTP`                 |
| `22` (TCP)      | `SSH`                 |
| `23` (TCP)      | `Telnet`              |
| `25` (TCP)      | `SMTP`                |
| `80` (TCP)      | `HTTP`                |
| `161` (TCP/UDP) | `SNMP`                |
| `389` (TCP/UDP) | `LDAP`                |
| `443` (TCP)     | `SSL`/`TLS` (`HTTPS`) |
| `445` (TCP)     | `SMB`                 |
| `3389` (TCP)    | `RDP`                 |
Common port cheatlist: 
https://www.stationx.net/common-ports-cheat-sheet/
https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf
Top 1000 TCP and UDP ports: https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
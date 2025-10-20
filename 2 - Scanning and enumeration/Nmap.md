nmap 10.129.42.253 - scan 1,000 most common ports
-sC = more information
-sV = version scan
-p = scan all 65,535 ports

The syntax for running an Nmap script is `nmap --script <script name> -p<port> <host>`.

Banner grab = nmap -sV --script=banner <target>


| nmap 10.129.42.253                                       | Run nmap on an IP                               |
| nmap -sV -sC -p- 10.129.42.253                           | Nmap service/version + script scan on all ports |
| locate scripts/citrix                                    | List various available nmap scripts             |
| nmap --script smb-os-discovery.nse -p445 10.10.10.40     | Run an nmap script on an IP                     |
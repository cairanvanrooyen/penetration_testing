nmap 10.129.42.253 - scan 1,000 most common ports
-sC = more information
-sV = version scan
-p = scan all 65,535 ports

The syntax for running an Nmap script is `nmap --script <script name> -p<port> <host>`.

Banner grab = nmap -sV --script=banner <target>



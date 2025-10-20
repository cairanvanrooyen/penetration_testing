Gobuster tool for DNS, vhost and directory brute forcing

`gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt`

HTTP status code 200 = successful
HTTP status code 403 = forbidden access
HTTP status code 301 = redirected

[List of HTTP status codes](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)

Wordpress: `http://10.10.10.121/wordpress`

## DNS Subdomain enumeration

Install SecLists
````shell-session
git clone https://github.com/danielmiessler/SecLists

sudo apt install seclists -y
````

Add a DNS Server such as 1.1.1.1 to the `/etc/resolv.conf` file. We will target the domain `inlanefreight.com`

````shell-session
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
````

------
## Banner grabbing

Reveal specific application framework. Use cURL to retrieve server header information.

```shell-session
curl -IL https://www.inlanefreight.com
```

### Whatweb

Option for whole network

```shell-session
whatweb 10.10.10.121

whatweb --no-errors 10.10.10.0/24

```

### Certificates

Browse to and view cert:
`https://10.10.10.121/`

### Robots.txt

Can reveal private files and admin pages

### Source code

CTRL + U to view source code


Find all subdomains to main domains.

Tool sublist3r in Kali

Tool to probe a list of subdomains to check if they are live
https://github.com/tomnomnom/httprobe

Enumeration for sub domains
amass enum -d cairanvanrooyen.com                               

Wappalyzer app in Chrome

Tool whatwebb app in Kali

** dirbuster


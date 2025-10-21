# Python for Penetration Testing

Python programming language essentials for cybersecurity professionals and penetration testers.

## Overview

Python is one of the most popular programming languages in cybersecurity due to its simplicity, extensive libraries, and powerful capabilities for automation, exploitation, and tool development.

## Basic Python Concepts

### Data Types

| Type | Example | Usage |
|------|---------|-------|
| **String** | `"Hello World"` | Text manipulation |
| **Integer** | `42` | Numbers and calculations |
| **List** | `[1, 2, 3]` | Collections of items |
| **Dictionary** | `{"key": "value"}` | Key-value pairs |
| **Boolean** | `True/False` | Logical operations |

### Boolean Logic (Truth Tables)

| A | B | A and B | A or B | not A |
|---|---|---------|---------|-------|
| True | True | True | True | False |
| True | False | False | True | False |
| False | True | False | True | True |
| False | False | False | False | True |

## Essential Libraries for Penetration Testing

### Network Libraries

| Library | Purpose | Example |
|---------|---------|---------|
| **socket** | Network connections | `socket.socket()` |
| **requests** | HTTP requests | `requests.get(url)` |
| **urllib** | URL handling | `urllib.parse.urlparse()` |
| **scapy** | Packet manipulation | `scapy.IP()` |

## Common Penetration Testing Scripts

### Simple Port Scanner

```python
import socket

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port}: Open")
        sock.close()
    except:
        pass

host = "192.168.1.1"
for port in range(1, 1025):
    scan_port(host, port)
```

### HTTP Request Example

```python
import requests

# Basic GET request
response = requests.get("http://target.com")
print(response.status_code)
print(response.text)

# POST request with data
data = {"username": "admin", "password": "password"}
response = requests.post("http://target.com/login", data=data)
```

## File Operations

```python
# Read file safely
try:
    with open("wordlist.txt", "r") as file:
        passwords = file.read().splitlines()
        for password in passwords:
            print(password)
except FileNotFoundError:
    print("File not found")
```

## Security Considerations

- Always test in authorized environments only
- Use proper error handling in scripts
- Implement rate limiting to avoid detection
- Follow responsible disclosure practices

## Additional Resources

- [Python Official Documentation](https://docs.python.org/)
- [Violent Python Book](https://www.elsevier.com/books/violent-python/hutson/978-1-59749-957-6)
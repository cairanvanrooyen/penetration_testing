# Burp Suite Proxy Configuration

Web application security testing platform and intercepting proxy for analyzing and manipulating HTTP/HTTPS traffic.

## Overview

Burp Suite is the leading toolkit for web application security testing. It acts as an intercepting proxy between your browser and web applications, allowing you to capture, analyze, and modify HTTP requests and responses in real-time.

## Installation

### Burp Suite Community (Free)

```bash
# Download from official website
wget https://portswigger.net/burp/releases/community/latest
# Or install via package manager
sudo apt install burpsuite
```

### Burp Suite Professional

- Commercial license required
- Extended features including scanner and advanced tools
- Available from PortSwigger website

## Basic Setup

### Proxy Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| **Proxy listener** | 127.0.0.1:8080 | Default local proxy |
| **Browser proxy** | 127.0.0.1:8080 | Point browser to Burp |
| **Intercept** | On/Off | Control request interception |

### Browser Configuration

```bash
# Firefox proxy settings
# Manual proxy: 127.0.0.1:8080
# Use for all protocols
# No proxy for: (leave blank)

# Chrome with proxy
google-chrome --proxy-server=127.0.0.1:8080
```

### SSL Certificate Installation

1. Navigate to `http://burp` in configured browser
2. Download CA certificate
3. Install in browser certificate store
4. Trust for website identification

## Core Features

### Proxy Tab

| Function | Description | Use Case |
|----------|-------------|----------|
| **Intercept** | Pause and modify requests | Manipulate parameters |
| **HTTP History** | View all traffic | Analyze application flow |
| **WebSockets** | Real-time communication | Test modern web apps |
| **Options** | Configure proxy settings | Custom match/replace rules |

### Target Tab

| Feature | Purpose |
|---------|---------|
| **Site map** | Visual application structure |
| **Scope** | Define testing boundaries |
| **Issue definitions** | Understand vulnerabilities |

### Repeater Tab

| Function | Description |
|----------|-------------|
| **Request editing** | Modify and resend requests |
| **Response analysis** | Compare different responses |
| **Request templates** | Save common attack patterns |

## Common Testing Workflows

### Authentication Testing

| Test | Process |
|------|---------|
| **Credential capture** | Intercept login requests |
| **Session analysis** | Examine session tokens |
| **Forced browsing** | Test unauthorized access |

### Input Validation Testing

| Vulnerability | Test Method |
|---------------|-------------|
| **SQL Injection** | Single quotes in parameters |
| **XSS** | Script tags in input fields |
| **Path Traversal** | `../../../etc/passwd` in paths |
| **Command Injection** | Shell metacharacters |

### Session Management

| Test | Description |
|------|-------------|
| **Session fixation** | Test session ID handling |
| **Session timeout** | Verify automatic logout |
| **Concurrent sessions** | Multiple login testing |

## Advanced Features (Professional)

### Scanner

| Scan Type | Description | Use Case |
|-----------|-------------|----------|
| **Active scan** | Automated vulnerability testing | Comprehensive assessment |
| **Passive scan** | Traffic analysis only | Safe reconnaissance |
| **Custom insertion points** | Targeted parameter testing | Specific attack vectors |

### Intruder

| Attack Type | Description | Example |
|-------------|-------------|---------|
| **Sniper** | Single payload position | Password brute force |
| **Battering ram** | Same payload multiple positions | Session token testing |
| **Pitchfork** | Different payloads per position | Username/password pairs |
| **Cluster bomb** | All payload combinations | Comprehensive fuzzing |

## Extension Integration

### Popular Extensions

| Extension | Purpose |
|-----------|---------|
| **Active Scan++** | Additional vulnerability checks |
| **Autorize** | Authorization testing |
| **J2EEScan** | Java application testing |
| **Upload Scanner** | File upload vulnerability testing |

### Custom Extensions

```python
# Burp extension development
from burp import IBurpExtender

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Extension")
```

## Security Considerations

- Only test applications you're authorized to assess
- Be careful with automated scanning on production systems
- Understand the impact of active testing
- Use proper scoping to avoid testing unauthorized areas
- Keep Burp Suite updated for latest security features

## Best Practices

| Practice | Benefit |
|----------|---------|
| **Use project files** | Organize testing sessions |
| **Configure scope properly** | Focus testing efforts |
| **Save interesting requests** | Build attack library |
| **Document findings** | Maintain testing records |

## Troubleshooting

| Issue | Solution |
|-------|---------|
| **Certificate errors** | Properly install Burp CA certificate |
| **No traffic captured** | Verify browser proxy settings |
| **Application breaks** | Check for session handling issues |
| **Performance issues** | Adjust memory allocation |

## Additional Resources

- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Web Security Academy](https://portswigger.net/web-security)
- [Burp Extension Development](https://portswigger.net/burp/extender)

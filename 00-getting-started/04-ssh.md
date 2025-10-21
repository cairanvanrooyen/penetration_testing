# SSH (Secure Shell)

Cryptographic network protocol for secure communication and remote access, running on port 22 by default.

## Overview

SSH provides encrypted communication between networked devices and is essential for penetration testers to access remote systems securely. It's commonly used for remote administration, file transfers, and tunneling traffic.

## Basic Usage

| Command | Description | Example |
|---------|-------------|---------|
| `ssh user@host` | Connect to remote host | `ssh admin@192.168.1.100` |
| `ssh -p port user@host` | Connect using custom port | `ssh -p 2222 admin@192.168.1.100` |
| `ssh -i keyfile user@host` | Connect using private key | `ssh -i ~/.ssh/id_rsa user@host` |
| `ssh-keygen -t rsa` | Generate SSH key pair | `ssh-keygen -t rsa -b 4096` |
| `ssh-copy-id user@host` | Copy public key to remote | `ssh-copy-id user@192.168.1.100` |

## File Transfer

| Command | Description | Example |
|---------|-------------|---------|
| `scp file user@host:/path` | Copy file to remote | `scp data.txt user@host:/tmp/` |
| `scp user@host:/path/file .` | Copy file from remote | `scp user@host:/etc/passwd .` |
| `scp -r folder user@host:/path` | Copy folder recursively | `scp -r tools/ user@host:/tmp/` |
| `sftp user@host` | Interactive file transfer | `sftp admin@192.168.1.100` |

## Tunneling and Port Forwarding

| Command | Description | Example |
|---------|-------------|---------|
| `ssh -L local:remote user@host` | Local port forwarding | `ssh -L 8080:localhost:80 user@host` |
| `ssh -R remote:local user@host` | Remote port forwarding | `ssh -R 9999:localhost:22 user@host` |
| `ssh -D port user@host` | Dynamic port forwarding (SOCKS) | `ssh -D 1080 user@host` |
| `ssh -N -L port:host:port user@gateway` | Create tunnel without shell | `ssh -N -L 3389:target:3389 user@gateway` |

## Configuration

### Client Configuration (`~/.ssh/config`)

```bash
Host target
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/target_key
    
Host jump
    HostName jumpserver.example.com
    User pentester
    ProxyCommand ssh -W %h:%p gateway
```

### Key Management

| Command | Description | Example |
|---------|-------------|---------|
| `ssh-keygen -t ed25519` | Generate modern key type | `ssh-keygen -t ed25519 -C "comment"` |
| `ssh-add keyfile` | Add key to SSH agent | `ssh-add ~/.ssh/id_rsa` |
| `ssh-add -l` | List loaded keys | `ssh-add -l` |
| `chmod 600 keyfile` | Set proper key permissions | `chmod 600 ~/.ssh/id_rsa` |

## Security Considerations

- Always verify host fingerprints on first connection
- Use key-based authentication instead of passwords
- Disable root login and password authentication when possible
- Monitor SSH logs for unauthorized access attempts
- Use jump hosts for accessing internal networks

## Common Issues

| Problem | Solution |
|---------|----------|
| Permission denied | Check key permissions (600) and ownership |
| Host key verification failed | Remove old key with `ssh-keygen -R hostname` |
| Connection timeout | Check firewall rules and SSH service status |
| Agent forwarding issues | Use `-A` flag or configure `ForwardAgent yes` |

## Additional Resources

- [OpenSSH Manual](https://man.openbsd.org/ssh)
- [SSH Academy](https://www.ssh.com/academy/ssh)
- [SSH Security Best Practices](https://infosec.mozilla.org/guidelines/openssh)
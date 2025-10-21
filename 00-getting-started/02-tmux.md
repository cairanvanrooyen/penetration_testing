# Tmux Terminal Multiplexer

Terminal multiplexer allowing multiple terminal sessions within a single terminal window, essential for managing long-running penetration testing tasks.

## Overview

Tmux enables you to create, access, and control multiple terminals from a single screen. It's invaluable during penetration testing for maintaining persistent sessions, running multiple tools simultaneously, and organizing complex engagements.

## Installation

```bash
# Ubuntu/Debian
sudo apt install tmux

# CentOS/RHEL
sudo yum install tmux

# macOS
brew install tmux
```

## Session Management

| Command | Description | Example |
|---------|-------------|---------|
| `tmux` | Start new session | `tmux` |
| `tmux new -s name` | Start named session | `tmux new -s pentest` |
| `tmux ls` | List sessions | `tmux ls` |
| `tmux attach -t name` | Attach to session | `tmux attach -t pentest` |
| `tmux kill-session -t name` | Kill session | `tmux kill-session -t pentest` |

## Key Bindings (Ctrl+b prefix)

| Key | Description |
|-----|-------------|
| `Ctrl+b c` | Create new window |
| `Ctrl+b n` | Next window |
| `Ctrl+b p` | Previous window |
| `Ctrl+b 0-9` | Switch to window number |
| `Ctrl+b ,` | Rename current window |
| `Ctrl+b %` | Split window vertically |
| `Ctrl+b "` | Split window horizontally |
| `Ctrl+b arrow` | Navigate between panes |
| `Ctrl+b x` | Kill current pane |
| `Ctrl+b d` | Detach from session |

## Penetration Testing Use Cases

| Scenario | Setup | Benefit |
|----------|-------|---------|
| **Multi-target scanning** | Separate window per target | Parallel operations |
| **Long-running scans** | Detached sessions | Persistent execution |
| **Tool monitoring** | Split panes for logs/output | Real-time monitoring |
| **Documentation** | Dedicated pane for notes | Organized workflow |

## Configuration

Create `~/.tmux.conf` for custom settings:

```bash
# Enable mouse support
set -g mouse on

# Set prefix to Ctrl+a instead of Ctrl+b
set -g prefix C-a
unbind C-b

# Start window numbering at 1
set -g base-index 1
set -g pane-base-index 1
```

## Security Considerations

- Tmux sessions persist even when disconnected from SSH
- Be aware of screen locks when using shared systems
- Use named sessions for better organization during engagements

## Additional Resources

- [Tmux Manual](https://man7.org/linux/man-pages/man1/tmux.1.html)
- [Tmux Cheat Sheet](https://tmuxcheatsheet.com/)
- [Tmux Configuration Guide](https://github.com/tmux/tmux/wiki)
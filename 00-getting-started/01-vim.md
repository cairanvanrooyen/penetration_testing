# Vim Text Editor

Essential text editor for penetration testing and system administration with powerful editing capabilities.

## Overview

Vim is a highly configurable text editor built to make creating and changing any kind of text very efficient. It's ubiquitous on Unix/Linux systems and essential for penetration testers working in terminal environments.

## Basic Commands

| Command | Description | Example |
|---------|-------------|---------|
| `vim filename` | Open file in vim | `vim /etc/passwd` |
| `i` | Enter insert mode | Press `i` to start editing |
| `:w` | Save file | Type `:w` and press Enter |
| `:q` | Quit vim | Type `:q` and press Enter |
| `:wq` | Save and quit | Type `:wq` and press Enter |
| `:q!` | Quit without saving | Type `:q!` and press Enter |

## Navigation

| Command | Description |
|---------|-------------|
| `h, j, k, l` | Move left, down, up, right |
| `gg` | Go to beginning of file |
| `G` | Go to end of file |
| `0` | Go to beginning of line |
| `$` | Go to end of line |
| `/pattern` | Search for pattern |
| `n` | Next search result |
| `N` | Previous search result |

## Editing Commands

| Command | Description |
|---------|-------------|
| `dd` | Delete current line |
| `yy` | Copy (yank) current line |
| `p` | Paste below current line |
| `P` | Paste above current line |
| `u` | Undo last change |
| `Ctrl+r` | Redo |
| `x` | Delete character under cursor |
| `r` | Replace character under cursor |

## Security Considerations

- Always backup important files before editing
- Use `:set number` to show line numbers for easier navigation
- Be careful when editing system configuration files

## Additional Resources

- [Vim Cheat Sheet](https://vimsheet.com/)
- [Official Vim Documentation](https://www.vim.org/docs.php)
- [Interactive Vim Tutorial](https://www.openvim.com/)
# scanrunner v1.2.0

This release improves scanrunner’s CLI behavior, NetExec integration, parallel scan visibility, target handling, installation flow, and shell completion.

## Highlights

- Added `scanrunner -v` and `scanrunner --version`
- Added focused nested help pages
- Improved NetExec help and result handling
- Added live parallel scan output
- Added hostname and URL normalization
- Improved DNS timeout handling
- Improved `-Pn` behavior
- Added stronger Nmap report validation
- Added Linux, macOS, and Windows installer support
- Added Bash, Zsh, Fish, and PowerShell autocomplete
- Added regression tests for CLI and scanner workflows

## Installation

```bash
git clone https://github.com/Madhav-Sai/scanrunner.git
cd scanrunner
python3 install.py
```

## Examples

```bash
scanrunner -i 10.10.10.10 -sV
scanrunner -i 10.10.10.10 -Pn -sV -p-
scanrunner -f targets.txt --yes --parallel 2 -Pn -sV
scanrunner -f targets.txt -nxc smb
```

## Security Notice

scanrunner is intended only for authorized security assessments, internal security reviews, and educational lab environments.

**Full Changelog:** https://github.com/Madhav-Sai/scanrunner/commits/v1.2.0
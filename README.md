<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=34&pause=1200&color=00BFFF&center=true&vCenter=true&width=1000&height=80&lines=scanrunner;Interactive+Nmap+Automation+Framework;Built+for+VAPT+Engagements" />

<br>

<img src="https://img.shields.io/github/stars/Madhav-Sai/scanrunner?style=for-the-badge&color=0891b2" />
<img src="https://img.shields.io/github/forks/Madhav-Sai/scanrunner?style=for-the-badge&color=0284c7" />
<img src="https://img.shields.io/github/license/Madhav-Sai/scanrunner?style=for-the-badge&color=2563eb" />
<img src="https://img.shields.io/github/last-commit/Madhav-Sai/scanrunner?style=for-the-badge&color=1d4ed8" />

<br><br>

<img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Nmap-Required-004170?style=for-the-badge" />
<img src="https://img.shields.io/badge/Platform-Linux-success?style=for-the-badge&logo=linux" />
<img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" />
<img src="https://img.shields.io/badge/Security-VAPT-0ea5e9?style=for-the-badge" />

<br><br>

```text
   _____                  ____                            
  / ___/________ _____   / __ \__  ______  ____  ___  _____
  \__ \/ ___/ __ `/ __ \ / /_/ / / / / __ \/ __ \/ _ \/ ___/
 ___/ / /__/ /_/ / / / // _, _/ /_/ / / / / / / /  __/ /    
/____/\___/\__,_/_/ /_//_/ |_|\__,_/_/ /_/_/ /_/\___/_/     
```

### Interactive Nmap Automation Framework

*Automate • Resume • Track • Enumerate*

</div>

---

## Overview

scanrunner is an interactive Nmap automation framework designed for:

- Vulnerability Assessment & Penetration Testing (VAPT)
- Internal Network Assessments
- Active Directory Enumerations
- Security Operations
- Infrastructure Discovery
- Continuous Security Reviews

Instead of replacing Nmap, scanrunner acts as an orchestration layer that simplifies scan management, report handling, session recovery, and workflow automation.

---

## Why scanrunner?

Traditional Nmap workflows become painful during large assessments:

```text
• Hundreds of hosts
• Interrupted scans
• Duplicate reports
• Manual tracking
• Repeated rescans
• No session recovery
```

scanrunner solves these problems through automation.

---

## Core Features

<table>
<tr>
<td width="50%">

### Scan Management

- Existing Scan Detection
- Report Preview
- Skip / Rescan Controls
- Session Resume
- Progress Tracking
- Output Validation

</td>

<td width="50%">

### Assessment Workflow

- Ping Validation
- Optional -Pn Handling
- Audit Logging
- Report Organization
- Failure Tracking
- Interactive Execution

</td>
</tr>
</table>

---

## Architecture

```text
                         ┌──────────────────┐
                         │   Target List    │
                         └────────┬─────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │ Existing Report Check   │
                    └───────────┬─────────────┘
                                │
                     ┌──────────┴──────────┐
                     │                     │
                     ▼                     ▼
             Existing Report         New Target
                     │                     │
                     ▼                     ▼
            Preview / Rescan        Ping Validation
                     │                     │
                     └──────────┬──────────┘
                                ▼
                     ┌───────────────────┐
                     │   Nmap Scanner    │
                     └─────────┬─────────┘
                               │
                               ▼
                     ┌───────────────────┐
                     │ Report Generation │
                     └─────────┬─────────┘
                               │
                               ▼
                     ┌───────────────────┐
                     │ Audit Log Update  │
                     └───────────────────┘
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/Madhav-Sai/scanrunner.git

cd scanrunner
```

### Install Dependencies

#### Debian / Ubuntu / Kali

```bash
sudo apt update

sudo apt install nmap
```

#### RHEL / CentOS

```bash
sudo yum install nmap
```

#### Arch Linux

```bash
sudo pacman -S nmap
```

---

## Requirements

```text
Python 3.8+
Nmap
Linux
```

Verify installation:

```bash
python3 --version

nmap --version
```

---

## Usage

### Syntax

```bash
python3 scanrunner.py (-f <targets.txt> | -i <target>) [-o <output_folder>] [nmap arguments]
```

### Section Help

`scanrunner -h` now shows only the entry points, so users are not flooded with
unrelated Nmap, NetExec, reporting, and automation flags at once.

```bash
scanrunner -h
```

Open the nested help page for the workflow you need:

```bash
scanrunner --nmap -h
scanrunner --template -h
scanrunner -nxc -h
scanrunner --split -h
scanrunner --reports -h
```

Individual option help remains available, while the intentionally verbose
reference is kept behind `--help-all`:

```bash
scanrunner --parallel -h
scanrunner --help output
scanrunner --help-all
```

### Examples

#### Service Enumeration

```bash
python3 scanrunner.py -f alive.txt -o results -sV -T4
```

#### Aggressive Assessment

```bash
python3 scanrunner.py -f alive.txt -o results -sV -A -vv
```

#### Full Port Scan

```bash
python3 scanrunner.py -f alive.txt -o results -sS -p- -T4
```

#### Vulnerability Discovery

```bash
python3 scanrunner.py -f alive.txt -o results --script vuln -sV
```

#### Active Directory Assessment

```bash
python3 scanrunner.py -f dc.txt -o ad-assessment -sV -A -T4
```

---

## Input Format

### alive.txt

```text
192.168.1.10
192.168.1.20
10.10.10.5
172.16.1.100
```

Supported Targets:

```text
IPv4
IPv6
Hostnames
CIDR Ranges
```

### Split a target list

Use `--split N` with `--file` to create `N` balanced target files before
scanning. The source file is never modified. Blank lines, comments, and duplicate
targets are omitted from the split files.

```bash
python3 scanrunner.py --file targets.txt --split 3
```

For `targets.txt`, this writes `targets_part_1.txt`, `targets_part_2.txt`, and
`targets_part_3.txt` in the same directory. `N` must be at least 1 and cannot
exceed the number of unique usable targets.

---

## Existing Scan Detection

When a report already exists:

```text
======================================================================
Existing Scan Found
======================================================================

Status      : COMPLETE
Modified    : 2026-06-08 18:17:20
Size        : 23.7 KB
```

The last 15 lines are automatically displayed.

Available actions:

```text
[s] Skip
[r] Rescan
[m] Mark done
[v] View Full Report
[q] Quit
```

---

## Session Resume

Resume interrupted assessments instantly.

```text
[r] Resume (skip completed)  [f] Fresh (review all)
```

Previously completed hosts are automatically excluded.

Ideal for:

```text
Large Environments
Multi-Day Assessments
Long Running Scans
Client Engagements
```

---

## Output Structure

```text
results/
│
├── 192.168.1.10.txt
├── 192.168.1.10.xml
├── 192.168.1.20.txt
├── 10.10.10.5.txt
│
├── completed.txt
├── skipped.txt
├── rescanned.txt
├── not-pingip.txt
├── failed.txt
├── retried.txt
├── open-ports-inventory.csv
└── open-ports-inventory.json
```

---

## Audit Logs

| File | Purpose |
|--------|----------|
| completed.txt | Successfully scanned hosts |
| skipped.txt | User-skipped hosts |
| rescanned.txt | Hosts rescanned after detection |
| not-pingip.txt | Hosts skipped after failed ping validation |
| failed.txt | Scan failures |
| retried.txt | Targets that needed another attempt |

---

## Automation and Reporting

### Built-in Profiles

```bash
python3 scanrunner.py -f targets.txt -o results --profile quick
python3 scanrunner.py -f targets.txt -o results --profile web
python3 scanrunner.py -f targets.txt -o results --profile full
```

`--profile`, `--template`, and `--preset` are equivalent. They are optional
shortcuts: omit them and use ordinary Nmap arguments whenever you prefer.
Any Nmap arguments supplied after a preset are appended to the preset.

List the exact Nmap arguments in every preset:

```bash
python3 scanrunner.py --list-templates
# Alias: python3 scanrunner.py --template -vv
```

| Preset | Included Nmap arguments | Best for |
|---|---|---|
| `quick` | `-sV -T4 --top-ports 100` | Fast service check |
| `full` | `-sS -sV -O -T4 -p-` | Thorough TCP scan |
| `full-fast` | `-sV -A -Pn --min-rate 200 -p-` | Fast full-port scan |
| `web` | `-sV -p 80,443,8080,8443 --script http-title,http-headers` | Web identification |
| `web-enum` | `-sV -p 80,443,8080,8443 --script http-title,http-headers,http-enum` | Web enumeration |
| `ssl-ciphers` | `-sV -p 443,8443,9443 --script ssl-enum-ciphers` | TLS cipher review |
| `smb-audit` | `-sV -p 139,445 --script smb-os-discovery,smb-protocols,smb-security-mode` | SMB hardening review |
| `rdp-audit` | `-sV -p 3389 --script rdp-enum-encryption,rdp-ntlm-info` | RDP hardening review |
| `udp` | `-sU -sV --top-ports 100` | Common UDP services |
| `vuln` | `-sV --script vuln` | Nmap vulnerability scripts |

```bash
# Equivalent aliases; use whichever reads best in your workflow.
python3 scanrunner.py -f targets.txt --template ssl-ciphers
python3 scanrunner.py -f targets.txt --preset full-fast --host-timeout 10m
python3 scanrunner.py -f targets.txt --template full-fast -vv

# No preset: pass raw Nmap arguments as before.
python3 scanrunner.py -f targets.txt -sV -A -Pn --min-rate 200 -p-
```

### Non-interactive and Parallel Scans

Use `--yes` for automation. Pair it with `--parallel` for bounded concurrent
scans and `--retries` for transient failures. Parallel mode intentionally has
no keyboard controls or live per-process output.

```bash
python3 scanrunner.py -f targets.txt -o results --yes --parallel 4 --retries 1 -sV
python3 scanrunner.py -f targets.txt -o results --resume --skip-ping --no-color -sV
```

### Scope and Asset Metadata

`--scope-file` refuses targets that are not explicitly listed or contained by
an allowlisted CIDR. Use it for authorized engagement boundaries.

```text
# scope.txt
10.10.0.0/16
scanner.example.internal
```

Optional metadata is included in the generated inventories:

```csv
target,owner,environment
10.10.1.25,Platform Team,production
```

```bash
python3 scanrunner.py -f targets.txt -o results --scope-file scope.txt \
  --metadata-csv assets.csv --html-report -sV
```

Each run creates normal Nmap output (`.txt`), XML (`.xml`), and an open-port
inventory in CSV and JSON. `--html-report` also writes `open-ports-report.html`.

### NetExec (NXC) tables

Use `-nxc` (or `--nxc`) to run any installed NetExec protocol and its native
options against the supplied target or target file. scanrunner supports both the
`nxc` and `netexec` launcher names, streams NetExec output live, and then saves
the complete output plus terminal, CSV, and JSON tables.

```bash
# General SMB inventory table; any normal NXC options are passed through.
python3 scanrunner.py -f targets.txt -nxc smb --timeout 5

# Display only the SMB facts needed for a hardening review.
python3 scanrunner.py -f targets.txt -nxc smb --nxc-query os,hostname,smbv1,smb-signing

# Test whether anonymous SMB authentication succeeds. Empty credentials are added automatically.
python3 scanrunner.py -f targets.txt -nxc smb --nxc-query null-auth

# Show only RDP Network Level Authentication status.
python3 scanrunner.py -f targets.txt -nxc rdp --nxc-query rdp-nla
```

Focused fields are `os`, `hostname`, `smbv1`, `smb-signing`, `null-auth`, and
`rdp-nla`; `--nxc-query all` shows every field. NetExec options and modules are
not restricted by scanrunner, so use only those authorized for your engagement.
NXC mode supports target, output, scope, and color options; Nmap-only workflow
flags are rejected rather than silently ignored.

### Testing

Run the offline regression suite (it uses mocked scanner commands and does not
send network traffic):

```bash
python3 -m unittest discover -s tests -v
```

---

<details>
<summary><strong>Recommended Scan Profiles</strong></summary>

### Fast Internal Assessment

```bash
-sV -sC -T4
```

### Full Enumeration

```bash
-sS -sV -O -A -T4
```

### Vulnerability Discovery

```bash
--script vuln -sV
```

### Web Assessment

```bash
-sV -p 80,443,8080,8443 --script http-title,http-headers
```

### Full Port Enumeration

```bash
-sS -p- -T4
```

</details>

---

## Example Execution

```bash
python3 scanrunner.py -f alive.txt -o client-network -sV -A -T4
```

Output:

```text
======================================================================
Progress : 12/45 (26.67%)
Remaining: 33
======================================================================

Target: 172.16.5.120

[+] Pinging 172.16.5.120 ...

[+] Host is alive

[+] Command:
nmap --stats-every 15s -sV -A -T4 -oN client-network/172.16.5.120.txt -- 172.16.5.120
```

### Hosts Blocking Ping

When `-Pn` is supplied, scanrunner does not run its own ping check and does not
add a second `-Pn`. This lets Nmap scan hosts that block ICMP or discovery probes.

```bash
python3 scanrunner.py -i 192.168.1.50 -o results -Pn -sV
```

---

## Roadmap

```text
[ ] Parallel Scanning
[ ] HTML Reporting
[ ] XML Parsing
[ ] CSV Export
[ ] Asset Inventory
[ ] Dashboard Integration
[ ] Scheduling
[ ] Notification Support
```

---

## Known Limitations

```text
• Sequential Scanning
• Linux Focused
• No Native XML Parsing
• No Built-in Parallel Execution
• Requires Local Nmap Installation
```

---

## Security Notice

This project is intended for:

- Authorized Security Assessments
- Vulnerability Management
- Internal Security Reviews
- Educational Laboratories

Ensure all scanning activities are conducted within authorized scope and applicable legal requirements.

---

<div align="center">

### scanrunner

Interactive Nmap Workflow Automation Framework

Built for Security Professionals

</div>

## Shell Tab Completion

scanrunner can generate and install completion for Zsh and Bash.

### Zsh

```bash
scanrunner --install-completion zsh
```

If `~/.zsh/completions` is not already in your completion path, add these lines
to `~/.zshrc` and restart the shell:

```bash
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
```

Then pressing Tab completes scanrunner options, target files, output directories,
Nmap templates, NetExec protocols, and NXC query fields.

### Bash

```bash
scanrunner --install-completion bash
```

Completion scripts can also be printed without installing them:

```bash
scanrunner --completion zsh
scanrunner --completion bash
```

## Regression Tests

Run the offline test suite:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover nested help, argument validation, target normalization, URL and
hostname handling, NXC table parsing, quoted Nmap arguments, and completion
script generation.

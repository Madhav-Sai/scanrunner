# ScanRunner

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=30&pause=1200&color=00BFFF&center=true&vCenter=true&width=900&lines=scanrunner;Interactive+Nmap+Automation+Framework;Built+for+VAPT+Engagements;Assessment+Workflow+Automation" />

<br>

<img src="https://img.shields.io/github/stars/Madhav-Sai/scanrunner?style=for-the-badge&color=0891b2" />
<img src="https://img.shields.io/github/forks/Madhav-Sai/scanrunner?style=for-the-badge&color=0ea5e9" />
<img src="https://img.shields.io/github/license/Madhav-Sai/scanrunner?style=for-the-badge&color=2563eb" />
<img src="https://img.shields.io/github/last-commit/Madhav-Sai/scanrunner?style=for-the-badge&color=1d4ed8" />

<br>

<img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Nmap-Required-004170?style=for-the-badge" />
<img src="https://img.shields.io/badge/Platform-Linux-success?style=for-the-badge&logo=linux" />
<img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" />
<img src="https://img.shields.io/badge/Security-VAPT-blue?style=for-the-badge" />

<br><br>

```text
   _____                     ____                            
  / ___/_________ _____     / __ \__  ______  ____  ___  _____
  \__ \/ ___/ __ `/ __ \   / /_/ / / / / __ \/ __ \/ _ \/ ___/
 ___/ / /__/ /_/ / / / /  / _, _/ /_/ / / / / / / /  __/ /    
/____/\___/\__,_/_/ /_/  /_/ |_|\__,_/_/ /_/_/ /_/\___/_/     

             Interactive Nmap Automation Framework
```

**Automate. Resume. Track. Enumerate.**

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
python3 scanrunner.py <alive.txt> <output_folder> '<nmap_arguments>'
```

### Examples

#### Service Enumeration

```bash
python3 scanrunner.py alive.txt results '-sV -T4'
```

#### Aggressive Assessment

```bash
python3 scanrunner.py alive.txt results '-sV -A -vv'
```

#### Full Port Scan

```bash
python3 scanrunner.py alive.txt results '-sS -p- -T4'
```

#### Vulnerability Discovery

```bash
python3 scanrunner.py alive.txt results '--script vuln -sV'
```

#### Active Directory Assessment

```bash
python3 scanrunner.py dc.txt ad-assessment '-sV -A -T4'
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
[v] View Full Report
[q] Quit
```

---

## Session Resume

Resume interrupted assessments instantly.

```text
Resume previous session? [y/n]
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
├── 192.168.1.20.txt
├── 10.10.10.5.txt
│
├── completed.txt
├── skipped.txt
├── rescanned.txt
├── not-pingip.txt
└── failed.txt
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
python3 scanrunner.py alive.txt client-network '-sV -A -T4'
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
nmap -sV -A -T4 172.16.5.120 -oN results/172.16.5.120.txt
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

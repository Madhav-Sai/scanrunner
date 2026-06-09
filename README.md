<div align="center">

```text
   _____                     ____                            
  / ___/_________ _____     / __ \__  ______  ____  ___  _____
  \__ \/ ___/ __ `/ __ \   / /_/ / / / / __ \/ __ \/ _ \/ ___/
 ___/ / /__/ /_/ / / / /  / _, _/ /_/ / / / / / / /  __/ /    
/____/\___/\__,_/_/ /_/  /_/ |_|\__,_/_/ /_/_/ /_/\___/_/     

             Interactive Nmap Automation Framework
```

**Built for VAPT Engagements, Internal Assessments, and Security Operations**

</div>

---

## Overview

ScanRunner is a workflow-oriented Nmap automation framework designed to simplify large-scale host assessments.

The project focuses on reducing operational overhead during vulnerability assessments by automating:

- Existing scan detection
- Session resume functionality
- Reachability validation
- Report management
- Scan tracking
- Audit logging
- Interactive rescan workflows

Rather than replacing Nmap, ScanRunner enhances the scanning workflow around it.

---

## Features

| Capability | Description |
|------------|-------------|
| Session Resume | Continue interrupted assessments |
| Existing Scan Detection | Detect previously generated reports |
| Report Preview | Display last 15 lines before rescanning |
| Reachability Validation | Verify host availability before scanning |
| Optional `-Pn` Support | Scan hosts that block ICMP |
| Audit Logging | Track completed, skipped, rescanned and failed hosts |
| Interactive Controls | Skip, rescan, view or quit |
| Progress Tracking | Real-time assessment progress |
| Organized Output | Structured report storage |
| Flexible Scanning | Pass any valid Nmap arguments |

---

## Requirements

### Operating System

```text
Linux
```

### Dependencies

```text
Python 3.8+
Nmap
```

### Verify Installation

```bash
python3 --version
nmap --version
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/Madhav-Sai/scanrunner.git

cd scanrunner
```

### Install Nmap

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

## Usage

### Syntax

```bash
python3 scanrunner.py <alive.txt> <output_folder> '<nmap_arguments>'
```

### Examples

#### Service Detection

```bash
python3 scanrunner.py alive.txt results '-sV -T4'
```

#### Aggressive Scan

```bash
python3 scanrunner.py alive.txt results '-sV -A -vv'
```

#### Full Port Enumeration

```bash
python3 scanrunner.py alive.txt results '-sS -p- -T4'
```

#### Vulnerability Scripts

```bash
python3 scanrunner.py alive.txt results '--script vuln -sV'
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

Rules:

```text
- One target per line
- Blank lines are ignored
- Duplicate entries are ignored
- IPv4 supported
- IPv6 supported
- Hostnames supported
- CIDR ranges supported
```

---

## Workflow

```text
                   +-------------------+
                   |   Read Targets    |
                   +---------+---------+
                             |
                             v
                   +-------------------+
                   | Existing Report ? |
                   +----+---------+----+
                        |         |
                      Yes         No
                        |         |
                        v         v
             +----------------+  Ping Check
             | Show Preview   |       |
             | Skip/Rescan    |       |
             +-------+--------+       |
                     |                |
                     +--------+-------+
                              |
                              v
                    +------------------+
                    | Launch Nmap Scan |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | Store Results    |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | Update Logs      |
                    +------------------+
```

---

## Existing Scan Detection

Before scanning a target, ScanRunner checks whether a report already exists.

Example:

```text
======================================================================
Existing Scan Found
======================================================================

Status      : COMPLETE
Modified    : 2026-06-08 18:17:20
Size        : 23.7 KB
```

Available actions:

```text
[s] Skip
[r] Rescan
[v] View Full Report
[q] Quit
```

---

## Session Resume

If a previous assessment exists:

```text
Resume previous session? [y/n]
```

Completed targets are automatically skipped.

This is useful for:

```text
- Large assessments
- Interrupted scans
- Multi-day engagements
- Internal network reviews
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

## Log Files

### completed.txt

```text
2026-06-08 18:20:01 | 192.168.1.10
```

Successfully scanned hosts.

---

### skipped.txt

```text
2026-06-08 18:35:11 | 192.168.1.20
```

User skipped targets.

---

### rescanned.txt

```text
2026-06-08 18:40:45 | 10.10.10.5
```

Previously scanned hosts that were rescanned.

---

### not-pingip.txt

```text
2026-06-08 18:55:22 | 172.16.1.50
```

Hosts that failed ICMP validation and were skipped.

---

### failed.txt

```text
2026-06-08 19:10:08 | 192.168.1.100
```

Targets where Nmap execution failed.

---

## Recommended Scan Profiles

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

### Web Application Reconnaissance

```bash
-sV -p 80,443,8080,8443 --script http-title,http-headers
```

### Full Port Scan

```bash
-sS -p- -T4
```

---

## Example Assessment

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

## Known Limitations

```text
- Sequential scanning only
- Linux-focused implementation
- No XML parsing
- No parallel execution
- No HTML reporting
- Depends on local Nmap installation
```

---

## Roadmap

```text
[ ] Parallel scanning
[ ] HTML report generation
[ ] XML report parsing
[ ] Asset inventory mode
[ ] Tag-based target grouping
[ ] CSV export
[ ] Dashboard integration
[ ] Scheduled assessments
```

---

## Disclaimer

This tool is intended for authorized security assessments, vulnerability management activities, and laboratory environments.

Users are responsible for ensuring that all scanning activities are performed with proper authorization and within the scope of applicable laws, regulations, and contractual agreements.

---

<div align="center">

**ScanRunner**  
A practical Nmap workflow automation framework for security professionals.

</div>

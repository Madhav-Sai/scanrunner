<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=34&pause=1200&color=00BFFF&center=true&vCenter=true&width=1000&height=80&lines=scanrunner;Interactive+Nmap+%26+NetExec+Automation;Built+for+VAPT+Engagements" alt="scanrunner animated title" />

<br>

<img src="assets/readme/badges.png" alt="scanrunner project badges" />

<br><br>

<img src="assets/readme/ascii-banner.png" alt="scanrunner ASCII banner" />

### Interactive Nmap and NetExec Automation Framework

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

### Clone and install

```bash
git clone https://github.com/Madhav-Sai/scanrunner.git
cd scanrunner
python3 install.py
```

The installer automatically detects Linux, macOS, or Windows and then:

- installs the `scanrunner` command
- detects Zsh, Bash, Fish, or PowerShell
- installs shell tab completion
- checks whether Nmap and NetExec are available
- avoids duplicate shell configuration entries when run again

Verify the installation:

```bash
scanrunner -h
```

### Linux and macOS

The default installation creates an absolute system-wide launcher:

```text
/usr/local/bin/scanrunner -> /absolute/path/to/scanrunner.py
```

Administrator permission is requested only when `/usr/local/bin` is not
writable. For a user-only installation:

```bash
python3 install.py --user
```

This installs the launcher under `~/.local/bin`. Ensure that directory is in
`PATH`.

Force a specific completion shell when automatic detection is not suitable:

```bash
python3 install.py --shell zsh
python3 install.py --shell bash
python3 install.py --shell fish
```

After installation, reload the current shell:

```bash
exec zsh
# or
exec bash
```

### Windows

Run from PowerShell or Command Prompt:

```powershell
py install.py
```

The installer creates a user-level `scanrunner.cmd` launcher, adds its scripts
directory to the user `PATH`, and installs PowerShell completion. Open a new
PowerShell window afterward.

### Installation options

```text
--user              Install under the current user
--system            Request a system-wide Unix installation
--shell SHELL       auto, zsh, bash, fish, powershell, or none
--no-completion     Install without shell completion
```

### Dependencies

The installer checks dependencies and prints the relevant platform guidance.
Nmap is required for scanning. NetExec is optional and is only required for
`-nxc` mode.

#### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install nmap
```

#### macOS with Homebrew

```bash
brew install nmap
```


## Requirements

```text
Python 3.8+
Nmap
Linux, macOS, or Windows
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

If it's easier to think in terms of group size instead of file count, use
`--split-size N` instead — it splits into as many files as needed so each one
has about `N` targets:

```bash
python3 scanrunner.py --file targets.txt --split-size 50
```

Use only one of `--split` / `--split-size`.

### Large target lists: automatic terminal-tab offer

You don't have to plan a split ahead of time. When an interactive run has 20
or more pending targets, scanrunner offers to divide the work across separate
terminal tabs/windows instead of scanning everything, one host at a time, in
the current window:

```text
[*] Large target list detected: 84 targets pending.
Split across separate terminal tabs? Enter number of tabs (2-84), or press Enter to continue in this window:
```

Press Enter to decline and keep scanning normally, or enter a tab count to
launch that many independent scanrunner processes — each with its own target
list, but all writing their reports straight into the same output folder
(safe because every report is named after its own IP, so tabs never collide).
A `tab-manifest.txt` and each tab's target-list file live under
`<output>/tabs/`, recording exactly which targets went to which tab. If no
terminal emulator can be opened (for example, a headless shell), that tab
runs in the background instead, with its own console log under
`<output>/tabs/` to watch — a batch of targets is never silently dropped.

This window doesn't just launch and walk away — it stays open and shows a
live, self-updating dashboard of combined progress across every tab
(percent complete, completed/skipped/failed/no-ping/retried counts, and open
ports found so far), refreshed every few seconds by reading the shared
report and log files. Press Ctrl+C to stop watching without killing the
tabs; they keep scanning either way.

The prompt only appears on a real interactive terminal; it never fires under
`--yes`, `--parallel`, or piped/non-tty input. Two flags give you direct
control instead of waiting for the prompt:

- **`--tabs N`** — split into `N` tabs immediately, skipping the prompt
  entirely. This also works below the 20-target threshold, so a 5-target
  file can still be split if you want it to: `--tabs 2` on a 5-IP file gives
  you two tabs of 2-3 targets each. Mutually exclusive with `--parallel` and
  `--no-auto-tabs`.
- **`--no-auto-tabs`** — the opposite: never offer to split, no matter how
  large the list. A 100-target file with this flag just scans one host at a
  time in the current window, same as any small list.

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
| unaccounted.txt | Written only if a run ends with targets that have no recorded outcome at all |

### Reconciliation check

At the end of every run, scanrunner cross-checks the full input target list
against completed.txt, skipped.txt, not-pingip.txt, and failed.txt. Every
target should land in at least one of those. If a run gets interrupted before
reaching some hosts (Ctrl+C, a closed terminal, a killed process), those hosts
won't be in any of them yet — scanrunner prints a loud warning listing them
and writes `unaccounted.txt` so a partially finished assessment can never be
mistaken for a complete one:

```text
[!] WARNING: 3 target(s) have NO recorded outcome (scan likely interrupted before reaching them):
    1.1.1.1
    8.8.8.8
    9.9.9.9
[!] Saved to: results/unaccounted.txt
[!] Re-run with --resume to pick these up, or investigate before reporting results.
```

A clean run instead prints `Reconciliation OK — all N input target(s) are
accounted for.` Before reporting scan results to a client, check for this line
or for the absence of `unaccounted.txt`.

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
scans and `--retries` for transient failures. Parallel mode has no interactive keyboard controls, but it displays live target-prefixed worker output.

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

By default, `-nxc` writes its `nxc-<protocol>-<timestamp>.{txt,csv,json}`
files directly into the current directory rather than into `results/` — pass
`-o DIR` to send them somewhere else. Normal (non-`-nxc`) scans keep the
`results/` default.

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


### Automatically Skip No-Ping Targets

Use `-ok` (or `--skip-no-ping`) when you want scanrunner to keep the normal
wrapper ping check but automatically skip targets that do not respond.

```bash
scanrunner -f file.txt -o nmap -ok -sV -A
```

Behavior:

```text
Ping succeeds  -> scan normally
Ping fails     -> log to not-pingip.txt and skip automatically
No prompt      -> scanrunner does not ask whether to retry with -Pn
```

Without `-ok`, the existing interactive behavior is unchanged:

```text
Run nmap with -Pn anyway? [y/n]:
```

`-ok` is different from both `--skip-ping` and Nmap's `-Pn`:

| Option | Wrapper ping | On ping failure | Nmap discovery |
|---|---|---|---|
| default | Yes | Ask `[y/n]` about `-Pn` | Normal |
| `-ok` | Yes | Auto-skip + log | Normal |
| `--skip-ping` | No | Not applicable | Normal |
| `-Pn` | No | Not applicable | Disabled by Nmap |


---

## Roadmap

```text
[ ] Dashboard integration
[ ] Scheduled scan profiles
[ ] Notification integrations
[ ] Additional report formats
```

---

## Known Limitations

```text
• Requires a local Nmap installation
• NetExec functionality requires NetExec to be installed
• Interactive keyboard controls are unavailable during parallel scans
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

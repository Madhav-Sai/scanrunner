<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=34&pause=1200&color=00BFFF&center=true&vCenter=true&width=1000&height=80&lines=scanrunner;Interactive+Nmap+%26+NetExec+Automation;Built+for+VAPT+Engagements" alt="scanrunner animated title" />

<br>

<img src="assets/readme/badges.png" alt="scanrunner project badges" />

<br><br>

<img src="assets/readme/ascii-banner.png" alt="scanrunner ASCII banner" />

### Interactive Nmap and NetExec Automation Framework

*Automate • Resume • Track • Enumerate*

</div>

## Start with one complete assessment

```bash
scanrunner guide
scanrunner --whats-new
```

The guide walks through preparing scope, previewing a baseline scan, running it,
reading inventory and exporting an HTML report. It prints copyable commands.
Use your authorized IP with `scanrunner guide --target YOUR_IP`.

```bash
scanrunner guide --task reports
scanrunner guide --task findings
scanrunner guide --task optional-tools
scanrunner help report
```

Every assessment command's help explains its purpose, prerequisites, examples and
next step. [Assessment workflows](docs/assessment-workflows.md) covers optional
tools, XLSX, private sharing, scheduling and other local features.

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
python3 scanrunner.py -f alive.txt -o results -sV -vv
```

#### Full Port Scan

```bash
python3 scanrunner.py -f alive.txt -o results -sS -p- -T4
```

#### TLS Configuration Observations

```bash
python3 scanrunner.py -f alive.txt -o results --script ssl-enum-ciphers -sV --allow-intrusive --authorization-note AUTH_REF
```

#### Active Directory Assessment

```bash
python3 scanrunner.py -f dc.txt -o ad-assessment -sV -O -T4
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
├── 192.168.1.10.txt            Nmap normal output (-oN)
├── 192.168.1.10.xml            Nmap XML (-oX) — source for the inventory
├── 10.10.10.0_24.txt           a CIDR target: one report, many hosts
├── 10.10.10.5.error.log        Nmap console output, only for failed --parallel scans
│
├── completed.txt
├── skipped.txt
├── rescanned.txt
├── not-pingip.txt
├── failed.txt
├── retried.txt
├── unaccounted.txt             only when a run left targets without an outcome
├── open-ports-inventory.csv    one row per host and open port
├── open-ports-inventory.json
├── open-ports-report.html      with --html-report: by-service and by-host tables
└── scan-diff.json              written by --diff into the newer folder
```

Inventory columns: `target, host, hostname, owner, environment, port_service,
version`. `target` is what you listed; `host` is the address Nmap found, so a
CIDR target produces one row per live host.

---

## Audit Logs

| File | Purpose |
|--------|----------|
| completed.txt | Successfully scanned hosts |
| skipped.txt | User-skipped hosts |
| rescanned.txt | Hosts rescanned after detection |
| not-pingip.txt | Hosts skipped after failed ping validation, and hosts Nmap reported down (0 hosts up) |
| failed.txt | Scan failures: Nmap errors, `--host-timeout` hit (partial results), unresolvable hostnames, fatal Nmap errors |
| retried.txt | Targets that needed another attempt |
| unaccounted.txt | Written only if a run ends with targets that have no recorded outcome at all |

### Reconciliation check

At the end of every run, scanrunner cross-checks the full input target list
against completed.txt, skipped.txt, not-pingip.txt, and failed.txt. Every
target should land in at least one of those **during this run** — an outcome
left over from an earlier run doesn't count, so it can't hide a target this
run never reached. Each target is counted once, by its latest outcome (a host
that failed last week and completed today counts as completed). If a run gets interrupted before
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

## Reviewing Results Without Scanning

```bash
# Outcome counts, reports that aren't complete, tab-run progress,
# unaccounted targets, and the top open services
scanrunner --status results

# What changed between an initial test and a retest
scanrunner --diff results-june results-retest
```

`--diff` lists ports newly open (red) or now closed (green) on each host, hosts
that are new, and hosts no longer seen up. It also saves the result as
`scan-diff.json` in the newer folder. Neither command runs Nmap.

## How Nmap Results Are Classified

| Report says | Logged as | `--resume` |
|---|---|---|
| `Nmap done`, hosts up | completed.txt | skipped |
| `Nmap done ... (0 hosts up)` | not-pingip.txt (down) | tried again |
| `Skipping host ... due to host timeout` | failed.txt (partial results kept) | tried again |
| `0 IP addresses` (name did not resolve) | failed.txt | tried again |
| no `Nmap done` line (interrupted) | — | tried again, even if completed.txt lists it from an earlier run |

If Nmap refuses to start at all (an unknown option, a scan type that needs root,
a missing NSE script — `QUITTING!` or `See the output of nmap -h`), scanrunner
stops the run right away instead of failing every host the same way. The
targets it didn't reach are listed as unaccounted, ready for `--resume` once the
arguments are fixed.

## Nmap Flags scanrunner Handles Itself

| Flag | Behaviour |
|---|---|
| `-n`, and any other Nmap flag | passed to Nmap unchanged (scanrunner options must be typed in full; abbreviations are not guessed) |
| `-iL FILE` | treated as `-f FILE` |
| `-oN` / `-oX` / `-oG` / `-oA` / `-oS` | refused — scanrunner writes per-target `.txt` and `.xml` itself; use `-o DIR` |
| `-iR N` | refused — random targets can't be scope-checked or tracked |
| `-f` | always scanrunner's target file (Nmap's fragmentation flag is not available) |

In NXC mode, `-o KEY=VALUE ...` is passed to NetExec as module options, while
`-o DIR` is still the output folder.

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
| `full-fast` | `-sV -O -Pn -T4 -p-` | Full TCP service/OS scan under configured rate limits |
| `web` | `-sV -p 80,443,8000,8080,8443` | Web service/version inventory |
| `web-enum` | `-sV -p 80,443,8000,8080,8443` | Compatibility alias for web service inventory |
| `ssl-ciphers` | `-sV --script ssl-enum-ciphers` | TLS cipher observations |
| `smb-audit` | `-sV --script smb-os-discovery,smb-protocols,smb-security-mode,smb2-security-mode` | SMB observations requiring explicit anonymous-session authorization |
| `rdp-audit` | `-sV --script rdp-enum-encryption,rdp-ntlm-info` | RDP observations |
| `safe-baseline` | `-sT --top-ports 100 --version-light` | TCP connect inventory |
| `ssh-audit` | `-sV -p 22 --script ssh2-enum-algos` | SSH algorithm offers |
| `dns-audit` | `-sU -p 53 -sV` | DNS service inventory |
| `ad-discovery` | `-sT -p 53,88,135,139,389,445,464,636,3268,3269` | AD-associated port inventory |
| `tls-audit` | `-sV -p 443,8443 --script ssl-cert,ssl-enum-ciphers` | TLS certificate and cipher observations |
| `udp` | `-sU -sV --top-ports 100` | Common UDP services |

The broad `vuln` preset is retired because its script category includes unreviewed checks.
Choose a supported profile or explicitly select approved scripts. `full-fast` no longer
expands `-A` or sets a minimum traffic rate. `web` and `web-enum` provide service inventory
without HTTP NSE enumeration. These compatibility changes are also displayed in profile
notes. `smb-audit`, `ssl-ciphers` and `tls-audit` require both `--allow-intrusive` and `--authorization-note`.

```bash
# Equivalent aliases; use whichever reads best in your workflow.
python3 scanrunner.py -f targets.txt --template ssl-ciphers --allow-intrusive --authorization-note AUTH_REF
python3 scanrunner.py -f targets.txt --preset full-fast --host-timeout 10m
python3 scanrunner.py -f targets.txt --template full-fast -vv

# No preset: pass raw Nmap arguments as before.
python3 scanrunner.py -f targets.txt -sV -O -Pn -p- --scan-rate 100
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
python3 scanrunner.py -f targets.txt -nxc smb --allow-intrusive --authorization-note AUTH_REF --timeout 5

# Display only the SMB facts needed for a hardening review.
python3 scanrunner.py -f targets.txt -nxc smb --allow-intrusive --authorization-note AUTH_REF --nxc-query os,hostname,smbv1,smb-signing

# Test whether anonymous SMB authentication succeeds. Empty credentials are added automatically.
python3 scanrunner.py -f targets.txt -nxc smb --allow-intrusive --authorization-note AUTH_REF --nxc-query null-auth

# Show only RDP Network Level Authentication status.
python3 scanrunner.py -f targets.txt -nxc rdp --nxc-query rdp-nla
```

The default terminal/CSV/JSON table has three columns — `IP`, `HOSTNAME`,
`OS` — colorized for quick scanning: the IP in cyan, the OS in yellow, and
(when you add fields with `--nxc-query`) security-relevant booleans colored
by what they mean rather than uniformly — SMBv1 enabled, signing disabled,
RDP without NLA, and a successful null-auth attempt are red findings; their
safe counterparts are green.

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

Run the regression suite. It uses fake `nmap`, `ping` and `nxc` programs, so it
sends no network traffic. The one exception is a single real-Nmap check against
a listener on 127.0.0.1, which is skipped when Nmap isn't installed:

```bash
python3 -m pip install -r requirements-optional.txt
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
-sS -sV -O -T4
```

### TLS Configuration Observations

```bash
--script ssl-enum-ciphers -sV
```

### Web Assessment

```bash
-sV -p 80,443,8000,8080,8443
```

### Full Port Enumeration

```bash
-sS -p- -T4
```

</details>

---

## Example Execution

```bash
python3 scanrunner.py -f alive.txt -o client-network -sV -O -T4
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
nmap --stats-every 15s -sV -O -T4 -oN client-network/172.16.5.120.txt -- 172.16.5.120
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
scanrunner -f file.txt -o nmap -ok -sV
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
• Nmap's -f (fragmentation) cannot be passed, since -f is the target file
• Scope checks understand IPs, CIDRs, last-octet ranges (10.0.0.5-20) and
  hostnames; other Nmap range syntax (10.0-5.0.1) is refused when --scope-file is set
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

The installer provides completion for Bash, Zsh, Fish and PowerShell.
The CLI can also generate or install Bash and Zsh scripts directly.
Completion includes the assessment commands, `guide`, `help`, `--whats-new`,
scan profiles and the existing scan options. It does not suggest live hostnames
or dynamically look up finding IDs.

After upgrading, regenerate completion so your shell sees the new commands:

```bash
# Bash or Zsh: select your shell
scanrunner --install-completion bash
scanrunner --install-completion zsh

# Fish: rerun the installer from the updated checkout
python3 install.py --user --shell fish
```

For PowerShell, run `python install.py --user --shell powershell` from the
updated checkout. Open a new shell after installation. These installer commands
also refresh the installed application; they do not run a scan.

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

The tests cover nested help, argument validation and Nmap/NetExec flag
conflicts, scope checks, target normalization, report classification (complete,
down, timeout, unresolved, interrupted), per-host XML parsing, inventory
merging, outcome reconciliation, resume rules, NXC table parsing, and end-to-end
serial, parallel, tab, fatal-error, retry, `--status` and `--diff` runs.

Offline workflow tests run synthetic scanners through Python on Windows and POSIX;
they block child DNS, shell launches and real scanner executables. A controlled
localhost Nmap integration is separate and requires both Nmap and the explicit
`SCANRUNNER_TEST_REAL_NMAP=1` environment variable. Leave it unset for offline tests.
See `tests/fixtures/README.md` for fixture provenance. The supported control checks and their limitations are described below.

Port diffs report removed entries as **no longer observed open**. Scan coverage
has not been proved equivalent, so this is not proof of closure or remediation.
For JSON compatibility, the `closed` key remains; `closed_interpretation` and
`coverage_comparability` explain its limits.

## Scope and impact preview

Use `scanrunner -i 192.0.2.10 --dry-run --json -sV` to inspect planned commands,
impact, privileges and output paths without DNS queries or scanner processes.
Hostname addresses require validation at execution. Use `--scope-file scope.txt`
for an engagement allowlist. Empty scopes and mixed authorized/unauthorized DNS
answers are refused. Without a scope file, explicit requested targets form the
allowlist. DNS answers are checked again and pinned before scanner execution.
Exclusion overlap rejects the requested range. Split ranges around exclusions.

Scanner arguments and NSE scripts must be reviewed for scope preservation.
Unreviewed scripts and NetExec modules are refused. Credential operations require
`--allow-intrusive --authorization-note "Engagement authorization reference"`.
The retired `vuln` preset is rejected. Supported profiles are listed by `--list-templates`,
including authorization requirements and changes to legacy behavior.

## Durable runs and evidence

Each scanner attempt preserves raw stdout, stderr, XML, command metadata and a
SHA-256 manifest under `OUTPUT/.scanrunner/runs/RUN_ID/JOB_ID`. SQLite metadata
tracks jobs, scope snapshots and completion. The private directory restricts
access to the owner on Unix and owner/SYSTEM/administrators on Windows. Existing
`<target>.txt`/`.xml` paths provide current report views. Earlier legacy bytes are
retained with the attempt before those views change. Back up `.scanrunner` with
reports to retain complete provenance.

`scanrunner --history results --json` reviews runs and outcomes.
`scanrunner --verify-evidence results --json` checks artifact integrity and returns
a failure when evidence is missing, corrupt or unfinished.

Resume requires matching tool/version, binary hash, target, scope, profile,
arguments and execution policy plus valid associated XML and artifact hashes.
Legacy logs and manual acknowledgements alone cannot mark a new job complete.

Processes default to a 600-second timeout and retries are bounded to five.
`--global-concurrency` defaults to 4 and `--subnet-concurrency` to 2. These ceilings
apply to workers sharing an output directory. `--scan-rate` defaults to 100 Nmap
discovery/port-scan packets per second, divided across global slots. Raw rate
overrides must fit that ceiling. OS, version and NSE traffic is outside this budget.
Use `--dry-run` to review the effective arguments and impact.

Run `python scripts/check_quality.py` for offline syntax, safety lint and installer
archive checks. The GitHub Actions workflow runs those checks and the offline
regression suite on Windows, Linux and macOS.

## Assessment workflow in 1.5

Install from the complete repository and retain all `scanrunner_*.py` companion
modules beside `scanrunner.py`. The installer validates and copies the complete
application payload on Windows.
Unix launchers continue to use the repository source directory. Existing raw scan
artifacts and legacy CSV/JSON/HTML views remain available.

```bash
python3 scanrunner.py engagement create --name lab --scope-file scope.txt -o results
python3 scanrunner.py import saved.xml --engagement lab --scope-file scope.txt --target 192.0.2.0/24 -o results
python3 scanrunner.py inventory --engagement lab --port 445 --transport tcp -o results
python3 scanrunner.py observations --engagement lab -o results
python3 scanrunner.py findings create --engagement lab --observation OBSERVATION_ID -o results
python3 scanrunner.py findings list --engagement lab -o results
```

Import stores a private evidence copy, SHA-256, parser identity and original scanner
metadata. It performs no scanner execution or DNS lookup. A registered engagement's
scope and exclusions also constrain imports and subsequent scans. Inventory retains
exact TCP/UDP states, OS guesses and confidence, source hostnames and timestamps.
Unknown endpoint associations remain explicit. `asset --metadata metadata.json`
updates assessor-owned owner, site, environment, criticality, tags, notes, subnet or
customer fields. `asset ASSET_ID --add-address ADDRESS` records an analyst-approved
address alias while preserving asset identity.

Supported configuration rules currently interpret structured `smb2-security-mode`
and `smb-protocols` evidence on an associated open TCP endpoint. They produce
candidate observations with explicit prerequisites and rule versions. Their output
semantics follow the [SMB signing script documentation](https://nmap.org/nsedoc/scripts/smb2-security-mode.html)
and [SMB dialect script documentation](https://nmap.org/nsedoc/scripts/smb-protocols.html).
Host-script evidence can use a sole eligible SMB endpoint under the documented
[Nmap SMB library selection](https://svn.nmap.org/nmap/nselib/smb.lua). The observation
records this derivation and its source port field. Multiple eligible endpoints,
custom script arguments, failed checks and conflicting results require further
verification. Additional contracts cover RDP negotiation, TLS protocol/cipher evidence,
certificate validity, SSH algorithm offers, explicit anonymous FTP authentication and
controlled DNS recursion. Open management-associated ports produce exposure observations.
See [assessment workflows](docs/assessment-workflows.md) for supported evidence,
optional scanners, workbook exports, private sharing, scheduling and local operations.

Use `findings review --help` for supported decisions. Confirmation requires the
reviewer's identity and rationale, an explicit approval of prerequisites and impact,
positive source evidence, a known scanner version and observation time, and reviewed
description, impact, remediation and references. Imported origin needs an explicit
trust decision. For example, `reviewed-details.json` can contain these fields with
the assessor's actual conclusions. Missing fields remain `Not determined`.

```bash
python3 scanrunner.py findings review --engagement lab --finding FINDING_ID --status Confirmed --reviewer ANALYST --rationale REVIEW_REASON --details reviewed-details.json --approve-preconditions-and-impact --trust-import-origin -o results
python3 scanrunner.py retest FINDING_ID --engagement lab --run NEW_RUN_ID -o results
python3 scanrunner.py findings history --engagement lab --finding FINDING_ID -o results
python3 scanrunner.py report --engagement lab --view executive -o results
python3 scanrunner.py report --engagement lab --format html --destination technical.html -o results
python3 scanrunner.py findings export --engagement lab --destination final.json -o results
```

Review and retest events preserve history. Comparable negative evidence yields
`Potentially Remediated`. `retest --approve --reviewer ... --rationale ...` can record
`Remediated (Verified)` after the checks pass. Imported retest origin also requires
`--trust-import-origin`. Missing, older, filtered, failed or different-method evidence
cannot establish verified remediation. Final finding exports include confirmed
records by default and revalidate their raw evidence and approval hashes. Use
`--include-candidates` explicitly for draft exports. Reports retain coverage limits
and count candidate and confirmed statuses separately. JSON, CSV and HTML exports
redact recognized secrets, escape content and neutralize spreadsheet formulas.

## Measuring checks against labeled data

```bash
python3 scanrunner.py benchmark tests/fixtures/detection-benchmark/dataset.json --destination synthetic-score.json
```

That dataset contains six invented offline cases, including deliberately
unassessable cases. Its metrics describe those fixtures. For a controlled-lab or
verified-output dataset, supply independently verified positive/negative labels,
reviewer, method, timestamp, proof artifact and SHA-256 for each case. Each case
identifies an exact scanner artifact hash, IP, port, transport and check ID. The
benchmark invokes the production normalization and rule evaluator without scanning.
Duplicate cases are refused. Errors and abstentions remain in the counts, operational
recall includes positive abstentions, and reports include per-check denominators,
coverage and Wilson intervals. Field accuracy is pending a representative labeled
dataset. End-to-end scanner performance additionally requires executing the pinned
scanner against the authorized lab and independently checking its ground truth.

## NetExec authorization and assessment coverage

Every `-nxc smb` invocation requires `--allow-intrusive --authorization-note AUTH_REF`.
Replace `AUTH_REF` with the actual authorization reference. NetExec SMB host
enumeration performs a null-login probe and can probe Guest, including when no
credentials were supplied. The preview describes those effects. The underlying
behavior is visible in [NetExec SMB enumeration](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/protocols/smb.py).

Completion requires evidence for each requested address and focused field on the
selected protocol/port. Sparse CIDR results and unresolved requested facts retain
`PARTIAL` or `INCONCLUSIVE` coverage. The CLI exits 1 for incomplete coverage while
preserving the raw evidence and CSV/JSON facts. `coverage.json` in each job directory
records per-target outcomes, requested queries and port. Capacity reservations use
the selected targets within an engagement's authorization scope.

SMB signing is labeled as a signing requirement. An explicit blank-login
`STATUS_LOGON_FAILURE` is recorded as `Rejected`. Access denial remains
`Inconclusive`. Hash credentials prevent anonymous-credential injection, and generic
progress messages leave the OS field unknown. SMB `all` queries require the same
authorization and request an explicit blank login only when credentials are absent.
RDP `all` queries cover OS, hostname and NLA fields. Unsupported protocol/query
combinations fail before scanner execution. `--port` accepts an integer from 1 to
65535, and completion evidence must match the selected endpoint.

Evidence parser revision 4 invalidates earlier completion fingerprints. Version
compatibility remains important because the upstream SMB implementation documents
earlier SMB 3.1.1 signing interpretation pitfalls. Independent lab measurements must
pin the scanner version and verify the actual server policy.

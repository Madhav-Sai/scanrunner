# scanrunner v1.7.1

Bug fixes found by running v1.7.0 for real on Kali against a Docker lab (Samba,
legacy SMBv1 Samba, a Samba AD DC, SSH, FTP, IPv6, a high-latency host) with
real Nmap 7.99, NetExec 1.5.1 and PingMe 3.3.0, and tabs in qterminal,
gnome-terminal, konsole, xfce4-terminal, xterm and tmux. No new options.

## Fixes

- `10.0.0.1-20` range targets were pinged as one host, which always fails, so
  the range was logged as no-ping and never scanned; Nmap now does the host
  discovery, as for a CIDR
- `--nxc-query all` now attempts the SMB null session, so the Null Auth column
  and finding are filled in (only `null-auth` did before)
- Linux tab windows stay open when their part is done (press Enter to close),
  like Windows and macOS tabs
- Closing the launching window no longer kills running tabs (tab windows and
  background tabs run in their own session)
- No colour escape codes when output is redirected or piped
- `python3 install.py` falls back to a `~/.local/bin` install when sudo can't
  run instead of failing; `--system` still requires sudo
- IPv6 targets get `-6` automatically, so IPv6-only and mixed IPv4/IPv6 lists
  scan (Nmap refused them and scanrunner reported "could not resolve")
- `-i` or `-f` given twice is now an error; before, only the last one was kept
  and the other targets were silently dropped
- The wrapper ping sends two echo requests (up to 2 s), so one lost packet no
  longer marks a live host as down
- NXC table: SSH/FTP no longer show the IP as HOSTNAME, LDAP no longer shows
  "None" as the OS, and later lines (`[*] Enumerated ... users`) can't replace it
- Tabs in qterminal (Kali's default), konsole and xfce4-terminal no longer break
  arguments that contain an apostrophe
- macOS tabs: arguments with `"` or `\` no longer break the Terminal command;
  Windows Terminal tabs keep `;` inside arguments (unit-tested; not yet run on
  a real Mac or Windows machine)
- Fixed a flaky Windows CI test (fake Nmap call log lost lines in parallel)

# scanrunner v1.7.0

Back to the simple scanrunner. The v1.5/v1.6 "assessment framework" rewrite made
everyday scans harder, so this release restores the v1.3.0 workflow and adds
PingMe on top.

## Restored

- Every Nmap flag is passed straight to Nmap again: `-A`, `-sC`, `-O`, `-p-`,
  `--script vuln`, `--script-args ...` — no allowlist, no "unreviewed argument" errors
- No `--allow-intrusive` / `--authorization-note AUTH_REF` gates for NXC, SMB
  templates or credentials
- NetExec runs at its own default speed with live output
- Interactive prompts, existing-report menu, resume and terminal tabs as in v1.3.0
- Removed the assessment/plugin/probe/discover subcommands, run database and lab tooling

## Added

- `--pingme`: sweep targets with PingMe first and scan only live hosts
  (CIDRs become their live hosts; no-response targets go to `not-pingip.txt`)
- `--pingme-only`, `--pingme-path`, `--pingme-args`, and `scanrunner --pingme -h`
- Resume prompt defaults to resume — just press Enter to skip completed targets
- `--host-timeout 15m` is added when you don't set one (your own value, or `0`, wins)
- `--pingme-args` refuses PingMe modes that never finish (`--watch`, `--serve`, ...)
- Space / Ctrl+X / Ctrl+C scan keys now work on Windows too

## Fixes

- `--pingme` works with CIDR and `10.0.0.1-20` range targets (PingMe only reads
  single hosts from a file, so these failed with "No valid IPs")
- `--tabs`: the launching window prints the summary and `Reconciliation OK` once
  every tab finishes (Linux tab windows close when their part is done)
- NXC table keeps the OS from the host banner; `--shares` output no longer
  replaces it with share rows
- Tabs on Windows no longer lose outcome log lines (and report finished targets
  as unaccounted): concurrent appends to `completed.txt` etc. are now locked
- NetExec/Nmap output is read as UTF-8, so Windows doesn't garble or crash on it
- `nmap`, `ping` and `nxc` are found through PATH including `.cmd`/`.bat` wrappers
- Nmap `-n` passthrough on Python 3.10
- No `UnicodeEncodeError` when output is piped or redirected on Windows
- The whole test suite now runs on Windows too, and never runs the real Nmap
- Skipping a host no longer leaks Nmap's output pipe

# scanrunner v1.3.0

Accuracy fixes for how results are parsed, classified and reconciled, plus
`--status` and `--diff` for reviewing results without scanning.

## Fixes

- Nmap's `-n` no longer turns into `-nxc` (argparse abbreviation matching is off)
- `-oA/-oN/-oX/-oG/-oS` are refused with an explanation instead of silently
  changing the output folder; `-iL FILE` works as `-f FILE`; `-iR` is refused
- CIDR scans are broken down per host in the inventory and summary (parsed from the Nmap XML)
- NXC tables no longer show blank rows for CIDR/range targets, and hostname
  targets merge into their IP's row; `-o KEY=VALUE` reaches NetExec as module options
- `--parallel` now logs targets it skips, runs the wrapper ping check (honouring `-ok`),
  saves Nmap's output to `<target>.error.log` on failure, and requires a finished report
- `[q]` in the existing-report menu now writes the inventory and HTML report
- Summary counts each target once, by its latest outcome, and reconciliation only
  counts outcomes from the current run
- Hosts Nmap reports down are logged as down, not completed; host timeouts and
  unresolvable hostnames are logged as failures, not completed
- `--resume` rescans a report that was overwritten by an interrupted rescan
- Tab launch detects terminals that can't open (no display) and falls back to background runs
- No escape codes with `--no-color`; the live timer no longer floods piped/logged output

## Added

- `scanrunner --status [DIR]` and `scanrunner --diff OLD NEW`
- Fatal Nmap errors (bad option, missing privileges) stop the run immediately
- Inventory columns `host`, `hostname`, `version`; HTML report with a by-service table
- `--scope-file` accepts hostnames that resolve into scope and last-octet ranges
- End-to-end tests with fake nmap/ping/nxc, plus a real-Nmap localhost check

---

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
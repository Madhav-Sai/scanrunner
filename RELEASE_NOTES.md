# scanrunner v1.5.0

Download `scanrunner-1.5.0.zip` from the GitHub release and extract the entire
folder before installing. A SHA-256 checksum accompanies the ZIP. Supporting
code now lives in `scanrunner_lib/`, keeping the repository root easier to browse.
Existing CLI commands remain unchanged. Reinstall from the complete updated
folder to refresh the application and shell completion.

Adds evidence contracts for RDP, TLS, SSH, controlled FTP/DNS checks and management exposure. New observations preserve prerequisites, source identity and conservative outcomes. Finding templates include explicit missing-value fields, and optional XLSX exports preserve text cell types.

Optional httpx, testssl.sh and reviewed Nuclei adapters use explicit scope, version and authorization checks. Local operations add a terminal menu, queued scheduling, manual CVE snapshots, keyed sharing, asset history, reusable templates and HMAC report/evidence attestations. See [assessment workflows](docs/assessment-workflows.md) for commands and limitations.

The profile catalog adds baseline, SSH, DNS, AD and TLS workflows. TLS cipher enumeration now requires explicit authorization. Application parser revision 4 invalidates earlier completion fingerprints. Rule revision 5 requires renewed review of previously confirmed findings before final export.

The main help groups commands by task. `scanrunner guide` walks through a complete first scan, with additional walkthroughs for reports, findings, optional tools, sharing and scheduling. `scanrunner --whats-new` lists new features, and command help includes prerequisites, examples and a next action.

Live terminal controls preserve output newline processing, fixing diagonal/scattered scanner output. Exact evidence captures and explicit analyst confirmation remain part of the assessment workflow.

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

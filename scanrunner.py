#!/usr/bin/env python3
"""
scanrunner.py — Automated Nmap wrapper  by madhav
"""

import os
import sys
import re
import csv
import json
import html
import ipaddress
import signal
import socket
import shutil
import shlex
import time
import select

# tty/termios are POSIX-only and back the raw-keystroke live controls
# (Space/Ctrl+X/Ctrl+C during a scan). They don't exist on Windows, so the
# live key-watcher is disabled there instead of crashing at import time.
if sys.platform != "win32":
    import tty
    import termios
else:
    tty = None
    termios = None

RAW_MODE_SUPPORTED = sys.platform != "win32"
import queue
import threading
import argparse
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.2.0"

# When an interactive run has at least this many pending targets, offer to
# split the work across separate terminal tabs (see offer_terminal_tabs()).
AUTO_TAB_PROMPT_THRESHOLD = 20


SCAN_PROFILES = {
    "quick": ["-sV", "-T4", "--top-ports", "100"],
    "full": ["-sS", "-sV", "-O", "-T4", "-p-"],
    "web": ["-sV", "--script", "http-title,http-headers"],
    "udp": ["-sU", "-sV", "--top-ports", "100"],
    "vuln": ["-sV", "--script", "vuln"],
    "full-fast": ["-sV", "-A", "-Pn", "--min-rate", "200", "-p-"],
    "ssl-ciphers": ["-sV", "--script", "ssl-enum-ciphers"],
    "web-enum": ["-sV", "--script",
                 "http-title,http-headers,http-enum"],
    "smb-audit": ["-sV", "--script",
                  "smb-os-discovery,smb-protocols,smb-security-mode"],
    "rdp-audit": ["-sV", "--script",
                  "rdp-enum-encryption,rdp-ntlm-info"],
}

NXC_QUERY_CHOICES = {
    "os", "hostname", "smbv1", "smb-signing", "null-auth", "rdp-nla", "all"
}

HELP_BANNER = r"""
   _____                  ____
  / ___/________ _____   / __ \__  ______  ____  ___  _____
  \__ \/ ___/ __ `/ __ \ / /_/ / / / / __ \/ __ \/ _ \/ ___/
 ___/ / /__/ /_/ / / / // _, _/ /_/ / / / / / / /  __/ /
/____/\___/\__,_/_/ /_//_/ |_|\__,_/_/ /_/_/ /_/\___/_/

                     scanrunner
"""

TOP_LEVEL_HELP = HELP_BANNER + r"""
Automated Nmap and NetExec workflow for authorized assessments.

Usage:
  scanrunner <target> [mode/options]

Start here:
  scanrunner -f targets.txt -sV               Run Nmap with raw arguments
  scanrunner -i 10.10.10.10 --template quick  Run an Nmap template
  scanrunner -f targets.txt -nxc smb           Run NetExec SMB mode
  scanrunner -f targets.txt --split 3          Split a target file

Focused help:
  scanrunner --nmap -h       Nmap workflow and options
  scanrunner --template -h   Nmap templates
  scanrunner -nxc -h         NetExec mode, queries, and examples
  scanrunner --split -h      Target splitting
  scanrunner --reports -h    Output and reporting

Version:
  scanrunner -v | --version

Use `scanrunner --help-all` only when you need the complete reference.
"""



class ScanrunnerHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=32, width=100)


# ═══════════════════════════════════════════════════════════════════════════════
#  COLORS
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;214m"

COLORS_ENABLED = True

def c(color, text):
    return f"{color}{text}{C.RESET}" if COLORS_ENABLED else text

def sep(color=C.DIM, char="─", width=70):
    print(c(color, char * width))

def banner():
    print(c(C.CYAN + C.BOLD, HELP_BANNER.rstrip()))
    print(c(C.DIM, "  Nmap • NetExec • Resume • Reports\n"))



# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL SAFETY
# ═══════════════════════════════════════════════════════════════════════════════

_original_term_settings = None

def _save_terminal():
    global _original_term_settings
    if RAW_MODE_SUPPORTED and sys.stdin.isatty():
        try:
            _original_term_settings = termios.tcgetattr(sys.stdin.fileno())
        except Exception:
            pass

def restore_terminal():
    global _original_term_settings
    if RAW_MODE_SUPPORTED and _original_term_settings is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN,
                              _original_term_settings)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def log_to_file(filename, data):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {data}\n")


class _FileLock:
    """Advisory lock for a shared file, based on atomic exclusive file creation.

    Several scanrunner processes (e.g. spawned terminal tabs) may write into
    the same output directory at once. Per-host report files never collide
    (each is named after its own IP), but files that get rewritten wholesale
    — the inventory CSV/JSON — need to be serialized so one process's write
    can't clobber another's. A stale lock from a crashed process is stolen
    after `timeout` seconds rather than blocking forever.
    """
    def __init__(self, path, timeout=30):
        self.lock_path = path + ".lock"
        self.timeout = timeout
        self._fd = None

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self._fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                if time.time() > deadline:
                    try:
                        os.remove(self.lock_path)
                    except OSError:
                        pass
                    continue
                time.sleep(0.05)

    def __exit__(self, *exc_info):
        if self._fd is not None:
            os.close(self._fd)
        try:
            os.remove(self.lock_path)
        except OSError:
            pass

def read_logged_ips(path):
    """Return the set of unique targets recorded in an audit-log file."""
    if not os.path.exists(path):
        return set()
    seen = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 2:
                seen.add(parts[-1].strip())
    return seen

def count_unique_ips(path):
    return len(read_logged_ips(path))

def sanitize_filename(ip):
    return ip.replace(":", "_").replace("/", "_")

def check_nmap_installed():
    if shutil.which("nmap") is None:
        print(c(C.RED + C.BOLD, "\n  [!] nmap not found in PATH. Install nmap first."))
        sys.exit(1)

def find_nxc_binary():
    """Return the available NetExec launcher name."""
    return shutil.which("nxc") or shutil.which("netexec")


def check_nxc_installed():
    binary = find_nxc_binary()
    if binary is None:
        print(c(C.RED + C.BOLD,
                "\n  [!] NetExec not found. Expected `nxc` or `netexec` in PATH."))
        sys.exit(1)
    return binary

def safe_input(prompt):
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted. Saving progress and exiting."))
        restore_terminal()
        sys.exit(0)

def strip_inline_comment(line):
    """
    Strip inline # comments from an IP line.
    '10.10.10.1  # dc' -> '10.10.10.1'
    Lines starting with # are ignored entirely in the caller.
    """
    return line.split("#")[0].strip()

def has_nmap_option(nmap_extra, option):
    """Return whether an option is present, including --option=value form."""
    return any(token == option or token.startswith(f"{option}=")
               for token in nmap_extra)


def redact_command(command):
    """Return a display-safe command without credential values."""
    sensitive_options = {"-p", "--password", "-H", "--hash", "--aesKey", "--key"}
    redacted = []
    hide_next = False
    for token in command:
        if hide_next:
            redacted.append("***")
            hide_next = False
        else:
            option, separator, _ = token.partition("=")
            redacted.append(f"{option}=***" if separator and option in sensitive_options else token)
            hide_next = token in sensitive_options
    return redacted

def is_network_target(target):
    """Return whether target is a CIDR range that should be discovered by Nmap."""
    return "/" in target

def load_metadata(path):
    if not path:
        return {}
    try:
        with open(path, newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)
            if not reader.fieldnames or "target" not in reader.fieldnames:
                raise ValueError("CSV must include a target column")
            return {row["target"].strip(): row for row in reader if row.get("target", "").strip()}
    except (OSError, ValueError, csv.Error) as error:
        print(c(C.RED + C.BOLD, f"  [!] Invalid metadata CSV: {error}"))
        sys.exit(1)

def load_scope(path):
    if not path:
        return []
    try:
        with open(path, encoding="utf-8-sig") as file:
            return [cleaned for line in file if (cleaned := strip_inline_comment(line))]
    except OSError as error:
        print(c(C.RED + C.BOLD, f"  [!] Cannot read scope file: {error}"))
        sys.exit(1)

def target_in_scope(target, scope):
    if not scope or target in scope:
        return True
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return any(network.subnet_of(ipaddress.ip_network(item, strict=False))
                       for item in scope if "/" in item)
        address = ipaddress.ip_address(target)
        return any(address in ipaddress.ip_network(item, strict=False)
                   for item in scope if "/" in item)
    except ValueError:
        return False


HELP_TOPICS = {
    "nxc": """NetExec (NXC) help

Usage:
  scanrunner -f targets.txt -nxc <protocol> [NXC options]
  scanrunner -i 10.10.10.10 -nxc <protocol> [NXC options]

Examples:
  scanrunner -f targets.txt -nxc smb --nxc-query os,hostname,smbv1
  scanrunner -f targets.txt -nxc smb --nxc-query null-auth
  scanrunner -f targets.txt -nxc rdp --nxc-query rdp-nla

scanrunner passes all remaining options to NetExec and saves raw output, CSV,
and JSON tables. For protocol-specific NetExec options, run: nxc <protocol> --help
Focused table fields: os, hostname, smbv1, smb-signing, null-auth, rdp-nla, all.
""",
    "templates": """Nmap templates help

Usage:
  scanrunner -f targets.txt --template <name> [extra Nmap arguments]

Aliases:
  --profile, --template, and --preset are equivalent.

Templates:
  quick, full, full-fast, web, web-enum, ssl-ciphers, smb-audit,
  rdp-audit, udp, vuln

Run --list-templates or --template -vv to view the exact arguments in each template.

Examples:
  scanrunner -f targets.txt --template ssl-ciphers
  scanrunner -f targets.txt --preset full-fast --host-timeout 10m

Templates are optional. You can always use raw Nmap arguments instead:
  scanrunner -f targets.txt -sV -A -Pn --min-rate 200 -p-

Nmap verbosity is passed through normally:
  scanrunner -f targets.txt --template full-fast -vv
""",
    "split": """Target splitting help

Two ways to split a target file — pick whichever is easier to reason about:

  --split N        Split into exactly N files (you choose the file count)
  --split-size N   Split into files of N targets each (you choose the group size;
                    the file count is worked out for you)

Usage:
  scanrunner -f targets.txt --split <number-of-files>
  scanrunner -f targets.txt --split-size <targets-per-file>

Examples:
  scanrunner -f targets.txt --split 3            # -> 3 files, balanced
  scanrunner -f targets.txt --split-size 50       # -> ceil(total/50) files, ~50 targets each

Creates balanced files such as targets_part_1.txt beside the source file.
The source is never modified. Blank lines, comments, and duplicate targets are
ignored. --split's N must be at least 1 and no greater than the number of
usable unique targets; --split-size's N must be at least 1 (the last file may
have fewer targets than the others). Use only one of --split / --split-size.

Note: you don't have to plan ahead. If you load a large target file directly
into a normal scan (no --split), scanrunner will offer to split the work
across separate terminal tabs interactively — see `scanrunner --nmap -h`.
""",
    "nmap": """Nmap scan help

Usage:
  scanrunner (-f targets.txt | -i target) [scanrunner options] [Nmap arguments]

Examples:
  scanrunner -f targets.txt -sV -A -Pn --min-rate 200 -p-
  scanrunner -i 10.10.10.10 -o results -sS -sV
  scanrunner -f targets.txt --template smb-audit
  scanrunner -f targets.txt -ok -sV -A

Ping decision helpers:
  -ok, --skip-no-ping     Skip and log wrapper ping failures without prompting
  --skip-ping             Do not perform scanrunner's wrapper ping check
  -Pn                     Nmap option: bypass host discovery and scan anyway

Large target lists:
  An interactive run with 20+ pending targets is offered a choice: split the
  work across separate terminal tabs/windows, or keep scanning them one at a
  time in this window. See --split -h for the offer's details, or --split /
  --split-size to prepare separate files yourself ahead of time.

All unrecognized arguments are passed directly to Nmap. Use nmap --help for
the complete current list of Nmap flags and NSE scripts. Use -v or -vv for
more verbose Nmap output.
""",
    "reports": """Reporting and automation help

Output options:
  -o DIR                 Save reports in DIR (default: results; current
                          directory when combined with -nxc)
  --html-report          Add an HTML open-port report
  --metadata-csv FILE    Add owner/environment fields to inventories

Automation options:
  --yes                  Non-interactive mode
  --resume               Skip targets with completed reports
  -ok, --skip-no-ping    Skip and log wrapper ping failures without prompting
  --parallel N           Run N non-interactive scans concurrently (requires --yes)
  --retries N            Retry failed scans N times
  --scope-file FILE      Refuse targets outside the authorized scope

Every run ends by reconciling the full target list against completed.txt,
skipped.txt, not-pingip.txt, and failed.txt. Any target with no recorded
outcome at all (e.g. an interrupted run) is printed as a warning and saved to
unaccounted.txt in the output directory — check for this before reporting
results as final.
""",
}

OPTION_HELP = {
    "file": "--file FILE\nRead IPs, hostnames, CIDRs, or ranges from FILE. Blank lines, # comments, and duplicates are ignored.\nExample: scanrunner -f targets.txt -sV",
    "ip": "--ip TARGET\nScan one IP address, hostname, or CIDR directly.\nExample: scanrunner -i 10.10.10.10 -sV",
    "output": "--output DIR\nWrite reports, logs, and inventories to DIR. Default: results (current directory when combined with -nxc).\nExample: scanrunner -f targets.txt -o client-assessment -sV",
    "exclude": "--exclude TARGET\nExclude one target or CIDR from an Nmap scan. Repeat for multiple exclusions.\nExample: scanrunner -f targets.txt --exclude 10.10.10.5 -sV",
    "exclude-file": "--exclude-file FILE\nPass FILE to Nmap as an exclusion list.\nExample: scanrunner -f targets.txt --exclude-file excluded.txt -sV",
    "nxc-query": "--nxc-query QUERY\nChoose NXC table fields: os, hostname, smbv1, smb-signing, null-auth, rdp-nla, all.\nExample: scanrunner -f targets.txt -nxc smb --nxc-query os,hostname,smbv1",
    "yes": "--yes\nRun non-interactively. Complete reports are skipped and incomplete reports are rescanned.\nExample: scanrunner -f targets.txt --yes --parallel 4 -sV",
    "resume": "--resume\nSkip targets with completed reports already in the output directory.\nExample: scanrunner -f targets.txt --resume -sV",
    "skip-ping": "--skip-ping\nSkip scanrunner's ping check. Nmap host discovery still runs unless you pass -Pn.\nExample: scanrunner -f targets.txt --skip-ping -sV",
    "no-color": "--no-color\nDisable terminal colors for CI logs or redirected output.\nExample: scanrunner -f targets.txt --no-color -sV",
    "scope-file": "--scope-file FILE\nAllowlist authorized hosts/CIDRs; targets outside it are refused.\nExample: scanrunner -f targets.txt --scope-file authorized.txt -sV",
    "retries": "--retries N\nRetry failed Nmap scans up to N additional times. Default: 0.\nExample: scanrunner -f targets.txt --retries 2 -sV",
    "parallel": "--parallel N\nRun up to N Nmap scans concurrently. Requires --yes.\nExample: scanrunner -f targets.txt --yes --parallel 4 -sV",
    "metadata-csv": "--metadata-csv FILE\nAdd owner/environment data to the CSV/JSON inventory; FILE needs a target column.\nExample: scanrunner -f targets.txt --metadata-csv assets.csv -sV",
    "html-report": "--html-report\nCreate open-ports-report.html in the output directory.\nExample: scanrunner -f targets.txt --html-report -sV",
}

OPTION_ALIASES = {
    "-f": "file", "--file": "file", "file": "file", "-i": "ip", "--ip": "ip", "ip": "ip",
    "-o": "output", "--output": "output", "output": "output", "--exclude": "exclude", "exclude": "exclude",
    "--exclude-file": "exclude-file", "exclude-file": "exclude-file", "--nxc-query": "nxc-query", "nxc-query": "nxc-query",
    "--yes": "yes", "yes": "yes", "--resume": "resume", "resume": "resume", "--skip-ping": "skip-ping", "skip-ping": "skip-ping",
    "-ok": "skip-no-ping", "--skip-no-ping": "skip-no-ping", "skip-no-ping": "skip-no-ping",
    "--no-color": "no-color", "no-color": "no-color", "--scope-file": "scope-file", "scope-file": "scope-file",
    "--retries": "retries", "retries": "retries", "--parallel": "parallel", "parallel": "parallel",
    "--metadata-csv": "metadata-csv", "metadata-csv": "metadata-csv", "--html-report": "html-report", "html-report": "html-report",
}


def print_template_catalog():
    print("\nAvailable templates:\n")
    for name, options in sorted(SCAN_PROFILES.items()):
        print(f"  {name:<14} {' '.join(options)}")


def print_topic_help(topic):
    print(HELP_TOPICS[topic].strip())
    if topic == "templates":
        print_template_catalog()


def print_option_help(option):
    print(OPTION_HELP[option])


def print_all_option_help():
    for topic in ("split", "templates", "nxc", "nmap", "reports"):
        print_topic_help(topic)
        print()
    for option in sorted(OPTION_HELP):
        print_option_help(option)
        print()



def completion_script(shell):
    """Return a lightweight native completion script for Bash or Zsh."""
    options = [
        "-h", "--help", "-v", "--version", "-f", "--file", "-i", "--ip",
        "--split", "--split-size", "--profile", "--template", "--preset", "--exclude",
        "--exclude-file", "-nxc", "--nxc", "--nxc-query", "--yes",
        "--resume", "--skip-ping", "-ok", "--skip-no-ping", "--no-color",
        "--scope-file", "--retries", "--parallel", "-o", "--output",
        "--metadata-csv", "--html-report", "--list-templates", "--help-all",
        "--nmap", "--reports", "--nxc-native-help", "--completion",
    ]
    profiles = " ".join(sorted(SCAN_PROFILES))
    protocols = "smb rdp ldap winrm ssh ftp mssql wmi vnc nfs"
    queries = " ".join(sorted(NXC_QUERY_CHOICES))

    if shell == "bash":
        words = " ".join(options)
        return f"""_scanrunner_completion() {{
    local cur prev
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    case "$prev" in
        --profile|--template|--preset) COMPREPLY=( $(compgen -W "{profiles}" -- "$cur") ); return ;;
        -nxc|--nxc|--nxc-native-help) COMPREPLY=( $(compgen -W "{protocols}" -- "$cur") ); return ;;
        --nxc-query) COMPREPLY=( $(compgen -W "{queries}" -- "$cur") ); return ;;
        -f|--file|--exclude-file|--scope-file|--metadata-csv) COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
        -o|--output) COMPREPLY=( $(compgen -d -- "$cur") ); return ;;
    esac
    COMPREPLY=( $(compgen -W "{words}" -- "$cur") )
}}
complete -F _scanrunner_completion scanrunner
"""

    if shell == "zsh":
        return f"""#compdef scanrunner
_scanrunner() {{
  _arguments -C \\
    '(-f --file)'{{-f,--file}}'[target file]:file:_files' \\
    '(-i --ip)'{{-i,--ip}}'[single target]:target:' \\
    '--profile[profile]:profile:({profiles})' \\
    '--template[template]:template:({profiles})' \\
    '--preset[preset]:preset:({profiles})' \\
    '(-nxc --nxc)'{{-nxc,--nxc}}'[NetExec protocol]:protocol:({protocols})' \\
    '--nxc-query[NXC result fields]:query:({queries})' \\
    '(-ok --skip-no-ping)'{{-ok,--skip-no-ping}}'[auto-skip wrapper ping failures]' \\
    '(-o --output)'{{-o,--output}}'[output directory]:directory:_directories' \\
    '*:argument:'
}}
_scanrunner "$@"
"""
    raise ValueError("completion shell must be zsh or bash")


def handle_topic_help():
    """Route standalone version/help requests before argparse validation."""
    arguments = sys.argv[1:]

    if len(arguments) == 2 and arguments[0] == "--completion":
        shell = arguments[1].lower()
        if shell not in {"zsh", "bash"}:
            print("scanrunner: error: --completion supports only zsh or bash",
                  file=sys.stderr)
            sys.exit(2)
        print(completion_script(shell), end="")
        sys.exit(0)

    # Standalone version commands must not require a target. Keep ``-v``
    # available to Nmap whenever a target was supplied.
    if arguments in (["-v"], ["--version"]):
        print(f"scanrunner {__version__}")
        sys.exit(0)

    if not arguments or arguments in (["-h"], ["--help"]):
        print(TOP_LEVEL_HELP.strip())
        sys.exit(0)

    # Any help request associated with NXC belongs to scanrunner's focused
    # NXC page. Do not forward -h to NetExec and do not start a scan.
    if any(arg in {"-nxc", "--nxc"} for arg in arguments) and any(
        arg in {"-h", "--help"} for arg in arguments
    ):
        print_topic_help("nxc")
        sys.exit(0)
    topic_aliases = {
        "nxc": "nxc", "netexec": "nxc", "template": "templates",
        "templates": "templates", "profile": "templates", "preset": "templates",
        "split": "split", "nmap": "nmap", "reports": "reports", "automation": "reports",
    }
    topic = None

    if len(arguments) == 2 and arguments[0] in {"-h", "--help"}:
        topic = topic_aliases.get(arguments[1].lower())
        option = OPTION_ALIASES.get(arguments[1].lower())
        if option:
            print_option_help(option)
            sys.exit(0)
    elif len(arguments) == 2 and arguments[1] in {"-h", "--help"}:
        option_topics = {
            "-nxc": "nxc", "--nxc": "nxc", "--split": "split", "--split-size": "split",
            "--profile": "templates", "--template": "templates", "--preset": "templates",
            "--nmap": "nmap", "--reports": "reports",
        }
        topic = option_topics.get(arguments[0])
        option = OPTION_ALIASES.get(arguments[0])
        if option:
            print_option_help(option)
            sys.exit(0)
    elif len(arguments) == 2 and arguments[1] == "-vv":
        if arguments[0] in {"--profile", "--template", "--preset"}:
            print_template_catalog()
            sys.exit(0)
    elif len(arguments) == 1 and arguments[0].startswith("--") and arguments[0].endswith("-help"):
        topic = topic_aliases.get(arguments[0][2:-5].lower())
    elif arguments == ["--list-templates"]:
        print_template_catalog()
        sys.exit(0)
    elif arguments == ["--help-all"]:
        print_all_option_help()
        sys.exit(0)

    if topic:
        print_topic_help(topic)
        sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    handle_topic_help()
    parser = argparse.ArgumentParser(
        prog="scanrunner",
        add_help=False,
        formatter_class=ScanrunnerHelpFormatter,
        usage="scanrunner (-f FILE | -i TARGET) [mode/options] [scanner arguments]",
    )
    target_group = parser.add_argument_group("Target input (choose one)")
    src = target_group.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--file",   metavar="FILE",
                     help="Text file with one IP/host per line")
    src.add_argument("-i", "--ip",     metavar="TARGET",
                     help="Single IP or CIDR subnet  (e.g. 10.0.0.0/24)")

    mode_group = parser.add_argument_group("Target preparation")
    mode_group.add_argument("--split", type=int, metavar="N",
                            help="Split --file into N balanced files and exit")
    mode_group.add_argument("--split-size", type=int, metavar="N",
                            help="Split --file into files of N targets each and exit")

    nmap_group = parser.add_argument_group("Nmap scan options")
    nmap_group.add_argument("--profile", "--template", "--preset", dest="profile",
                            choices=sorted(SCAN_PROFILES), metavar="NAME",
                            help="Use a named Nmap template (see --template -h)")
    nmap_group.add_argument("--exclude", action="append", default=[], metavar="TARGET",
                            help="Exclude target or CIDR (repeatable)")
    nmap_group.add_argument("--exclude-file", metavar="FILE",
                            help="File containing Nmap exclusions")

    nxc_group = parser.add_argument_group("NetExec (NXC) mode")
    nxc_group.add_argument("-nxc", "--nxc", metavar="PROTOCOL",
                           help="Run NXC protocol, e.g. smb, rdp, ldap")
    nxc_group.add_argument("--nxc-query", action="append", default=[], metavar="QUERY",
                           help="Table fields; see -nxc -h")

    workflow_group = parser.add_argument_group("Scan workflow")
    workflow_group.add_argument("--yes", action="store_true",
                        help="Run non-interactively; rescan incomplete reports")
    workflow_group.add_argument("--resume", action="store_true",
                        help="Skip targets with completed reports without prompting")
    workflow_group.add_argument("--skip-ping", action="store_true",
                        help="Skip wrapper ping checks; Nmap still performs discovery")
    workflow_group.add_argument("-ok", "--skip-no-ping", dest="skip_no_ping",
                        action="store_true",
                        help="Automatically skip and log targets that fail wrapper ping")
    workflow_group.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    workflow_group.add_argument("--scope-file", metavar="FILE",
                        help="Allowlist file; refuse targets outside this scope")
    workflow_group.add_argument("--retries", type=int, default=0, metavar="N",
                        help="Retry failed scans up to N times")
    workflow_group.add_argument("--parallel", type=int, default=1, metavar="N",
                                help="Run up to N non-interactive scans concurrently")
    workflow_group.add_argument("--no-auto-tabs", action="store_true",
                                help=argparse.SUPPRESS)

    report_group = parser.add_argument_group("Output and reporting")
    report_group.add_argument("-o", "--output", metavar="DIR", default=None,
                              help="Output folder (default: results; current dir for -nxc)")
    report_group.add_argument("--metadata-csv", metavar="FILE",
                        help="CSV with target,owner,environment columns")
    report_group.add_argument("--html-report", action="store_true",
                        help="Create an HTML open-port report")


    args, nmap_extra = parser.parse_known_args()
    # Keep the raw token list — do NOT join then re-split.
    # Joining then shlex.split-ing loses spaces inside quoted args
    # e.g. --script-args "user=admin pass=hi" becomes two broken tokens.
    if args.retries < 0 or args.parallel < 1:
        parser.error("--retries must be zero or greater and --parallel must be at least 1")
    if args.split is not None and args.split_size is not None:
        parser.error("use only one of --split or --split-size")
    if args.split is not None:
        if not args.file:
            parser.error("--split requires --file")
        if args.split < 1:
            parser.error("--split must be at least 1")
        if args.nxc:
            parser.error("--split cannot be used with --nxc")
    if args.split_size is not None:
        if not args.file:
            parser.error("--split-size requires --file")
        if args.split_size < 1:
            parser.error("--split-size must be at least 1")
        if args.nxc:
            parser.error("--split-size cannot be used with --nxc")
    nxc_queries = []
    for value in args.nxc_query:
        nxc_queries.extend(query.strip().lower() for query in value.split(",") if query.strip())
    invalid_queries = set(nxc_queries) - NXC_QUERY_CHOICES
    if invalid_queries:
        parser.error("unknown --nxc-query value(s): " + ", ".join(sorted(invalid_queries)))
    if nxc_queries and not args.nxc:
        parser.error("--nxc-query requires --nxc")
    args.nxc_queries = list(dict.fromkeys(nxc_queries))
    if args.parallel > 1 and not args.yes:
        parser.error("--parallel requires --yes because interactive controls are unavailable")
    if args.nxc:
        unsupported_nxc_options = []
        if args.profile:
            unsupported_nxc_options.append("--profile/--template/--preset")
        if args.exclude:
            unsupported_nxc_options.append("--exclude")
        if args.exclude_file:
            unsupported_nxc_options.append("--exclude-file")
        if args.resume:
            unsupported_nxc_options.append("--resume")
        if args.skip_ping:
            unsupported_nxc_options.append("--skip-ping")
        if args.skip_no_ping:
            unsupported_nxc_options.append("-ok/--skip-no-ping")
        if args.retries:
            unsupported_nxc_options.append("--retries")
        if args.parallel > 1:
            unsupported_nxc_options.append("--parallel")
        if args.metadata_csv:
            unsupported_nxc_options.append("--metadata-csv")
        if args.html_report:
            unsupported_nxc_options.append("--html-report")
        if unsupported_nxc_options:
            parser.error("NXC mode does not support: " + ", ".join(unsupported_nxc_options))
    if args.profile:
        nmap_extra = SCAN_PROFILES[args.profile] + nmap_extra
    if args.exclude:
        nmap_extra.extend(["--exclude", ",".join(args.exclude)])
    if args.exclude_file:
        nmap_extra.extend(["--excludefile", args.exclude_file])
    args.nmap_extra = nmap_extra   # list of strings, used directly in _build_nmap_command
    args.nmap_args  = " ".join(nmap_extra)   # human-readable display only
    if args.output is None:
        args.output = "." if args.nxc else "results"
    return args



def normalize_target(raw):
    """Normalize URLs/host:port input into a scanner-friendly host target."""
    target = str(raw).strip()
    if not target:
        return ""

    # Preserve CIDR targets exactly; ipaddress validates both IPv4 and IPv6.
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            pass

    # URL input: keep only the hostname.
    if "://" in target:
        try:
            parsed = urlsplit(target)
            if parsed.hostname:
                return parsed.hostname
        except ValueError:
            return target

    # Bracketed IPv6 with an optional port: [2001:db8::1]:443
    bracketed = re.fullmatch(r"\[([0-9A-Fa-f:]+)\](?::\d+)?", target)
    if bracketed:
        return bracketed.group(1)

    # host:port / IPv4:port. Avoid touching raw IPv6 literals containing
    # multiple colons.
    if target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        if host and port.isdigit():
            return host

    return target


def resolve_scan_target(target, timeout=8):
    """Resolve a hostname with a bounded timeout.

    Returns (resolved_target, message). IP literals and CIDRs are returned
    unchanged. A failed/timeout lookup also returns the original hostname so
    Nmap can still apply its own resolver when appropriate.
    """
    target = normalize_target(target)

    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
            return target, "CIDR target; DNS resolution not required"
        ipaddress.ip_address(target)
        return target, "IP target; DNS resolution not required"
    except ValueError:
        pass

    result = {}
    error = {}

    def _lookup():
        try:
            infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            addresses = []
            for info in infos:
                address = info[4][0]
                if address not in addresses:
                    addresses.append(address)
            if addresses:
                result["address"] = addresses[0]
        except Exception as exc:
            error["error"] = exc

    worker = threading.Thread(target=_lookup, daemon=True)
    worker.start()
    worker.join(timeout)

    if worker.is_alive():
        return target, f"DNS resolution timed out after {timeout}s; using hostname"
    if "address" in result:
        return result["address"], f"{target} resolved to {result['address']}"
    if "error" in error:
        return target, f"DNS resolution failed for {target}: {error['error']}"
    return target, f"DNS resolution returned no address for {target}; using hostname"


def load_targets(path):
    """Load normalized unique targets, ignoring blank lines and comments."""
    try:
        with open(path, encoding="utf-8-sig") as file:
            raw_targets = []
            for line in file:
                cleaned = strip_inline_comment(line)
                if not cleaned:
                    continue
                normalized = normalize_target(cleaned)
                if normalized:
                    raw_targets.append(normalized)
    except OSError as error:
        print(c(C.RED + C.BOLD, f"  [!] Cannot read target file: {error}"))
        sys.exit(1)
    return list(dict.fromkeys(raw_targets))


def split_target_file(path, targets, parts):
    """Write balanced target-list parts beside the source file."""
    if parts > len(targets):
        print(c(C.RED + C.BOLD,
                f"  [!] Cannot split {len(targets)} unique target(s) into {parts} files."))
        print(c(C.YELLOW,
                f"      Choose a number from 1 to {len(targets)}, "
                "or use --split-size to split by group size instead "
                "(e.g. --split-size 50 for ~50 targets per file)."))
        sys.exit(1)

    source_path = os.path.abspath(path)
    directory, filename = os.path.split(source_path)
    stem, extension = os.path.splitext(filename)
    extension = extension or ".txt"
    base_size, remainder = divmod(len(targets), parts)
    offset = 0
    output_paths = []

    for index in range(1, parts + 1):
        size = base_size + (1 if index <= remainder else 0)
        output_path = os.path.join(directory, f"{stem}_part_{index}{extension}")
        with open(output_path, "w", encoding="utf-8") as file:
            file.write("\n".join(targets[offset:offset + size]) + "\n")
        output_paths.append(output_path)
        offset += size

    print(c(C.GREEN + C.BOLD,
            f"  [+] Target file split into {parts} file(s). Original file is unchanged."))
    for output_path in output_paths:
        print(c(C.CYAN, f"      {output_path}"))


def strip_ansi(value):
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)


def parse_nxc_output(output, targets, null_auth_attempt=False):
    """Extract host facts from NetExec's human-readable protocol output."""
    rows = {target: {"target": target, "port": "", "hostname": "", "os": "",
                     "smbv1": "", "smb_signing": "", "null_auth": "",
                     "rdp_nla": "", "details": ""} for target in targets}
    line_pattern = re.compile(
        r"\b([A-Z]+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*)$", re.IGNORECASE)

    for raw_line in output.splitlines():
        line = strip_ansi(raw_line).strip()
        match = line_pattern.search(line)
        if not match:
            continue
        _, target, port, hostname, details = match.groups()
        row = rows.setdefault(target, {"target": target, "port": "", "hostname": "",
                                       "os": "", "smbv1": "", "smb_signing": "",
                                       "null_auth": "", "rdp_nla": "", "details": ""})
        row["port"] = port
        if hostname not in {"None", "(null)", "-"}:
            row["hostname"] = hostname
        row["details"] = details

        name = re.search(r"\(name:([^)]*)\)", details, re.IGNORECASE)
        if name:
            row["hostname"] = name.group(1)
        operating_system = details.split(" (name:", 1)[0]
        if operating_system.startswith("[*] "):
            operating_system = operating_system[4:]
        operating_system = operating_system.strip()
        if operating_system and not operating_system.startswith(("[+]", "[-]", "[!]") ):
            row["os"] = operating_system
        for field, pattern in (
            ("smbv1", r"SMBv1:(True|False|None)"),
            ("smb_signing", r"signing:(True|False|None)"),
            ("rdp_nla", r"NLA:(True|False|None)"),
        ):
            value = re.search(pattern, details, re.IGNORECASE)
            if value:
                row[field] = value.group(1)
        if null_auth_attempt and "[+]" in details:
            row["null_auth"] = "Success"

    return list(rows.values())


def nxc_table_columns(protocol, queries):
    if not queries:
        return [("target", "Target"), ("port", "Port"), ("hostname", "Hostname"),
                ("details", "Details")]
    if "all" in queries:
        queries = ["os", "hostname", "smbv1", "smb-signing", "null-auth", "rdp-nla"]
    columns = [("target", "Target")]
    fields = {
        "os": ("os", "OS"), "hostname": ("hostname", "Hostname"),
        "smbv1": ("smbv1", "SMBv1"), "smb-signing": ("smb_signing", "SMB Signing"),
        "null-auth": ("null_auth", "Null Auth"), "rdp-nla": ("rdp_nla", "RDP NLA"),
    }
    for query in queries:
        field = fields[query]
        if field not in columns:
            columns.append(field)
    return columns


def print_nxc_table(rows, columns):
    widths = {field: max(len(title), *(len(str(row.get(field, ""))) for row in rows))
              for field, title in columns}
    widths = {field: min(width, 46) for field, width in widths.items()}

    def format_row(row):
        return "  ".join(str(row.get(field, ""))[:widths[field]].ljust(widths[field])
                         for field, _ in columns)

    print(c(C.CYAN + C.BOLD, "  NXC RESULTS"))
    print(c(C.DIM, "  " + format_row({field: title for field, title in columns})))
    print(c(C.DIM, "  " + "  ".join("-" * widths[field] for field, _ in columns)))
    for row in rows:
        print(c(C.WHITE, "  " + format_row(row)))


def uses_anonymous_nxc_credentials(options):
    """Return whether NXC was explicitly invoked with empty user and password values."""
    values = {}
    for index, option in enumerate(options[:-1]):
        if option in {"-u", "--username"}:
            values["username"] = options[index + 1]
        elif option in {"-p", "--password"}:
            values["password"] = options[index + 1]
    for option in options:
        if option.startswith("--username="):
            values["username"] = option.split("=", 1)[1]
        elif option.startswith("--password="):
            values["password"] = option.split("=", 1)[1]
    return values.get("username") == "" and values.get("password") == ""


def run_nxc(binary, protocol, target_source, targets, nxc_extra, queries, output_dir):
    """Run NetExec with live output, then build table exports."""
    if queries and protocol.lower() not in {"smb", "rdp"}:
        print(c(C.YELLOW,
                "  [!] Focused queries are currently parsed only from SMB/RDP output."))

    effective_extra = list(nxc_extra)
    if "null-auth" in queries and not any(option in effective_extra
                                           for option in ("-u", "--username", "-p", "--password")):
        effective_extra.extend(["-u", "", "-p", ""])

    command = [binary, protocol, target_source, *effective_extra]
    print(c(C.DIM, "  Command : " + " ".join(redact_command(command))))
    print(c(C.DIM, "─" * 70))

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(c(C.RED, f"  [!] NetExec binary not found: {binary}"))
        return False

    captured = []
    assert process.stdout is not None
    for line in process.stdout:
        captured.append(line)
        print(line, end="")
    process.wait()
    output = "".join(captured)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    raw_path = os.path.join(output_dir, f"nxc-{sanitize_filename(protocol)}-{timestamp}.txt")
    with open(raw_path, "w", encoding="utf-8") as file:
        file.write(output)

    print(c(C.DIM, "─" * 70))
    rows = parse_nxc_output(
        output, targets,
        null_auth_attempt=uses_anonymous_nxc_credentials(effective_extra),
    )
    columns = nxc_table_columns(protocol, queries)
    print_nxc_table(rows, columns)

    fieldnames = [field for field, _ in columns]
    csv_path = os.path.join(output_dir, f"nxc-{sanitize_filename(protocol)}-{timestamp}.csv")
    json_path = os.path.join(output_dir, f"nxc-{sanitize_filename(protocol)}-{timestamp}.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fieldnames} for row in rows)
    with open(json_path, "w", encoding="utf-8") as file:
        json.dump([{field: row.get(field, "") for field in fieldnames} for row in rows], file, indent=2)

    print(c(C.GREEN, f"  [+] Saved NXC output: {raw_path}"))
    print(c(C.GREEN, f"  [+] Saved table data: {csv_path}, {json_path}"))
    if process.returncode != 0:
        print(c(C.RED, f"  [!] NetExec exited with status {process.returncode}. See raw output above."))
    return process.returncode == 0



# ═══════════════════════════════════════════════════════════════════════════════
#  PING
# ═══════════════════════════════════════════════════════════════════════════════

def ping_host(ip):
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        timeout = "1000" if sys.platform == "darwin" else "1"
        cmd = ["ping", "-c", "1", "-W", timeout, ip]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN FILE INSPECTION
# ═══════════════════════════════════════════════════════════════════════════════

def get_file_status(filepath):
    try:
        with open(filepath, "rb") as f:
            f.seek(max(0, os.path.getsize(filepath) - 4096))
            tail = f.read().decode(errors="ignore")
        return "COMPLETE" if "Nmap done" in tail else "INCOMPLETE"
    except Exception:
        return "UNKNOWN"

def show_last_lines(filepath, lines=15):
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.readlines()
        sep()
        print(c(C.CYAN, f"  Last {lines} lines"))
        sep()
        for line in content[-lines:]:
            print(c(C.DIM, "  " + line.rstrip()))
        sep()
    except Exception as e:
        print(c(C.RED, f"  [!] Error reading file: {e}"))

def display_existing_scan(filepath):
    status       = get_file_status(filepath)
    stat         = os.stat(filepath)
    modified     = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    size_kb      = round(stat.st_size / 1024, 2)
    status_color = C.GREEN if status == "COMPLETE" else C.YELLOW

    print(c(C.BLUE + C.BOLD, "\n  ╔══ Existing Scan Found " + "═" * 44))
    print(c(C.BLUE + C.BOLD, "  ║"))
    print(c(C.BLUE + C.BOLD, "  ║  ") + f"Status   : {c(status_color + C.BOLD, status)}")
    print(c(C.BLUE + C.BOLD, "  ║  ") + f"Modified : {c(C.WHITE, modified)}")
    print(c(C.BLUE + C.BOLD, "  ║  ") + f"Size     : {c(C.WHITE, str(size_kb) + ' KB')}")
    print(c(C.BLUE + C.BOLD, "  ╚" + "═" * 66))
    show_last_lines(filepath)

def view_full_report(filepath):
    pager = "less" if shutil.which("less") else "cat"
    subprocess.run([pager, filepath])


# ═══════════════════════════════════════════════════════════════════════════════
#  OPEN PORTS PARSER
#  Reads a completed nmap .txt file and returns a list of open port strings.
# ═══════════════════════════════════════════════════════════════════════════════

def parse_open_ports(filepath):
    """Return list of 'port/service' strings from an nmap normal-output file."""
    ports = []
    if not os.path.exists(filepath):
        return ports
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                # Match lines like: 22/tcp   open  ssh
                m = re.match(r"^\s*(\d+/\w+)\s+open\s+(\S+)", line)
                if m:
                    ports.append(f"{m.group(1)}/{m.group(2)}")
    except Exception:
        pass
    return ports


# ═══════════════════════════════════════════════════════════════════════════════
#  PROGRESS BAR
#  FIX: progress_bar(current, total) called with current=idx BEFORE scanning.
#  Now uses 0-based pre-scan index so 100% only shows when all done.
# ═══════════════════════════════════════════════════════════════════════════════

def progress_bar(done, total):
    """done = number of IPs fully processed so far (before current scan)."""
    percent = (done / total) * 100
    filled  = int(40 * done / total)
    bar     = "█" * filled + "░" * (40 - filled)
    print()
    print(
        c(C.BOLD,            f"  Progress  [{c(C.CYAN, bar)}{C.BOLD}]  ") +
        c(C.YELLOW + C.BOLD, f"{percent:.1f}%") +
        c(C.DIM,             f"  ({done}/{total})  {total - done} remaining")
    )
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  NMAP — BUILD COMMAND
# ═══════════════════════════════════════════════════════════════════════════════

def _build_nmap_command(target, output_file, nmap_extra, use_pn=False):
    cmd = ["nmap"]

    # Show Nmap progress every 15 seconds
    if not has_nmap_option(nmap_extra, "--stats-every"):
        cmd.extend(["--stats-every", "15s"])

    if use_pn and not has_nmap_option(nmap_extra, "-Pn"):
        cmd.append("-Pn")

    if nmap_extra:
        cmd.extend(nmap_extra)

    xml_file = f"{os.path.splitext(output_file)[0]}.xml"
    cmd.extend(["-oN", output_file, "-oX", xml_file, "--", target])

    return cmd
   


# ═══════════════════════════════════════════════════════════════════════════════
#  RAW-SAFE OUTPUT
#
#  When the key-watcher calls tty.setraw(), the terminal stops translating
#  \n → \r\n for ALL threads including main.  Every print() then starts from
#  wherever the cursor already is, scattering lines across the screen.
#
#  Fix: all output inside run_nmap_scan uses rprint() which writes \r\n
#  explicitly, guaranteeing every line starts at column 0 regardless of
#  terminal mode.
# ═══════════════════════════════════════════════════════════════════════════════

def _rprint(text=""):
    """Print with \r\n so output is always column-0 even in raw tty mode."""
    sys.stdout.write(text + "\r\n")
    sys.stdout.flush()

def _rticker(text):
    """Overwrite current line in-place (for live timer). No newline."""
    sys.stdout.write("\r" + text + "  ")
    sys.stdout.flush()

def _rclear():
    """Clear the current ticker line before printing real output."""
    sys.stdout.write("\r" + " " * 72 + "\r")
    sys.stdout.flush()


def run_nmap_scan(target, output_file, nmap_extra, use_pn=False):
    cmd = _build_nmap_command(target, output_file, nmap_extra, use_pn)

    _rprint(c(C.DIM, "  Command : " + " ".join(cmd)))
    _rprint(c(C.DIM, "─" * 70))

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
    except FileNotFoundError:
        _rprint(c(C.RED, "  [!] nmap binary not found."))
        return False

    skip_flag        = threading.Event()
    abort_flag       = threading.Event()
    status_requested = threading.Event()
    _proc_done       = threading.Event()

    line_queue    = queue.Queue()
    stdin_is_tty  = sys.stdin.isatty()
    open_ports    = []   # track open ports found so far for Space status

    # ── stdout reader thread ──────────────────────────────────────────────────
    def _read_stdout():
        try:
            for raw in proc.stdout:
                line_queue.put(raw)
        except Exception:
            pass
        finally:
            line_queue.put(None)

    reader = threading.Thread(target=_read_stdout, daemon=True)
    reader.start()

    # ── key watcher thread ────────────────────────────────────────────────────
    # Runs in raw mode — catches Space / Ctrl+X / Ctrl+C as raw bytes.
    def _watch_keys():
        if not stdin_is_tty or not RAW_MODE_SUPPORTED:
            return
        fd = sys.stdin.fileno()
        try:
            tty.setraw(fd)
            while not skip_flag.is_set() and not _proc_done.is_set() \
                    and not abort_flag.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch == "\x18":       # Ctrl+X — skip host
                        skip_flag.set()
                        break
                    elif ch == "\x03":     # Ctrl+C — full abort
                        abort_flag.set()
                        break
                    elif ch == " ":        # Space — request status
                        status_requested.set()
                        try:
                            # Best-effort: if nmap is on a real tty it prints
                            # its own % line; piped stdout silently ignores it
                            os.kill(proc.pid, signal.SIGWINCH)
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            restore_terminal()

    watcher    = threading.Thread(target=_watch_keys, daemon=True)
    scan_start = time.time()
    watcher.start()

    # ── terminal width ────────────────────────────────────────────────────────
    try:
        term_width = shutil.get_terminal_size(fallback=(120, 24)).columns
    except Exception:
        term_width = 120
    PREFIX_LEN = 10   # "  [MM:SS] " without ANSI codes

    # ── main output loop ──────────────────────────────────────────────────────
    while True:
        if skip_flag.is_set() or abort_flag.is_set():
            break

        # ── Space: print clean status block ──────────────────────────────────
        if status_requested.is_set():
            elapsed  = int(time.time() - scan_start)
            mins, secs = divmod(elapsed, 60)
            _rclear()
            _rprint()
            _rprint(c(C.CYAN + C.BOLD,  "  ┌─ STATUS " + "─" * 40))
            _rprint(c(C.CYAN + C.BOLD,  f"  │  Target  : ") + c(C.WHITE, target))
            _rprint(c(C.CYAN + C.BOLD,  f"  │  Elapsed : ") + c(C.YELLOW + C.BOLD, f"{mins:02d}:{secs:02d}"))
            _rprint(c(C.CYAN + C.BOLD,  f"  │  PID     : ") + c(C.WHITE, str(proc.pid)))
            if open_ports:
                _rprint(c(C.CYAN + C.BOLD, f"  │  Open    : ") +
                        c(C.GREEN, "  ".join(open_ports)))
            else:
                _rprint(c(C.CYAN + C.BOLD, f"  │  Open    : ") + c(C.DIM, "none yet"))
            _rprint(c(C.CYAN + C.BOLD,  "  └" + "─" * 50))
            _rprint()
            status_requested.clear()

        # ── Try to get a line from nmap ───────────────────────────────────────
        try:
            raw_line = line_queue.get(timeout=0.2)
        except queue.Empty:
            if proc.poll() is not None and line_queue.empty():
                break
            # No nmap output right now — update live timer in place
            elapsed = int(time.time() - scan_start)
            mins, secs = divmod(elapsed, 60)
            _rticker(
                c(C.DIM, f"  [{mins:02d}:{secs:02d}]") +
                c(C.DIM,  f"  scanning {target}") +
                (c(C.GREEN, f"  |  {len(open_ports)} open") if open_ports else "") +
                (c(C.DIM, "   Space=status  Ctrl+X=skip  Ctrl+C=exit")
                 if stdin_is_tty and RAW_MODE_SUPPORTED else "")
            )
            continue

        if raw_line is None:   # sentinel
            break

        # ── Got a line — clear ticker, then print ─────────────────────────────
        _rclear()

        line    = raw_line.rstrip()
        elapsed = int(time.time() - scan_start)
        mins, secs = divmod(elapsed, 60)
        ts      = c(C.DIM, f"  [{mins:02d}:{secs:02d}] ")

        max_content = term_width - PREFIX_LEN - 1
        if len(line) > max_content:
            line = line[:max_content - 3] + "..."

        if not line.strip():
            continue
        elif re.search(r'\bopen\b', line) or "Discovered" in line:
            # Track for Space status
            m = re.match(r"^\s*(\d+/\w+)\s+open\s+(\S+)", line)
            if m:
                entry = f"{m.group(1)}/{m.group(2)}"
                if entry not in open_ports:
                    open_ports.append(entry)
            _rprint(ts + c(C.GREEN, line))
        elif re.search(r'\b(closed|filtered)\b', line):
            _rprint(ts + c(C.DIM, line))
        elif any(x in line for x in ["WARNING", "WARN", "failed", "Failed"]):
            _rprint(ts + c(C.YELLOW, line))
        elif line.startswith("Nmap scan report") or line.startswith("Host is"):
            _rprint(ts + c(C.CYAN + C.BOLD, line))
        elif line.startswith("Nmap done"):
            _rprint(ts + c(C.GREEN + C.BOLD, line))
        elif (
    	     line.startswith("Stats:")
    	     or "Timing:" in line
    	     or ("%" in line and "remaining" in line)
         ):
            _rprint(ts + c(C.CYAN + C.BOLD, line))
        else:
            _rprint(ts + c(C.WHITE, line))

    # ── cleanup ───────────────────────────────────────────────────────────────
    _rclear()   # erase any live timer line before printing final output

    if skip_flag.is_set() or abort_flag.is_set():
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        _proc_done.set()
        reader.join(timeout=2)
        watcher.join(timeout=1)
        restore_terminal()

        if abort_flag.is_set():
            raise KeyboardInterrupt

        _rprint(c(C.YELLOW, "─" * 70))
        _rprint(c(C.YELLOW + C.BOLD, f"  [~] Skipped {target}."))
        return "SKIPPED"

    # Natural exit
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass

    elapsed = int(time.time() - scan_start)
    mins, secs = divmod(elapsed, 60)

    _proc_done.set()
    reader.join(timeout=2)
    watcher.join(timeout=1)
    restore_terminal()

    _rprint(c(C.DIM, "─" * 70))

    # If Nmap printed output and produced a report file, treat as success
    if proc.returncode is None:
        return False

    return proc.returncode == 0


def run_nmap_quiet(target, output_file, nmap_extra, use_pn, retries):
    """Run a non-interactive scan, returning success and attempts used."""
    for attempt in range(retries + 1):
        result = subprocess.run(
            _build_nmap_command(target, output_file, nmap_extra, use_pn),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0 and os.path.exists(output_file):
            return True, attempt + 1
    return False, retries + 1


# ═══════════════════════════════════════════════════════════════════════════════
#  OPEN PORTS ONE-LINER  (shown after each completed scan)
# ═══════════════════════════════════════════════════════════════════════════════

def print_open_ports_oneliner(ip, filepath):
    ports = parse_open_ports(filepath)
    if ports:
        ports_str = "  ".join(ports)
        print(c(C.GREEN + C.BOLD, f"  Open  →  ") + c(C.WHITE, ports_str))
    else:
        print(c(C.DIM, "  No open ports found."))
    return ports


def write_inventory(output_dir, targets, metadata, write_html):
    """Write machine-readable port inventory files from completed normal output.

    Merges into any existing inventory rather than overwriting it outright:
    when several scanrunner processes (spawned terminal tabs) share one
    output directory, each only knows its own slice of targets, so a plain
    overwrite would erase whatever the other processes already wrote.
    """
    new_rows = []
    for target in targets:
        details = metadata.get(target, {})
        report = os.path.join(output_dir, f"{sanitize_filename(target)}.txt")
        for port in parse_open_ports(report):
            new_rows.append({
                "target": target,
                "owner": details.get("owner", ""),
                "environment": details.get("environment", ""),
                "port_service": port,
            })

    csv_path = os.path.join(output_dir, "open-ports-inventory.csv")
    json_path = os.path.join(output_dir, "open-ports-inventory.json")
    targets_set = set(targets)

    with _FileLock(csv_path):
        rows = []
        if os.path.exists(json_path):
            try:
                with open(json_path, encoding="utf-8") as file:
                    rows = json.load(file)
            except (json.JSONDecodeError, OSError):
                rows = []
        rows = [row for row in rows if row.get("target") not in targets_set]
        rows.extend(new_rows)

        with open(csv_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["target", "owner", "environment", "port_service"])
            writer.writeheader()
            writer.writerows(rows)
        with open(json_path, "w", encoding="utf-8") as file:
            json.dump(rows, file, indent=2)

        if write_html:
            body = "\n".join(
                "<tr>" + "".join(f"<td>{html.escape(row[column])}</td>"
                                  for column in ("target", "owner", "environment", "port_service")) + "</tr>"
                for row in rows
            ) or "<tr><td colspan=\"4\">No open ports found.</td></tr>"
            report = (
                "<!doctype html><meta charset=\"utf-8\"><title>Scanrunner Inventory</title>"
                "<style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse}"
                "th,td{border:1px solid #ccc;padding:.5rem;text-align:left}</style>"
                "<h1>Scanrunner Open-Port Inventory</h1><table><tr><th>Target</th><th>Owner</th>"
                f"<th>Environment</th><th>Port / Service</th></tr>{body}</table>"
            )
            with open(os.path.join(output_dir, "open-ports-report.html"), "w", encoding="utf-8") as file:
                file.write(report)


# ═══════════════════════════════════════════════════════════════════════════════
#  SUMMARY BOX + OPEN PORTS TABLE
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(ips, completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file, output_dir):
    completed_ips = read_logged_ips(completed_file)
    skipped_ips   = read_logged_ips(skipped_file)
    rescanned_ips = read_logged_ips(rescanned_file)
    no_ping_ips   = read_logged_ips(not_ping_file)
    failed_ips    = read_logged_ips(failed_file)

    print()
    print(c(C.BOLD, "  ╔══════════════════════════════╗"))
    print(c(C.BOLD, "  ║       SCAN SUMMARY           ║"))
    print(c(C.BOLD, "  ╠══════════════════════════════╣"))
    print(c(C.BOLD, "  ║  ") + c(C.GREEN  + C.BOLD, f"  Completed : {len(completed_ips):<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.YELLOW + C.BOLD, f"  Skipped   : {len(skipped_ips):<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.CYAN   + C.BOLD, f"  Rescanned : {len(rescanned_ips):<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.ORANGE + C.BOLD, f"  No Ping   : {len(no_ping_ips):<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.RED    + C.BOLD, f"  Failed    : {len(failed_ips):<5}")    + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ╚══════════════════════════════╝"))

    # ── Reconciliation — every input target must land in some audit log ───────
    # This is the safety net: a target that isn't completed, skipped, logged as
    # unreachable, or logged as failed has NO recorded outcome at all (e.g. the
    # run was interrupted before reaching it). That must never pass silently.
    accounted = completed_ips | skipped_ips | no_ping_ips | failed_ips
    unaccounted = [ip for ip in ips if ip not in accounted]
    print()
    if unaccounted:
        unaccounted_path = os.path.join(output_dir, "unaccounted.txt")
        with _FileLock(unaccounted_path):
            existing = set()
            if os.path.exists(unaccounted_path):
                with open(unaccounted_path, encoding="utf-8") as f:
                    existing = {line.strip() for line in f if line.strip()}
            with open(unaccounted_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(existing | set(unaccounted))) + "\n")
        sep(C.RED, "!")
        print(c(C.RED + C.BOLD,
                f"  [!] WARNING: {len(unaccounted)} target(s) have NO recorded outcome "
                "(scan likely interrupted before reaching them):"))
        for ip in unaccounted:
            print(c(C.RED, f"      {ip}"))
        print(c(C.RED, f"  [!] Saved to: {unaccounted_path}"))
        print(c(C.RED, "  [!] Re-run with --resume to pick these up, or investigate before reporting results."))
        sep(C.RED, "!")
    else:
        print(c(C.GREEN, f"  [+] Reconciliation OK — all {len(ips)} input target(s) are accounted for."))

    # ── Open ports table across all completed hosts ───────────────────────────
    host_ports = {}
    if os.path.exists(completed_file):
        with open(completed_file, encoding="utf-8") as f:
            done_ips = [line.split("|")[-1].strip() for line in f if line.strip()]
        for ip in dict.fromkeys(done_ips):   # unique, preserve order
            fp = os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")
            ports = parse_open_ports(fp)
            if ports:
                host_ports[ip] = ports

    if host_ports:
        print()
        sep(C.CYAN, "═")
        print(c(C.CYAN + C.BOLD, "  OPEN PORTS SUMMARY"))
        sep(C.CYAN, "═")
        col = 20   # IP column width
        print(c(C.BOLD, f"  {'HOST':<{col}}  OPEN PORTS"))
        sep()
        for ip, ports in host_ports.items():
            ports_str = "  ".join(ports)
            print(c(C.WHITE, f"  {ip:<{col}}") + "  " + c(C.GREEN, ports_str))
        sep()

    print()
    print(c(C.GREEN + C.BOLD, "  All done.\n"))


# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL TAB SPLITTING
#
#  When an interactive run has a large pending target list, offer to split it
#  across separate terminal tabs/windows instead of scanning everything, one
#  host at a time, in this single window. Each tab gets its own target file
#  (under output_dir/tabs/) but all tabs write their scan reports straight
#  into the shared output_dir, since per-host filenames are unique by IP and
#  never collide. The files that get rewritten wholesale instead of appended
#  (the inventory CSV/JSON, unaccounted.txt) are merged under a file lock
#  (see _FileLock) so one tab finishing can't clobber another's results. A
#  manifest mapping every target to its tab is always written to disk for
#  the audit trail.
# ═══════════════════════════════════════════════════════════════════════════════

def _build_tab_command(args):
    """Rebuild the scanrunner invocation used for a spawned tab.

    args.nmap_extra already has --profile/--exclude/--exclude-file folded in
    by parse_args(), so passing it through covers all raw Nmap arguments.
    Every remaining scanrunner-level flag that should carry over to the tab
    is re-added explicitly. --yes is forced because prompts cannot sensibly
    be answered across several independent windows; --no-auto-tabs prevents
    a spawned tab from re-triggering this same prompt on its own sub-list.
    """
    cmd = [sys.executable, os.path.abspath(__file__)]
    cmd.extend(args.nmap_extra)
    if args.retries:
        cmd.extend(["--retries", str(args.retries)])
    if args.skip_ping:
        cmd.append("--skip-ping")
    if args.skip_no_ping:
        cmd.append("-ok")
    if args.no_color:
        cmd.append("--no-color")
    if args.scope_file:
        cmd.extend(["--scope-file", args.scope_file])
    if args.metadata_csv:
        cmd.extend(["--metadata-csv", args.metadata_csv])
    if args.html_report:
        cmd.append("--html-report")
    cmd.extend(["--yes", "--no-auto-tabs"])
    return cmd


def _spawn_windows_terminal(command, title, cwd):
    wt = shutil.which("wt.exe") or shutil.which("wt")
    if wt:
        try:
            subprocess.Popen([wt, "new-tab", "--title", title, "-d", cwd, "--", *command])
            return True
        except OSError:
            pass
    try:
        # cmd /k keeps the window open after the scan finishes so results
        # stay visible; start opens it as a separate window (best effort
        # when Windows Terminal itself is unavailable).
        quoted = subprocess.list2cmdline(command)
        subprocess.Popen(f'start "{title}" cmd /k "{quoted}"', cwd=cwd, shell=True)
        return True
    except OSError:
        return False


def _spawn_macos_terminal(command, title, cwd):
    script_command = " ".join(shlex.quote(part) for part in command)
    apple_script = (
        f'tell application "Terminal" to do script "cd {shlex.quote(cwd)} && {script_command}"'
    )
    try:
        subprocess.Popen(["osascript", "-e", apple_script])
        return True
    except OSError:
        return False


def _spawn_linux_terminal(command, title, cwd):
    if os.environ.get("TMUX"):
        try:
            subprocess.Popen(["tmux", "new-window", "-n", title, "-c", cwd, *command])
            return True
        except OSError:
            pass
    quoted_command = " ".join(shlex.quote(part) for part in command)
    for terminal in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal"):
        path = shutil.which(terminal)
        if not path:
            continue
        try:
            if terminal == "gnome-terminal":
                subprocess.Popen([path, "--title", title, "--working-directory", cwd, "--", *command])
            else:
                subprocess.Popen([path, "-e", quoted_command], cwd=cwd)
            return True
        except OSError:
            continue
    xterm = shutil.which("xterm")
    if xterm:
        try:
            subprocess.Popen([xterm, "-T", title, "-e", *command], cwd=cwd)
            return True
        except OSError:
            pass
    return False


def _spawn_background(command, cwd, log_path):
    """Last-resort fallback when no terminal emulator can be opened.

    Never silently drops a batch of targets: if we can't give it a visible
    tab, it still runs, in the background, with its own log file to watch.
    """
    with open(log_path, "w", encoding="utf-8") as log_file:
        subprocess.Popen(command, cwd=cwd, stdout=log_file, stderr=subprocess.STDOUT)


def offer_terminal_tabs(args, pending_ips, output_dir):
    """Offer to split a large pending list across separate terminal tabs.

    Returns True if tabs were launched (caller should stop; this window does
    not scan anything itself), False if the caller should continue normally.
    """
    if (args.no_auto_tabs or args.yes or not sys.stdin.isatty()
            or args.parallel > 1 or len(pending_ips) < AUTO_TAB_PROMPT_THRESHOLD):
        return False

    print(c(C.CYAN + C.BOLD,
            f"\n  [*] Large target list detected: {len(pending_ips)} targets pending."))
    answer = safe_input(
        c(C.CYAN, f"  Split across separate terminal tabs? Enter number of tabs "
                   f"(2-{len(pending_ips)}), or press Enter to continue in this window: ")
    )
    if not answer:
        return False
    try:
        tab_count = int(answer)
    except ValueError:
        print(c(C.RED, "  [!] Not a number — continuing in this window.\n"))
        return False
    if tab_count < 2 or tab_count > len(pending_ips):
        print(c(C.RED,
                f"  [!] Enter a number from 2 to {len(pending_ips)} — continuing in this window.\n"))
        return False

    tabs_dir = os.path.join(output_dir, "tabs")
    os.makedirs(tabs_dir, exist_ok=True)
    base_size, remainder = divmod(len(pending_ips), tab_count)
    base_command = _build_tab_command(args)
    cwd = os.getcwd()
    manifest_lines = []
    spawned = backgrounded = 0
    offset = 0

    for index in range(1, tab_count + 1):
        size = base_size + (1 if index <= remainder else 0)
        part_targets = pending_ips[offset:offset + size]
        offset += size
        if not part_targets:
            continue

        part_file = os.path.join(tabs_dir, f"tab_{index}_targets.txt")
        with open(part_file, "w", encoding="utf-8") as f:
            f.write("\n".join(part_targets) + "\n")

        command = [*base_command, "-f", part_file, "-o", output_dir]
        title = f"scanrunner tab {index}/{tab_count}"

        if sys.platform == "win32":
            launched = _spawn_windows_terminal(command, title, cwd)
        elif sys.platform == "darwin":
            launched = _spawn_macos_terminal(command, title, cwd)
        else:
            launched = _spawn_linux_terminal(command, title, cwd)

        if launched:
            spawned += 1
        else:
            log_path = os.path.join(tabs_dir, f"tab_{index}_console.log")
            _spawn_background(command, cwd, log_path)
            backgrounded += 1
            print(c(C.YELLOW,
                    f"  [~] No terminal emulator found for tab {index}; "
                    f"running in background instead. Watch: {log_path}"))

        manifest_lines.append(f"tab_{index}\t{output_dir}\t{','.join(part_targets)}")

    manifest_path = os.path.join(output_dir, "tab-manifest.txt")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(manifest_lines) + "\n")

    print(c(C.GREEN + C.BOLD,
            f"\n  [+] Launched {tab_count} tab(s): {spawned} in terminal windows, "
            f"{backgrounded} running in background."))
    print(c(C.CYAN, f"  [i] All tabs write their reports directly into {output_dir}/."))
    print(c(C.CYAN, f"  [i] Target-to-tab manifest saved: {manifest_path}"))
    print(c(C.YELLOW,
            "  [!] This window is not tracking their progress. When they finish, check "
            f"{output_dir}/unaccounted.txt and the open-ports inventory before reporting results.\n"))
    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global COLORS_ENABLED
    _save_terminal()
    args = parse_args()
    COLORS_ENABLED = not args.no_color
    banner()

    if args.split is not None or args.split_size is not None:
        if not os.path.exists(args.file):
            print(c(C.RED + C.BOLD, f"  [!] File not found: {args.file}"))
            sys.exit(1)
        targets = load_targets(args.file)
        if not targets:
            print(c(C.RED + C.BOLD, "  [!] Target file contains no usable targets."))
            sys.exit(1)
        if args.split_size is not None:
            parts = -(-len(targets) // args.split_size)   # ceil division
            print(c(C.DIM,
                    f"  [i] {len(targets)} target(s) ÷ {args.split_size} per file "
                    f"= {parts} file(s)."))
        else:
            parts = args.split
        split_target_file(args.file, targets, parts)
        return

    if args.nxc:
        nxc_binary = check_nxc_installed()
        output_dir = args.output
        os.makedirs(output_dir, exist_ok=True)
        if args.ip:
            normalized_ip = normalize_target(args.ip)
            ips = [normalized_ip]
            target_source = normalized_ip
        else:
            if not os.path.exists(args.file):
                print(c(C.RED + C.BOLD, f"  [!] File not found: {args.file}"))
                sys.exit(1)
            ips = load_targets(args.file)
            target_source = args.file
        if not ips:
            print(c(C.RED + C.BOLD, "  [!] Target file contains no usable targets."))
            sys.exit(1)
        scope = load_scope(args.scope_file)
        out_of_scope = [target for target in ips if not target_in_scope(target, scope)]
        if out_of_scope:
            print(c(C.RED + C.BOLD,
                    "  [!] Refusing targets outside --scope-file: " + ", ".join(out_of_scope)))
            sys.exit(1)
        print(c(C.CYAN, f"  NXC protocol : {args.nxc}"))
        print(c(C.CYAN, f"  Targets      : {len(ips)}"))
        print(c(C.CYAN, f"  Output       : {output_dir}"))
        temporary_target_file = None
        if args.file:
            # NetExec should receive exactly the same cleaned targets scanrunner validated.
            temporary_target_file = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", prefix="scanrunner-nxc-", suffix=".txt", delete=False
            )
            temporary_target_file.write("\n".join(ips) + "\n")
            temporary_target_file.close()
            target_source = temporary_target_file.name
        try:
            success = run_nxc(nxc_binary, args.nxc, target_source, ips, args.nmap_extra,
                              args.nxc_queries, output_dir)
        finally:
            if temporary_target_file:
                try:
                    os.unlink(temporary_target_file.name)
                except OSError:
                    pass
        sys.exit(0 if success else 1)

    check_nmap_installed()

    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    # ── Build target list ─────────────────────────────────────────────────────
    if args.ip:
        normalized_ip = normalize_target(args.ip)
        ips = [normalized_ip]
        print(c(C.CYAN, f"  Target   : {normalized_ip}"))
    else:
        if not os.path.exists(args.file):
            print(c(C.RED + C.BOLD, f"  [!] File not found: {args.file}"))
            sys.exit(1)
        ips = load_targets(args.file)
        print(c(C.CYAN, f"  File     : {args.file}  ({len(ips)} unique targets)"))

    metadata = load_metadata(args.metadata_csv)
    scope = load_scope(args.scope_file)
    out_of_scope = [ip for ip in ips if not target_in_scope(ip, scope)]
    if out_of_scope:
        print(c(C.RED + C.BOLD,
                "  [!] Refusing targets outside --scope-file: " + ", ".join(out_of_scope)))
        sys.exit(1)

    print(c(C.CYAN, f"  Output   : {output_dir}"))
    if args.skip_no_ping:
        print(c(C.CYAN, "  No-ping  : auto-skip enabled (-ok)"))

    # ── --host-timeout warning ────────────────────────────────────────────────
    if args.nmap_args:
        print(c(C.CYAN, f"  Nmap args: {args.nmap_args}"))
    if not has_nmap_option(args.nmap_extra, "--host-timeout"):
        print(c(C.YELLOW,
                "  [!] No --host-timeout set. A hung host will block forever.\n"
                "      Consider adding: --host-timeout 10m"))
    print()

    # ── Log files ─────────────────────────────────────────────────────────────
    completed_file = os.path.join(output_dir, "completed.txt")
    skipped_file   = os.path.join(output_dir, "skipped.txt")
    rescanned_file = os.path.join(output_dir, "rescanned.txt")
    not_ping_file  = os.path.join(output_dir, "not-pingip.txt")
    failed_file    = os.path.join(output_dir, "failed.txt")
    retry_file     = os.path.join(output_dir, "retried.txt")

    def write_reports():
        write_inventory(output_dir, ips, metadata, args.html_report)

    # ── Resume — single prompt ────────────────────────────────────────────────
    completed_ips = set()
    if os.path.exists(completed_file) or args.resume:
        all_done = set()
        if os.path.exists(completed_file):
            with open(completed_file, encoding="utf-8") as f:
                all_done = {line.split("|")[-1].strip() for line in f if line.strip()}
        all_done.update(ip for ip in ips
                        if get_file_status(os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")) == "COMPLETE")
        if all_done:
            print(c(C.BLUE + C.BOLD, f"  Found {len(all_done)} previously completed IP(s)."))
            if args.resume:
                completed_ips = all_done
                # Backfill completed_file: all_done also includes hosts detected
                # purely by inspecting existing report files, which may never
                # have been logged. The audit trail (and the end-of-run
                # reconciliation check) must be able to account for every one.
                for ip in completed_ips:
                    log_to_file(completed_file, ip)
                print(c(C.GREEN,
                        f"  [+] Resuming — {len(completed_ips)} IP(s) will be skipped.\n"))
            else:
                if args.yes:
                    ch = "f"
                else:
                    ch = safe_input(
                        c(C.CYAN, "  [r] Resume (skip completed)  [f] Fresh (review all)  -> ")
                    ).lower()
                if ch == "r":
                    completed_ips = all_done
                    for ip in completed_ips:
                        log_to_file(completed_file, ip)
                    print(c(C.GREEN,
                            f"  [+] Resuming — {len(completed_ips)} IP(s) will be skipped.\n"))
                else:
                    print(c(C.YELLOW, "  [+] Fresh run — all IPs will be reviewed.\n"))

    pending_ips   = [ip for ip in ips if ip not in completed_ips]
    total_pending = len(pending_ips)

    if total_pending == 0:
        print(c(C.GREEN, "  [+] All IPs already completed. Nothing to do."))
        write_reports()
        print_summary(ips, completed_file, skipped_file, rescanned_file,
                      not_ping_file, failed_file, output_dir)
        return

    if offer_terminal_tabs(args, pending_ips, output_dir):
        return

    print(c(C.CYAN + C.BOLD, f"  [*] {total_pending} IP(s) queued.\n"))

    nmap_uses_pn = has_nmap_option(args.nmap_extra, "-Pn")
    if nmap_uses_pn:
        print(c(C.YELLOW,
                "  [*] -Pn detected: wrapper ping checks are disabled.\n"))

    if args.parallel > 1:
        parallel_targets = [ip for ip in pending_ips
                            if get_file_status(os.path.join(
                                output_dir, f"{sanitize_filename(ip)}.txt")) != "COMPLETE"]
        print(c(C.CYAN, f"  [*] Running {len(parallel_targets)} scan(s) with {args.parallel} workers.\n"))
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {
                executor.submit(run_nmap_quiet, ip,
                                os.path.join(output_dir, f"{sanitize_filename(ip)}.txt"),
                                args.nmap_extra, nmap_uses_pn, args.retries): ip
                for ip in parallel_targets
            }
            for future in as_completed(futures):
                ip = futures[future]
                success, attempts = future.result()
                if attempts > 1:
                    log_to_file(retry_file, ip)
                if success:
                    log_to_file(completed_file, ip)
                    print(c(C.GREEN, f"  [+] Completed {ip} ({attempts} attempt(s))"))
                else:
                    log_to_file(failed_file, ip)
                    print(c(C.RED, f"  [x] Failed {ip} after {attempts} attempt(s)"))
        write_reports()
        print_summary(ips, completed_file, skipped_file, rescanned_file,
                      not_ping_file, failed_file, output_dir)
        return

    # ── Scan loop ─────────────────────────────────────────────────────────────
    done_count = 0

    def _show_menu():
        print(
            c(C.CYAN,   "\n  [s] Skip      ") +
            c(C.YELLOW, "[r] Rescan     ") +
            c(C.GREEN,  "[m] Mark done  ") +
            c(C.BLUE,   "[v] View full  ") +
            c(C.RED,    "[q] Quit")
        )

    try:
        for ip in pending_ips:

            # Progress shows how many are DONE before this one starts
            # So it starts at 0% and reaches 100% only after the last host
            progress_bar(done_count, total_pending)

            print(c(C.CYAN  + C.BOLD, f"  ┌─ Target {'─' * 41}"))
            print(c(C.WHITE + C.BOLD, f"  │  {ip}"))
            print(c(C.CYAN  + C.BOLD, f"  └{'─' * 49}"))

            output_file = os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")

            # ── Existing scan file ───────────────────────────────────────────
            action = None   # "scan" | "skip"

            if os.path.exists(output_file):
                display_existing_scan(output_file)
                while True:
                    if args.yes:
                        ch = "s" if get_file_status(output_file) == "COMPLETE" else "r"
                    else:
                        _show_menu()
                        ch = safe_input(c(C.BOLD, "  Choice -> ")).lower()
                    if ch == "s":
                        log_to_file(skipped_file, ip)
                        print(c(C.YELLOW, f"  [~] Skipped {ip}"))
                        action = "skip"
                        break
                    elif ch == "r":
                        log_to_file(rescanned_file, ip)
                        print(c(C.CYAN, f"  Rescanning {ip}"))
                        action = "scan"
                        break
                    elif ch == "m":
                        log_to_file(completed_file, ip)
                        print(c(C.GREEN, f"  [+] Marked {ip} as complete."))
                        action = "skip"
                        break
                    elif ch == "v":
                        view_full_report(output_file)
                    elif ch == "q":
                        print(c(C.RED + C.BOLD, "\n  Quitting."))
                        restore_terminal()
                        print_summary(ips, completed_file, skipped_file, rescanned_file,
                                      not_ping_file, failed_file, output_dir)
                        sys.exit(0)
                    else:
                        print(c(C.RED, "  [!] Invalid — s / r / m / v / q"))
            else:
                action = "scan"

            if action == "skip":
                done_count += 1
                continue

            # ── Ping check ───────────────────────────────────────────────────
            use_pn = nmap_uses_pn

            if nmap_uses_pn:
                print(c(C.DIM, f"\n  Skipping wrapper ping for {ip} (-Pn supplied)."))
            elif args.skip_ping:
                print(c(C.DIM, f"\n  Skipping wrapper ping for {ip} (--skip-ping supplied)."))
            elif is_network_target(ip):
                print(c(C.DIM,
                        f"\n  Skipping wrapper ping for CIDR target {ip}; "
                        "Nmap will perform host discovery."))
            else:
                print(c(C.DIM, f"\n  Pinging {ip} ..."))

            if (not nmap_uses_pn and not args.skip_ping and not is_network_target(ip)
                    and not ping_host(ip)):
                print(c(C.ORANGE + C.BOLD, f"  [-] {ip} did not respond to ping."))

                # -ok / --skip-no-ping is intentionally opt-in. It changes only
                # the wrapper ping-failure decision: no prompt, no -Pn fallback.
                if args.skip_no_ping:
                    log_to_file(not_ping_file, ip)
                    print(c(C.ORANGE,
                            f"  [~] -ok enabled: logged {ip} as no-ping and skipped."))
                    done_count += 1
                    continue

                ping_choice = "n" if args.yes else ""
                while not ping_choice:
                    ping_choice = safe_input(
                        c(C.YELLOW, "  Run nmap with -Pn anyway? [y/n]: ")
                    ).lower()
                    if ping_choice == "y":
                        use_pn = True
                    elif ping_choice == "n":
                        log_to_file(not_ping_file, ip)
                        print(c(C.ORANGE, f"  Logged {ip} as no-ping. Skipping."))
                    else:
                        print(c(C.RED, "  [!] Enter y or n."))
                        ping_choice = ""
                if args.yes:
                    log_to_file(not_ping_file, ip)
                    print(c(C.ORANGE, f"  Logged {ip} as no-ping. Skipping."))
                if ping_choice == "n":
                    done_count += 1
                    continue
            elif not nmap_uses_pn and not args.skip_ping and not is_network_target(ip):
                print(c(C.GREEN, f"  [+] {ip} is alive."))

            # ── Run scan ─────────────────────────────────────────────────────
            print(c(C.MAGENTA + C.BOLD, f"\n  [>] Scanning {ip}"))
            if sys.stdin.isatty() and RAW_MODE_SUPPORTED:
                print(c(C.DIM,
                        "      Space = status   "
                        "Ctrl+X = skip host   "
                        "Ctrl+C = exit\n"))

            start  = time.time()
            attempt = 0
            while True:
                result = run_nmap_scan(ip, output_file, args.nmap_extra, use_pn)
                if result is not False or attempt >= args.retries:
                    break
                attempt += 1
                log_to_file(retry_file, ip)
                print(c(C.YELLOW, f"  [~] Retrying {ip} ({attempt}/{args.retries})"))
            elapsed = round(time.time() - start, 2)

            if result == "SKIPPED":
                log_to_file(skipped_file, ip)

            elif result is True:
                print(c(C.GREEN + C.BOLD, f"\n  [+] Nmap finished {ip} in {elapsed}s"))
                # Wait up to 2s for nmap to flush the file
                for _ in range(4):
                    if os.path.exists(output_file):
                        break
                    time.sleep(0.5)
                if os.path.exists(output_file):
                    log_to_file(completed_file, ip)
                    print(c(C.GREEN, f"  [+] Saved report for {ip}"))
                    print_open_ports_oneliner(ip, output_file)
                else:
                    print(c(C.YELLOW,
                            f"  [!] nmap finished but no output file for {ip}"))
                    log_to_file(failed_file, ip)
            else:
                print(c(C.RED + C.BOLD, f"\n  [x] Scan failed for {ip}  ({elapsed}s)"))
                log_to_file(failed_file, ip)

            done_count += 1
            print()

    except KeyboardInterrupt:
        print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted. Saving progress..."))
        restore_terminal()

    # Final progress bar — 100% when we get here
    progress_bar(done_count, total_pending)
    write_reports()
    print_summary(ips, completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file, output_dir)


if __name__ == "__main__":
    main()

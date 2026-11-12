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
import hashlib
import sqlite3
import uuid
import signal
from pathlib import Path
import xml.etree.ElementTree as ET
from collections import Counter, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

__version__ = "1.3.0"

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

                     scanrunner by Madhav"""

TOP_LEVEL_HELP = HELP_BANNER + r"""
Automated Nmap and NetExec workflow for authorized assessments.

Usage:
  scanrunner <target> [mode/options]

Start here:
  scanrunner -f targets.txt -sV               Run Nmap with raw arguments
  scanrunner -i 10.10.10.10 --template quick  Run an Nmap template
  scanrunner -f targets.txt -nxc smb           Run NetExec SMB mode
  scanrunner -f targets.txt --split 3          Split a target file

Review results (no scanning):
  scanrunner --status [DIR]                    Summarise an output folder
  scanrunner --diff OLD_DIR NEW_DIR            Compare open ports between two runs

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
    if ACTIVE_STORE is not None:
        outcomes = {"completed.txt": "COMPLETE", "skipped.txt": "Skipped",
                    "not-pingip.txt": "Unreachable or no discovery response", "failed.txt": "FAILED"}
        outcome = outcomes.get(os.path.basename(filename))
        if outcome:
            with ACTIVE_STORE.connect() as database:
                database.execute("UPDATE run_targets SET outcome=? WHERE run_id=? AND requested=?",
                                 (outcome, ACTIVE_STORE.run_id, data))


class _FileLock:
    """OS-owned locks release on process exit and never steal active writers."""
    def __init__(self, path, timeout=30):
        self.path = path + '.lock'
        self.timeout = timeout
        self.file = None

    def __enter__(self):
        self.file = open(self.path, 'a+b')
        self.file.seek(0)
        if not self.file.read(1):
            self.file.write(b'0')
            self.file.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self.file.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self.file.close()
                    raise TimeoutError('Another writer still owns the output lock')
                time.sleep(0.05)

    def __exit__(self, *exc_info):
        self.file.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        self.file.close()


LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Audit logs that record a target's outcome, in tie-break priority order: if
# two outcomes share a timestamp (second resolution), the earlier one here wins.
OUTCOME_LOGS = (
    ("completed", "completed.txt"),
    ("skipped", "skipped.txt"),
    ("no_ping", "not-pingip.txt"),
    ("failed", "failed.txt"),
)


def run_start_time():
    """Timestamp to pass as `since` for outcomes logged from now on."""
    return datetime.now().replace(microsecond=0)


def read_log_entries(path):
    """Return (timestamp, target) pairs from an audit-log file, in file order.

    Lines whose timestamp can't be parsed get datetime.min, so they still
    count for "ever logged" but never for "logged during this run".
    """
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) < 2 or not parts[-1].strip():
                continue
            try:
                stamp = datetime.strptime(parts[0].strip(), LOG_TIME_FORMAT)
            except ValueError:
                stamp = datetime.min
            entries.append((stamp, parts[-1].strip()))
    return entries


def read_logged_ips(path, since=None):
    """Return the set of unique targets recorded in an audit-log file.

    With `since`, only entries logged at or after that time count.
    """
    return {target for stamp, target in read_log_entries(path)
            if since is None or stamp >= since}


def latest_outcomes(output_dir, since=None, log_paths=None):
    """Return {target: outcome} using each target's most recent outcome.

    A target that failed last week and completed today is "completed", not
    both. `log_paths` optionally overrides the {outcome: path} mapping.
    """
    paths = log_paths or {name: os.path.join(output_dir, filename)
                          for name, filename in OUTCOME_LOGS}
    priority = {name: rank for rank, (name, _) in enumerate(OUTCOME_LOGS)}
    best = {}
    for name, path in paths.items():
        for stamp, target in read_log_entries(path):
            if since is not None and stamp < since:
                continue
            key = (stamp, -priority[name])
            if target not in best or key > best[target][0]:
                best[target] = (key, name)
    return {target: name for target, (_, name) in best.items()}

def count_unique_ips(path):
    return len(read_logged_ips(path))

def sanitize_filename(ip):
    value = str(ip)
    if "\\" in value or value in {".", ".."} or any(character in value for character in "\x00\r\n"):
        raise ValueError("Unsafe artifact target name")
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", value.replace(":", "_").replace("/", "_"))
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if len(cleaned) > 180 or cleaned.split(".")[0].upper() in reserved:
        cleaned = cleaned[:120] + "_" + hashlib.sha256(value.encode()).hexdigest()[:16]
    return cleaned


def csv_safe(value):
    text = redact_output_text(str(value if value is not None else ""))
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def redact_output_text(text):
    text = re.sub(r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;)]+)",
                  r"\1\2[REDACTED]", text)
    if ACTIVE_CONFIG.get("tool") == "nxc":
        options = ACTIVE_CONFIG.get("options", [])
        for index, option in enumerate(options):
            name, equal, value = option.partition("=")
            if name in {"-p", "--password", "-H", "--hash", "--aesKey", "--key"}:
                if not equal:
                    value = options[index + 1] if index + 1 < len(options) else ""
                if value:
                    text = text.replace(value, "[REDACTED]")
    return text


@contextmanager
def atomic_text(path, newline=None):
    temporary = path + "." + uuid.uuid4().hex + ".tmp"
    try:
        with open(temporary, "x", encoding="utf-8", newline=newline) as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

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
    sensitive_options = {"-u", "--username", "-p", "--password", "-H", "--hash", "--aesKey", "--key"}
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
        return None
    try:
        with open(path, encoding="utf-8-sig") as file:
            return [cleaned for line in file if (cleaned := strip_inline_comment(line))]
    except OSError as error:
        print(c(C.RED + C.BOLD, f"  [!] Cannot read scope file: {error}"))
        sys.exit(1)

def _scope_networks(scope):
    """Return the IP/CIDR entries of a scope list as ip_network objects."""
    networks = []
    for item in scope:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            interval = parse_last_octet_range(item)
            if interval:
                networks.extend(ipaddress.summarize_address_range(*interval))
    return networks


def _address_in_scope(address, networks):
    return any(address.version == network.version and address in network
               for network in networks)


def parse_last_octet_range(target):
    """Return (first, last) addresses for an Nmap range like 10.0.0.5-20, else None."""
    match = re.fullmatch(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})", target)
    if not match:
        return None
    prefix, start, end = match.group(1), int(match.group(2)), int(match.group(3))
    if start > end:
        return None
    try:
        return ipaddress.ip_address(f"{prefix}{start}"), ipaddress.ip_address(f"{prefix}{end}")
    except ValueError:
        return None


def target_in_scope(target, scope, resolver=None):
    """Return whether a target is inside the authorized scope.

    IPs and CIDRs are checked against the scope's IP/CIDR entries. A last-octet
    range (10.0.0.5-20) must lie entirely inside scope. A hostname is in scope
    when it is listed by name, or when it resolves to an in-scope address;
    an unresolvable hostname is refused. Anything else is refused.
    """
    if scope is None:
        scope = [target]
    if not scope:
        return False
    networks = _scope_networks(scope)
    try:
        network = ipaddress.ip_network(target, strict=False)
        return any(network.version == item.version and network.subnet_of(item)
                   for item in networks)
    except ValueError:
        pass

    octet_range = parse_last_octet_range(target)
    if octet_range:
        first, last = octet_range
        return all(_address_in_scope(ipaddress.ip_address(value), networks)
                   for value in range(int(first), int(last) + 1))

    if not re.fullmatch(r"[A-Za-z0-9._-]+", target):
        return False
    named = target.lower().rstrip(".") in {item.lower().rstrip(".") for item in scope}
    resolved, _ = (resolver or resolve_scope_addresses)(target, timeout=5)
    addresses = resolved if isinstance(resolved, list) else [resolved]
    try:
        parsed = [ipaddress.ip_address(value) for value in addresses]
        return bool(parsed) and all(named or _address_in_scope(value, networks) for value in parsed)
    except ValueError:
        return False


def resolve_scope_addresses(target, timeout=5):
    """Resolve every A/AAAA answer with a bounded wait and no fallback hostname."""
    result = []
    def lookup():
        try:
            result.extend(dict.fromkeys(str(ipaddress.ip_address(info[4][0]))
                          for info in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)))
        except (OSError, ValueError):
            pass
    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return [], "DNS lookup timed out"
    return result, "Resolved all addresses" if result else "DNS lookup failed"


class ScopeGuard:
    """Validate requested scope and pin DNS answers for each scanner invocation."""
    def __init__(self, targets, scope, exclusions=(), resolver=None):
        self.scope = list(targets) if scope is None else list(scope)
        self.exclusions = list(exclusions)
        self.resolver = resolver or resolve_scope_addresses
        self.answers = {}
        for entry in self.scope + self.exclusions:
            if not self._valid_entry(entry):
                raise ValueError(f"Invalid scope entry: {entry}")
        if not self.scope:
            raise ValueError("Authorized scope is empty")
        for target in targets:
            self.destinations(target)

    @staticmethod
    def _valid_entry(value):
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return bool(parse_last_octet_range(value) or
                        re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?", value))

    def _resolve(self, hostname):
        values, message = self.resolver(hostname, timeout=5)
        if not values or not isinstance(values, list):
            raise ValueError(f"Cannot validate DNS for {hostname}: {message}")
        return sorted({str(ipaddress.ip_address(value)) for value in values})

    def destinations(self, target):
        if not self._valid_entry(target):
            raise ValueError(f"Invalid scan target: {target}")
        networks = _scope_networks(self.scope)
        named = target.lower().rstrip(".") in {item.lower().rstrip(".") for item in self.scope}
        try:
            requested = [ipaddress.ip_network(target, strict=False)]
            destinations = [target]
        except ValueError:
            interval = parse_last_octet_range(target)
            if interval:
                requested = [ipaddress.ip_network(str(ipaddress.ip_address(value)))
                             for value in range(int(interval[0]), int(interval[1]) + 1)]
                destinations = [target]
            else:
                destinations = self._resolve(target)
                if target in self.answers and destinations != self.answers[target]:
                    raise ValueError(f"DNS answers changed for {target}; authorize a new run")
                requested = [ipaddress.ip_network(value) for value in destinations]
                if named:
                    networks = networks + requested
        if not all(any(net.version == allowed.version and net.subnet_of(allowed)
                       for allowed in networks) for net in requested):
            raise ValueError(f"Target outside authorized scope: {target}")
        denied = _scope_networks(self.exclusions)
        for exclusion in self.exclusions:
            if exclusion.lower().rstrip(".") == target.lower().rstrip("."):
                raise ValueError(f"Excluded target: {target}")
            try:
                ipaddress.ip_network(exclusion, strict=False)
            except ValueError:
                denied.extend(ipaddress.ip_network(value) for value in self._resolve(exclusion))
        if any(net.version == excluded.version and net.overlaps(excluded)
               for net in requested for excluded in denied):
            raise ValueError(f"Target overlaps exclusions: {target}")
        if not parse_last_octet_range(target) and not _is_ip_literal(target) and "/" not in target:
            self.answers[target] = destinations
        return destinations


ACTIVE_SCOPE = None
ACTIVE_STORE = None
ACTIVE_CONFIG = {}
CANCEL_EVENT = threading.Event()


def request_cancel(signum, frame):
    CANCEL_EVENT.set()
    raise KeyboardInterrupt


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def secure_storage_directory(path):
    if os.path.islink(path):
        raise ValueError("Private storage directory cannot be a symbolic link")
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
        return
    import ctypes
    from ctypes import wintypes
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    security.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    # Owner, SYSTEM and administrators. Child evidence inherits this protected DACL.
    sddl = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise OSError("Cannot construct private evidence permissions")
    try:
        if not security.SetFileSecurityW(path, 0x80000004, descriptor):
            raise OSError("Cannot apply private evidence permissions")
    finally:
        kernel.LocalFree(descriptor)


class CapacityBusy(RuntimeError):
    pass


class RunStore:
    """Transactional job ownership and immutable run evidence, schema version 1."""
    def __init__(self, directory, config=None):
        self.directory = os.path.abspath(directory)
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        self.storage_directory = os.path.join(self.directory, ".scanrunner")
        secure_storage_directory(self.storage_directory)
        self.database = os.path.join(self.storage_directory, "scanrunner.sqlite3")
        self.run_id = uuid.uuid4().hex
        self.config = config or {}
        with self.connect() as database:
            if database.execute("PRAGMA user_version").fetchone()[0] > 1:
                raise ValueError("Run database schema is newer than this ScanRunner version")
            database.executescript("""
                CREATE TABLE IF NOT EXISTS engagements (
                    id TEXT PRIMARY KEY, scope TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, engagement TEXT NOT NULL, config TEXT NOT NULL,
                    started TEXT NOT NULL, ended TEXT, outcome TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS run_targets (
                    run_id TEXT NOT NULL, requested TEXT NOT NULL, resolved TEXT NOT NULL,
                    outcome TEXT NOT NULL, PRIMARY KEY(run_id, requested));
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, target TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, started TEXT NOT NULL, ended TEXT,
                    outcome TEXT NOT NULL, exit_code INTEGER, parser_ok INTEGER NOT NULL DEFAULT 0,
                    directory TEXT NOT NULL, manifest TEXT);
                CREATE INDEX IF NOT EXISTS jobs_target ON jobs(target, fingerprint, started);
                CREATE TABLE IF NOT EXISTS claims (
                    target TEXT NOT NULL, fingerprint TEXT NOT NULL, job_id TEXT NOT NULL,
                    expires REAL NOT NULL, PRIMARY KEY(target, fingerprint));
                CREATE TABLE IF NOT EXISTS job_events (
                    job_id TEXT NOT NULL, at_utc TEXT NOT NULL, previous TEXT, outcome TEXT NOT NULL);
                PRAGMA user_version=1;
            """)
            if "subnets" not in {row["name"] for row in database.execute("PRAGMA table_info(jobs)")}:
                database.execute("ALTER TABLE jobs ADD COLUMN subnets TEXT NOT NULL DEFAULT '[]'")
            engagement = str(self.config.get("engagement", "default"))
            database.execute("INSERT OR IGNORE INTO engagements VALUES (?, ?)",
                             (engagement, json.dumps(self.config.get("scope", []))))
            safe_config = self.public_config()
            database.execute("INSERT INTO runs VALUES (?, ?, ?, ?, NULL, 'Running')",
                             (self.run_id, engagement, json.dumps(safe_config), utc_now()))
            for target in self.config.get("targets", []):
                database.execute("INSERT INTO run_targets VALUES (?, ?, ?, 'Queued')",
                                 (self.run_id, target, json.dumps(self.config.get("dns_answers", {}).get(target, [target]))))
        if os.name != "nt":
            os.chmod(self.database, 0o600)

    @contextmanager
    def connect(self):
        database = sqlite3.connect(self.database, timeout=30)
        try:
            database.execute("PRAGMA busy_timeout=30000")
            database.execute("PRAGMA journal_mode=WAL")
            database.row_factory = sqlite3.Row
            with database:
                yield database
        finally:
            database.close()

    def public_config(self):
        config = dict(self.config)
        config["options"] = redact_command(["nxc", *config.get("options", [])])[1:] if config.get("tool") == "nxc" else config.get("options", [])
        return config

    def fingerprint(self, target, use_pn=False):
        config = {**self.config, "target": target.lower(), "use_pn": use_pn}
        return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def claim(self, target, use_pn=False):
        fingerprint = self.fingerprint(target, use_pn)
        job_id = uuid.uuid4().hex
        directory = os.path.join(self.storage_directory, "runs", self.run_id, job_id)
        now = time.time()
        subnets = set()
        subjects = self.config.get("scope", []) if self.config.get("tool") == "nxc" else [target]
        for subject in subjects:
            resolved = self.config.get("dns_answers", {}).get(subject, [subject])
            for address in resolved:
                for network in _scope_networks([address]):
                    prefix = 24 if network.version == 4 else 64
                    if network.prefixlen < prefix and 2 ** (prefix - network.prefixlen) > 4096:
                        raise ValueError("Target spans more than 4096 concurrency subnets; split the engagement")
                    groups = network.subnets(new_prefix=prefix) if network.prefixlen < prefix else [network.supernet(new_prefix=prefix)]
                    subnets.update(str(group) for group in groups)
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            expired = database.execute("SELECT job_id FROM claims WHERE expires < ?", (now,)).fetchall()
            for row in expired:
                database.execute("UPDATE jobs SET outcome='Interrupted', ended=? WHERE id=? AND outcome='Running'",
                                 (utc_now(), row["job_id"]))
                database.execute("INSERT INTO job_events VALUES (?, ?, 'Running', 'Interrupted')", (row["job_id"], utc_now()))
            database.execute("DELETE FROM claims WHERE expires < ?", (now,))
            if database.execute("SELECT 1 FROM claims WHERE target=?", (target,)).fetchone():
                return None
            active = database.execute("SELECT jobs.subnets, runs.config FROM jobs JOIN runs ON jobs.run_id=runs.id WHERE jobs.outcome='Running'").fetchall()
            policies = [json.loads(row["config"]) for row in active]
            global_ceiling = min([self.config.get("global_workers", 4)] + [policy.get("global_workers", 4) for policy in policies])
            subnet_ceiling = min([self.config.get("subnet_workers", 2)] + [policy.get("subnet_workers", 2) for policy in policies])
            if any(policy.get("scan_rate", 100) != self.config.get("scan_rate", 100) for policy in policies):
                raise CapacityBusy("Another scan-rate policy is currently active")
            if len(active) >= global_ceiling:
                raise CapacityBusy("Global scanner concurrency ceiling reached")
            if any(sum(subnet in json.loads(row["subnets"]) for row in active) >= subnet_ceiling
                   for subnet in subnets):
                raise CapacityBusy("Per-subnet scanner concurrency ceiling reached")
            try:
                database.execute("INSERT INTO claims VALUES (?, ?, ?, ?)",
                                 (target, fingerprint, job_id, now + self.config.get("timeout", 600) + 60))
            except sqlite3.IntegrityError:
                return None
            database.execute("INSERT INTO jobs (id,run_id,target,fingerprint,started,outcome,directory) VALUES (?,?,?,?,?,'Running',?)",
                             (job_id, self.run_id, target, fingerprint, utc_now(), directory))
            database.execute("UPDATE jobs SET subnets=? WHERE id=?", (json.dumps(sorted(subnets)), job_id))
            database.execute("INSERT INTO job_events VALUES (?, ?, NULL, 'Running')", (job_id, utc_now()))
        os.makedirs(directory, mode=0o700, exist_ok=False)
        return {"id": job_id, "directory": directory, "target": target, "fingerprint": fingerprint}

    def wait_claim(self, target, use_pn=False):
        deadline = time.monotonic() + self.config.get("timeout", 600)
        while not CANCEL_EVENT.is_set():
            try:
                return self.claim(target, use_pn)
            except CapacityBusy:
                if time.monotonic() > deadline:
                    raise ValueError("Concurrency capacity wait timed out")
                time.sleep(0.05)
        return None

    def finish_job(self, job, outcome, exit_code, parser_ok, command):
        artifacts = []
        for name in sorted(os.listdir(job["directory"])):
            path = os.path.join(job["directory"], name)
            if os.path.isfile(path):
                artifacts.append({"name": name, "sha256": file_sha256(path), "size": os.path.getsize(path)})
        safe_argv = redact_command(command) if self.config.get("tool") == "nxc" else command
        manifest = {"run_id": self.run_id, "job_id": job["id"], "target": job["target"],
                    "fingerprint": job["fingerprint"], "ended_utc": utc_now(), "argv": safe_argv,
                    "tool_version": self.config.get("tool_version", "Not determined"),
                    "outcome": outcome, "exit_code": exit_code, "parser_ok": parser_ok,
                    "artifacts": artifacts, "config": self.public_config()}
        with self.connect() as database:
            manifest["started_utc"] = database.execute("SELECT started FROM jobs WHERE id=?", (job["id"],)).fetchone()[0]
        with open(os.path.join(job["directory"], "manifest.json"), "x", encoding="utf-8") as file:
            json.dump(manifest, file, indent=2)
        with self.connect() as database:
            database.execute("UPDATE jobs SET ended=?, outcome=?, exit_code=?, parser_ok=?, manifest=? WHERE id=? AND outcome='Running'",
                             (utc_now(), outcome, exit_code, int(parser_ok), json.dumps(manifest), job["id"]))
            database.execute("DELETE FROM claims WHERE job_id=?", (job["id"],))
            database.execute("INSERT INTO job_events VALUES (?, ?, 'Running', ?)", (job["id"], utc_now(), outcome))

    def verify_job(self, row):
        try:
            expected_root = Path(self.directory).resolve() / ".scanrunner" / "runs"
            if not Path(row["directory"]).resolve().is_relative_to(expected_root):
                return False
            manifest = json.loads(row["manifest"])
            manifest_path = os.path.join(row["directory"], "manifest.json")
            with open(manifest_path, encoding="utf-8") as file:
                if json.load(file) != manifest:
                    return False
            for artifact in manifest["artifacts"]:
                path = os.path.abspath(os.path.join(row["directory"], artifact["name"]))
                if os.path.dirname(path) != os.path.abspath(row["directory"]):
                    return False
                if os.path.getsize(path) != artifact["size"] or file_sha256(path) != artifact["sha256"]:
                    return False
            return True
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def completed(self, target, use_pn=False):
        with self.connect() as database:
            row = database.execute("SELECT * FROM jobs WHERE target=? AND fingerprint=? ORDER BY started DESC LIMIT 1",
                                   (target, self.fingerprint(target, use_pn))).fetchone()
        if row and row["outcome"] == "COMPLETE" and row["parser_ok"]:
            if self.verify_job(row):
                return True
            print(f"Evidence verification failed for {target}; rescan required", file=sys.stderr)
        return False

    def end(self, outcome):
        with self.connect() as database:
            database.execute("UPDATE runs SET ended=?, outcome=? WHERE id=?", (utc_now(), outcome, self.run_id))


def stop_process(process):
    if process.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=3)


POSIX_SUPERVISOR = r'''
import os, signal, subprocess, sys, time
parent = int(sys.argv[1])
def stop_group(signum=None, frame=None):
    os.killpg(os.getpgrp(), signal.SIGKILL)
signal.signal(signal.SIGTERM, stop_group)
if os.getppid() != parent:
    stop_group()
child = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL)
while child.poll() is None:
    if os.getppid() != parent:
        stop_group()
    time.sleep(0.05)
sys.exit(child.returncode if child.returncode >= 0 else 128 - child.returncode)
'''


class WindowsProcessJob:
    """Kill scanner descendants when their owning capture operation ends."""
    def __init__(self, process):
        self.handle = None
        if os.name != "nt":
            return
        import ctypes
        from ctypes import wintypes
        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
                        ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", IoCounters), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateJobObjectW(None, None)
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not handle or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            if handle:
                kernel.CloseHandle(handle)
            stop_process(process)
            raise OSError("Cannot create scanner process containment")
        if not kernel.AssignProcessToJobObject(handle, wintypes.HANDLE(int(process._handle))):
            failure = ctypes.get_last_error()
            kernel.CloseHandle(handle)
            stop_process(process)
            raise OSError(f"Cannot contain scanner child processes (Windows error {failure})")
        self.handle = handle
        self.kernel = kernel
        native = ctypes.WinDLL("ntdll")
        native.NtResumeProcess.argtypes = [wintypes.HANDLE]
        native.NtResumeProcess.restype = ctypes.c_long
        if native.NtResumeProcess(wintypes.HANDLE(int(process._handle))) != 0:
            self.close()
            raise OSError("Cannot resume contained scanner process")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def capture_process(command, directory, timeout=600, live=False):
    """Preserve exact stdout/stderr and bound execution, including cancellation."""
    execution = [sys.executable, "-c", POSIX_SUPERVISOR, str(os.getpid()), *command] if os.name == "posix" else command
    process = subprocess.Popen(execution, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=os.name == "posix",
                               creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | 0x4) if os.name == "nt" else 0)
    tree = WindowsProcessJob(process)
    lines = queue.Queue(maxsize=128)
    capture_errors = []
    stop_keys = threading.Event()
    key_state = []
    def watch_keys():
        if not live or not RAW_MODE_SUPPORTED or not sys.stdin.isatty():
            return
        try:
            tty.setraw(sys.stdin.fileno())
            while not stop_keys.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    key = sys.stdin.read(1)
                    if key in {"\x03", "\x18"}:
                        key_state.append("Interrupted" if key == "\x03" else "SKIPPED")
                        break
                    if key == " ":
                        print(f"\r\nScanner PID {process.pid}, running {time.monotonic() - started:.1f}s\r\n")
        finally:
            restore_terminal()
    def copy_stream(stream, name):
        try:
            with open(os.path.join(directory, name), "xb") as file:
                while True:
                    block = stream.read1(4096)
                    if not block:
                        break
                    file.write(block)
                    file.flush()
                    if live:
                        try:
                            lines.put_nowait(block.decode("utf-8", errors="replace"))
                        except queue.Full:
                            pass  # Raw bytes remain complete in the artifact.
        except OSError as error:
            capture_errors.append(str(error))
        finally:
            stream.close()
    readers = [threading.Thread(target=copy_stream, args=(process.stdout, "stdout.bin")),
               threading.Thread(target=copy_stream, args=(process.stderr, "stderr.bin"))]
    for reader in readers:
        reader.start()
    started = time.monotonic()
    watcher = threading.Thread(target=watch_keys, daemon=True)
    watcher.start()
    state = "Exited"
    try:
        while process.poll() is None:
            if CANCEL_EVENT.is_set():
                state = "Interrupted"
                stop_process(process)
                break
            if key_state:
                state = key_state[0]
                stop_process(process)
                break
            if time.monotonic() - started > timeout:
                state = "TIMEOUT"
                stop_process(process)
                break
            try:
                print(lines.get(timeout=0.05), end="")
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        state = "Interrupted"
        stop_process(process)
    finally:
        tree.close()
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        stop_keys.set()
        watcher.join(timeout=1)
        restore_terminal()
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            stop_process(process)
            state = "Interrupted"
        while not lines.empty():
            print(lines.get_nowait(), end="")
    if capture_errors:
        state = "CAPTURE_FAILED"
    return process.returncode, state


def validate_nmap_evidence(report, target, returncode):
    if returncode != 0:
        return "FAILED", False
    if not os.path.exists(report) or os.path.getsize(report) == 0:
        return "EMPTY", False
    status = get_file_status(report)
    if status not in {"COMPLETE", "DOWN"}:
        return status, False
    try:
        root = read_nmap_xml(_xml_report_path(report))
        if root.find("runstats/finished") is None or root.find("runstats/hosts") is None:
            return "INCOMPLETE", False
        if root.find("runstats/finished").get("exit") != "success":
            return "INCOMPLETE", False
        if int(root.find("runstats/hosts").get("total", "0")) == 0:
            return "UNRESOLVED", False
        if any(host.get("timedout") == "true" for host in root.findall("host")):
            return "TIMEOUT", False
        up_count = int(root.find("runstats/hosts").get("up", "0"))
        observed_up = sum(host.find("status") is not None and host.find("status").get("state") == "up"
                          for host in root.findall("host"))
        if (status == "COMPLETE" and (up_count < 1 or up_count != observed_up)) or (status == "DOWN" and up_count != 0):
            return "INCONCLUSIVE", False
        if ACTIVE_SCOPE is not None:
            destinations = ACTIVE_SCOPE.destinations(target)
            for host in root.findall("host"):
                addresses = [a.get("addr", "") for a in host.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}]
                if not addresses or not all(target_in_scope(address, destinations) for address in addresses):
                    return "INCONCLUSIVE", False
        _hosts_from_xml(_xml_report_path(report))
        return status, True
    except (OSError, ValueError, ET.ParseError):
        return "INCOMPLETE", False


def publish_report_cache(job, report):
    """Keep legacy report paths as replaceable views, retaining pre-migration bytes."""
    for suffix in (".txt", ".xml", ".error.log"):
        destination = os.path.splitext(report)[0] + suffix
        if os.path.isfile(destination):
            snapshot = os.path.join(job["directory"], "legacy-before" + suffix)
            shutil.copyfile(destination, snapshot)
        source = os.path.join(job["directory"], "nmap" + suffix)
        temporary = destination + "." + uuid.uuid4().hex + ".tmp"
        if os.path.exists(source):
            shutil.copyfile(source, temporary)
        else:
            with open(temporary, "xb"):
                pass
        os.replace(temporary, destination)


def execute_nmap(target, report, options, use_pn=False, live=False):
    store = ACTIVE_STORE or RunStore(os.path.dirname(os.path.abspath(report)), {"tool": "nmap", "options": options})
    job = store.wait_claim(target, use_pn)
    if job is None:
        return "CLAIMED", "Target already owned by another worker"
    output = os.path.join(job["directory"], "nmap.txt")
    command = []
    code = None
    status, parsed, detail = "Interrupted", False, ""
    try:
        command = _build_nmap_command(target, output, options, use_pn)
        code, process_state = capture_process(command, job["directory"], store.config.get("timeout", 600), live)
        status, parsed = validate_nmap_evidence(output, target, code)
        if process_state != "Exited":
            status, parsed = process_state, False
        captured = ""
        for name in ("stdout.bin", "stderr.bin"):
            with open(os.path.join(job["directory"], name), "rb") as file:
                captured += file.read().decode("utf-8", errors="replace")
        fatal = nmap_fatal_reason(captured.splitlines())
        if fatal:
            status, parsed, detail = "FATAL", False, fatal
        publish_report_cache(job, report)
        if status not in {"COMPLETE", "DOWN"}:
            error_path = os.path.splitext(report)[0] + ".error.log"
            with open(error_path, "w", encoding="utf-8") as file:
                file.write(captured)
            detail = detail or f"{status}; raw evidence: {job['directory']}"
    except (OSError, ValueError) as error:
        status, parsed, detail = "FAILED", False, str(error)
    finally:
        store.finish_job(job, status, code, parsed, command)
    return status, detail


def validate_scan_options(options, nxc=False, allow_intrusive=False):
    """Reject extra targets, unreviewed scripts, and scope-extending options."""
    if nxc:
        value_options = {"-u", "--username", "-p", "--password", "-H", "--hash", "--port", "--timeout", "-t"}
        flags = {"--local-auth", "--continue-on-success", "--no-progress"}
    else:
        value_options = {"-p", "--top-ports", "--host-timeout", "--max-retries", "--max-rate",
                         "--min-rate", "--scan-delay", "--max-scan-delay", "--initial-rtt-timeout",
                         "--min-rtt-timeout", "--max-rtt-timeout", "--max-parallelism", "--min-parallelism",
                         "--max-hostgroup", "--min-hostgroup", "--stats-every", "--version-intensity"}
        flags = {"-6", "-Pn", "-n", "-sV", "-sS", "-sT", "-sU", "-sn", "-sL", "-O", "-r", "-F",
                 "--open", "--reason", "--version-light", "--version-all", "--osscan-limit",
                 "--osscan-guess", "--disable-arp-ping", "--send-ip", "--send-eth", "--unprivileged",
                 "--privileged", "--defeat-rst-ratelimit", "--defeat-icmp-ratelimit"}
    approved_scripts = {"ssl-enum-ciphers", "smb-os-discovery",
                        "smb-protocols", "smb-security-mode", "rdp-enum-encryption", "rdp-ntlm-info"}
    index = 0
    while index < len(options):
        token = options[index]
        option, equal, value = token.partition("=")
        if option == "--script" and not nxc:
            if not equal:
                index += 1
                value = options[index] if index < len(options) else ""
            if not value or not set(value.split(",")) <= approved_scripts:
                raise ValueError("NSE selection contains an unreviewed or scope-extending script")
        elif option in value_options:
            if not equal:
                index += 1
                value = options[index] if index < len(options) else ""
            if not value or value.startswith("-"):
                raise ValueError(f"Missing or invalid value for {option}")
            if nxc and option in {"-u", "--username", "-p", "--password", "-H", "--hash"} and not allow_intrusive:
                raise ValueError("Credential operations require --allow-intrusive and --authorization-note")
        elif token in flags or (not nxc and re.fullmatch(r"-(?:v+|d+|T[0-5]|p[0-9,U:T,-]+)", token)):
            pass
        else:
            raise ValueError(f"Unreviewed scanner argument or extra target: {token}")
        index += 1


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
Default table columns: IP, HOSTNAME, OS. Add --nxc-query to add fields —
SMBv1 enabled, signing disabled, RDP without NLA, and successful null auth
are highlighted in red as findings; their safe counterparts in green.
Focused table fields: os, hostname, smbv1, smb-signing, null-auth, rdp-nla, all.

CIDR targets are listed per responding host. Hostname targets are matched to
their resolved IP, so each host appears once.

NetExec module options: `-o KEY=VALUE ...` is passed to NetExec (any -o value
containing "=" is a module option). Plain `-o DIR` is still scanrunner's
output folder.
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

Flags that overlap with scanrunner's own:
  -iL FILE                Accepted; treated as -f FILE
  -oN/-oX/-oG/-oA/-oS     Refused — scanrunner writes per-target .txt and .xml
                          reports itself; choose the folder with -o DIR
  -iR N                   Refused — random targets can't be scope-checked or tracked
  -f                      Always scanrunner's target file, never Nmap fragmentation

Pre-flight and failure handling:
  Scan types that need root (-sS, -sU, -O, ...) print a warning when not run as
  root. If Nmap stops with a fatal error (QUITTING!), for example a bad option or
  missing privileges, the run stops immediately instead of failing every host
  the same way. The remaining targets are reported as unaccounted.
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
  --tabs N               Split targets across N terminal tabs right away, no
                          prompt, even below the 20-target auto-prompt threshold
  --no-auto-tabs         Never offer to split into tabs; always scan one host
                          at a time in this window
  --retries N            Retry failed scans N times
  --scope-file FILE      Refuse targets outside the authorized scope

Every run ends by reconciling the full target list against completed.txt,
skipped.txt, not-pingip.txt, and failed.txt. Only outcomes recorded during the
current run count, and each target is counted once, by its latest outcome.
Any target with no outcome recorded this run (e.g. an interrupted run) is
printed as a warning and saved to unaccounted.txt in the output directory —
check for this before reporting results as final.

Hosts Nmap reports as down ("0 hosts up") are logged in not-pingip.txt and are
not treated as completed, so --resume tries them again.

Inventory files (open-ports-inventory.csv/.json, open-ports-report.html) are
built from each target's Nmap XML, one row per discovered host and open port,
so CIDR targets are broken down by host. Columns: target, host, hostname,
owner, environment, port_service, version.

Reviewing results without scanning:
  scanrunner --status [DIR]           Outcome counts, incomplete reports, tab
                                      progress, and top open services (default DIR: results)
  scanrunner --diff OLD_DIR NEW_DIR   Ports opened/closed per host between two
                                      runs; also saved as NEW_DIR/scan-diff.json
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
    "tabs": "--tabs N\nSplit targets across N terminal tabs immediately — skips the interactive prompt and works even below the 20-target auto-prompt threshold (e.g. a 5-target file). Mutually exclusive with --parallel and --no-auto-tabs.\nExample: scanrunner -f targets.txt --tabs 3 -sV",
    "no-auto-tabs": "--no-auto-tabs\nNever offer to split into terminal tabs, no matter how large the target list — always scan one host at a time in this window.\nExample: scanrunner -f targets.txt --no-auto-tabs -sV",
    "metadata-csv": "--metadata-csv FILE\nAdd owner/environment data to the CSV/JSON inventory; FILE needs a target column.\nExample: scanrunner -f targets.txt --metadata-csv assets.csv -sV",
    "html-report": "--html-report\nCreate open-ports-report.html (per-host table plus a by-service summary) in the output directory.\nExample: scanrunner -f targets.txt --html-report -sV",
    "status": "--status [DIR]\nSummarise an output folder without scanning: latest outcome per target, incomplete reports, tab progress, unaccounted targets, and top open services. Default DIR: results.\nExample: scanrunner --status client-assessment",
    "diff": "--diff OLD_DIR NEW_DIR\nCompare open ports per host between two output folders (e.g. an initial test and a retest). Prints opened/closed ports and new/missing hosts, and saves NEW_DIR/scan-diff.json.\nExample: scanrunner --diff results-june results-retest",
}

OPTION_ALIASES = {
    "-f": "file", "--file": "file", "file": "file", "-i": "ip", "--ip": "ip", "ip": "ip",
    "-o": "output", "--output": "output", "output": "output", "--exclude": "exclude", "exclude": "exclude",
    "--exclude-file": "exclude-file", "exclude-file": "exclude-file", "--nxc-query": "nxc-query", "nxc-query": "nxc-query",
    "--yes": "yes", "yes": "yes", "--resume": "resume", "resume": "resume", "--skip-ping": "skip-ping", "skip-ping": "skip-ping",
    "-ok": "skip-no-ping", "--skip-no-ping": "skip-no-ping", "skip-no-ping": "skip-no-ping",
    "--no-color": "no-color", "no-color": "no-color", "--scope-file": "scope-file", "scope-file": "scope-file",
    "--retries": "retries", "retries": "retries", "--parallel": "parallel", "parallel": "parallel",
    "--tabs": "tabs", "tabs": "tabs", "--no-auto-tabs": "no-auto-tabs", "no-auto-tabs": "no-auto-tabs",
    "--metadata-csv": "metadata-csv", "metadata-csv": "metadata-csv", "--html-report": "html-report", "html-report": "html-report",
    "--status": "status", "status": "status", "--diff": "diff", "diff": "diff",
}

for _name, _description in {
    "dry-run": "Preview argv, impact, privileges and output destinations without DNS or process execution.",
    "json": "Print JSON with --dry-run or a durable-history review command.",
    "engagement": "Set the engagement identifier stored with runs and scope snapshots.",
    "process-timeout": "Bound each scanner process in seconds (default 600). Partial evidence is retained.",
    "global-concurrency": "Set the shared output-directory scanner concurrency ceiling (default 4).",
    "subnet-concurrency": "Set the scanner concurrency ceiling per IPv4 /24 or IPv6 /64 (default 2).",
    "scan-rate": "Set the aggregate Nmap packet-rate ceiling divided across global workers (default 100 PPS).",
    "allow-intrusive": "Opt in to credential operations with --authorization-note.",
    "authorization-note": "Record the explicit authorization reference for credential operations.",
    "history": "Review durable run and job metadata with --history [DIR] [--json].",
    "verify-evidence": "Verify raw artifact hashes with --verify-evidence [DIR] [--json]. Returns failure for missing, corrupt or unfinished evidence.",
}.items():
    OPTION_HELP[_name] = "--" + _name + "\n" + _description
    OPTION_ALIASES["--" + _name] = _name
    OPTION_ALIASES[_name] = _name


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
        "--scope-file", "--retries", "--parallel", "--tabs", "--no-auto-tabs", "-o", "--output",
        "--metadata-csv", "--html-report", "--list-templates", "--help-all",
        "--nmap", "--reports", "--nxc-native-help", "--completion",
        "--status", "--diff",
    ]
    options.extend("--" + name for name in OPTION_HELP if "--" + name not in options)
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
        -o|--output|--status|--diff) COMPREPLY=( $(compgen -d -- "$cur") ); return ;;
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
    '--status[summarise an output folder]:directory:_directories' \\
    '--diff[compare two output folders]:old directory:_directories' \\
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

# Nmap output flags. scanrunner always writes -oN/-oX itself (one report per
# target), so a user-supplied one would either collide with those or — since
# argparse reads "-oA" as "-o A" — silently change the output folder.
_NMAP_OUTPUT_FLAG = re.compile(r"^-o[NXGASM]")


def preprocess_argv(argv):
    """Resolve flags that Nmap/NetExec and scanrunner both claim.

    Returns (argv_for_argparse, passthrough_tokens, error_message). The
    passthrough tokens are appended to the scanner arguments unchanged.
    """
    nxc_mode = any(token in {"-nxc", "--nxc"} or token.startswith(("-nxc=", "--nxc="))
                   for token in argv)
    result, passthrough = [], []
    index = 0
    while index < len(argv):
        token = argv[index]
        if nxc_mode:
            # NetExec module options: -o KEY=VALUE [KEY=VALUE ...]
            if token == "-o" and index + 1 < len(argv) and "=" in argv[index + 1] \
                    and not argv[index + 1].startswith("-"):
                values = []
                index += 1
                while index < len(argv) and "=" in argv[index] and not argv[index].startswith("-"):
                    values.append(argv[index])
                    index += 1
                passthrough.extend(["-o", *values])
                continue
        else:
            if _NMAP_OUTPUT_FLAG.match(token):
                return argv, [], (
                    f"{token[:3]} is not needed: scanrunner writes a .txt and .xml "
                    "report per target itself. Remove it and use -o DIR to choose "
                    "the output folder.")
            if token == "-iR" or token.startswith("-iR"):
                return argv, [], ("-iR (random targets) is not supported: targets must "
                                  "come from -f/-i so they can be scope-checked and tracked.")
            if token.startswith("-iL") and any(
                    other in {"-f", "--file", "-i", "--ip"}
                    or other.startswith(("--file=", "--ip="))
                    for other in argv):
                # argparse would silently keep only the last -f, dropping a list.
                return argv, [], "-iL and -f/-i both give targets — use only one of them."
            if token == "-iL":
                if index + 1 >= len(argv):
                    return argv, [], "-iL requires a file name"
                result.extend(["-f", argv[index + 1]])
                index += 2
                continue
            if token.startswith("-iL"):
                result.extend(["-f", token[3:]])
                index += 1
                continue
        result.append(token)
        index += 1
    return result, passthrough, None


def parse_args():
    handle_topic_help()
    parser = argparse.ArgumentParser(
        prog="scanrunner",
        add_help=False,
        # Abbreviation matching would turn Nmap's -n into -nxc and similar;
        # every scanrunner option must be typed in full.
        allow_abbrev=False,
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
    workflow_group.add_argument("--dry-run", action="store_true",
                        help="Preview commands and impact without DNS, processes, or output writes")
    workflow_group.add_argument("--json", action="store_true", help="Emit machine-readable dry-run output")
    workflow_group.add_argument("--allow-intrusive", action="store_true",
                        help="Opt in to explicitly authorized credential operations")
    workflow_group.add_argument("--authorization-note", help="Record the authorization for credential operations")
    workflow_group.add_argument("--engagement", default="default", help="Engagement identifier for durable run history")
    workflow_group.add_argument("--process-timeout", type=int, default=600, metavar="SECONDS",
                        help="Overall scanner timeout (1 to 86400 seconds, default 600)")
    workflow_group.add_argument("--global-concurrency", type=int, default=4, metavar="N",
                        help="Shared scanner concurrency ceiling in the output directory (default 4)")
    workflow_group.add_argument("--subnet-concurrency", type=int, default=2, metavar="N",
                        help="Concurrent scans per IPv4 /24 or IPv6 /64 (default 2)")
    workflow_group.add_argument("--scan-rate", type=int, default=100, metavar="PPS",
                        help="Aggregate Nmap packet-rate ceiling divided across global workers (default 100)")
    workflow_group.add_argument("--retries", type=int, default=0, metavar="N",
                        help="Retry failed scans up to N times")
    workflow_group.add_argument("--parallel", type=int, default=1, metavar="N",
                                help="Run up to N non-interactive scans concurrently")
    workflow_group.add_argument("--tabs", type=int, default=None, metavar="N",
                                help="Split targets across N terminal tabs immediately "
                                     "(skips the interactive prompt and the 20-target threshold)")
    workflow_group.add_argument("--no-auto-tabs", action="store_true",
                                help="Never offer to split into terminal tabs; always scan "
                                     "one host at a time in this window")

    report_group = parser.add_argument_group("Output and reporting")
    report_group.add_argument("-o", "--output", metavar="DIR", default=None,
                              help="Output folder (default: results; current dir for -nxc)")
    report_group.add_argument("--metadata-csv", metavar="FILE",
                        help="CSV with target,owner,environment columns")
    report_group.add_argument("--html-report", action="store_true",
                        help="Create an HTML open-port report")


    argv, passthrough, argv_error = preprocess_argv(sys.argv[1:])
    if argv_error:
        parser.error(argv_error)
    args, nmap_extra = parser.parse_known_args(argv)
    nmap_extra.extend(passthrough)
    # Keep the raw token list — do NOT join then re-split.
    # Joining then shlex.split-ing loses spaces inside quoted args
    # e.g. --script-args "user=admin pass=hi" becomes two broken tokens.
    if args.retries < 0 or args.parallel < 1:
        parser.error("--retries must be zero or greater and --parallel must be at least 1")
    if args.retries > 5 or args.parallel > 16 or not 1 <= args.process_timeout <= 86400:
        parser.error("Limits: retries <= 5, parallel <= 16, process timeout 1..86400 seconds")
    if not 1 <= args.subnet_concurrency <= args.global_concurrency <= 16 or not 16 <= args.scan_rate <= 10000:
        parser.error("Concurrency must satisfy 1 <= subnet <= global <= 16; scan rate must be 16..10000")
    if args.tabs is not None:
        if args.tabs < 2:
            parser.error("--tabs must be at least 2")
        if args.parallel > 1:
            parser.error("--tabs and --parallel are different concurrency modes — use only one")
        if args.no_auto_tabs:
            parser.error("--tabs and --no-auto-tabs contradict each other — use only one")
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
    if args.allow_intrusive and not args.authorization_note:
        parser.error("--allow-intrusive requires --authorization-note")
    if args.json and not args.dry_run:
        parser.error("--json is supported with --dry-run and review commands")
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


def _empty_nxc_row(target):
    return {"target": target, "port": "", "hostname": "", "os": "",
            "smbv1": "", "smb_signing": "", "null_auth": "",
            "rdp_nla": "", "details": ""}


def _is_ip_literal(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_nxc_output(output, targets, null_auth_attempt=False, resolver=None):
    """Extract host facts from NetExec's human-readable protocol output.

    Every IP or hostname target gets a row, so hosts that never answered still
    show up (as blanks). CIDR and range targets get no row of their own; each
    host that responds within them shows up on its own row instead. A hostname
    target whose resolved IP appears in the output is merged into that IP's row
    rather than listed twice.
    """
    seeded = [target for target in targets
              if not is_network_target(target) and not parse_last_octet_range(target)]
    rows = {target: _empty_nxc_row(target) for target in seeded}
    # NetExec lines start with the protocol name: "SMB  10.0.0.5  445  DC01  [*] ..."
    line_pattern = re.compile(r"^([A-Z][A-Z0-9]*)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*)$")

    for raw_line in output.splitlines():
        line = strip_ansi(raw_line).strip()
        match = line_pattern.match(line)
        if not match:
            continue
        _, target, port, hostname, details = match.groups()
        row = rows.setdefault(target, _empty_nxc_row(target))
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

    # Fold hostname targets into the row of the IP they resolve to.
    for target in seeded:
        if _is_ip_literal(target) or rows[target]["port"]:
            continue
        resolved, _ = (resolver or resolve_scan_target)(target, timeout=3)
        if resolved != target and resolved in rows and rows[resolved]["port"]:
            if not rows[resolved]["hostname"]:
                rows[resolved]["hostname"] = target
            del rows[target]

    return list(rows.values())


def nxc_table_columns(protocol, queries):
    if not queries:
        return [("target", "IP"), ("hostname", "HOSTNAME"), ("os", "OS")]
    if "all" in queries:
        queries = ["os", "hostname", "smbv1", "smb-signing", "null-auth", "rdp-nla"]
    columns = [("target", "IP")]
    fields = {
        "os": ("os", "OS"), "hostname": ("hostname", "HOSTNAME"),
        "smbv1": ("smbv1", "SMBv1"), "smb-signing": ("smb_signing", "SMB Signing"),
        "null-auth": ("null_auth", "Null Auth"), "rdp-nla": ("rdp_nla", "RDP NLA"),
    }
    for query in queries:
        field = fields[query]
        if field not in columns:
            columns.append(field)
    return columns


# Per-field color, keyed by field name and (lowercased) cell value. "*" is the
# fallback color for a field when the value doesn't match a listed key. Fields
# not listed here fall back to plain white. True/False are colored by their
# security meaning rather than uniformly, since that's what a reader is
# actually scanning the table for: SMBv1 enabled or signing disabled is a
# finding (red), NLA enabled or signing enforced is not (green).
_NXC_CELL_COLORS = {
    "target":      {"*": C.CYAN + C.BOLD},
    "hostname":    {"*": C.WHITE},
    "os":          {"*": C.YELLOW},
    "smbv1":       {"true": C.RED + C.BOLD, "false": C.GREEN, "*": C.DIM},
    "smb_signing": {"true": C.GREEN, "false": C.RED + C.BOLD, "*": C.DIM},
    "rdp_nla":     {"true": C.GREEN, "false": C.RED + C.BOLD, "*": C.DIM},
    "null_auth":   {"success": C.RED + C.BOLD, "*": C.DIM},
}


def _nxc_cell_color(field, value):
    colors = _NXC_CELL_COLORS.get(field)
    if not colors:
        return C.WHITE
    return colors.get(str(value).strip().lower(), colors["*"])


# The "bad" value per security field — the one that should count as a finding
# in the summary line under the table. Absent/blank never counts (the field
# wasn't observed, not necessarily unsafe).
_NXC_FINDING_VALUE = {
    "smbv1": "true", "smb_signing": "false", "rdp_nla": "false", "null_auth": "success",
}


def print_nxc_table(rows, columns, protocol=None):
    if not rows:
        print(c(C.YELLOW, "  [!] No hosts responded — nothing to show."))
        return

    def cell_text(field, value):
        text = str(value).strip()
        return text if text else "-"

    widths = {field: max(len(title), *(len(cell_text(field, row.get(field, ""))) for row in rows))
              for field, title in columns}
    widths = {field: min(width, 46) for field, width in widths.items()}

    def format_cell(field, value):
        return cell_text(field, value)[:widths[field]].ljust(widths[field])

    content_width = sum(widths.values()) + 3 * (len(columns) - 1)
    title = "  NXC RESULTS"
    if protocol:
        title += f" — {protocol.upper()}"
    title += f"  ({len(rows)} host{'s' if len(rows) != 1 else ''})"

    print(c(C.CYAN + C.BOLD, title))
    print(c(C.DIM, "  ┌─" + "─" * content_width + "─┐"))
    header = " │ ".join(c(C.BOLD, format_cell(field, title)) for field, title in columns)
    print(c(C.DIM, "  │ ") + header + c(C.DIM, " │"))
    print(c(C.DIM, "  ├─" + "─" * content_width + "─┤"))
    findings = 0
    for row in rows:
        cells = [c(_nxc_cell_color(field, row.get(field, "")), format_cell(field, row.get(field, "")))
                 for field, _ in columns]
        print(c(C.DIM, "  │ ") + " │ ".join(cells) + c(C.DIM, " │"))
        for field, _ in columns:
            if str(row.get(field, "")).strip().lower() == _NXC_FINDING_VALUE.get(field):
                findings += 1
    print(c(C.DIM, "  └─" + "─" * content_width + "─┘"))

    finding_fields = {field for field, _ in columns} & set(_NXC_FINDING_VALUE)
    if finding_fields:
        color = C.RED + C.BOLD if findings else C.GREEN
        plural = "s" if findings != 1 else ""
        print(c(color, f"  {findings} finding{plural} across {len(rows)} host(s).") +
              c(C.DIM, "  (red = finding, green = safe)"))


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
    if ACTIVE_SCOPE is not None:
        pinned = [address for target in targets for address in ACTIVE_SCOPE.destinations(target)]
        with tempfile.TemporaryDirectory(prefix="scanrunner-scope-") as temporary:
            source = os.path.join(temporary, "targets.txt")
            with open(source, "x", encoding="utf-8") as file:
                file.write("\n".join(pinned) + "\n")
            return _run_nxc_command(binary, protocol, source, targets, nxc_extra, queries, output_dir)
    return _run_nxc_command(binary, protocol, target_source, targets, nxc_extra, queries, output_dir)


def _run_nxc_command(binary, protocol, target_source, targets, nxc_extra, queries, output_dir):
    """Run NetExec with live output, then build table exports."""
    if queries and protocol.lower() not in {"smb", "rdp"}:
        print(c(C.YELLOW,
                "  [!] Focused queries are currently parsed only from SMB/RDP output."))

    effective_extra = list(nxc_extra)
    credential_supplied = any(
        token in {"-u", "--username", "-p", "--password"}
        or token.startswith(("--username=", "--password="))
        for token in effective_extra)
    if "null-auth" in queries and not credential_supplied:
        effective_extra.extend(["-u", "", "-p", ""])

    command = [binary, protocol, target_source, *effective_extra]
    print(c(C.DIM, "  Command : " + " ".join(redact_command(command))))
    print(c(C.DIM, "─" * 70))

    store = ACTIVE_STORE or RunStore(output_dir, {'tool': 'nxc', 'options': effective_extra})
    job = store.wait_claim(protocol + ':' + ','.join(targets))
    if job is None:
        print('NetExec target set is already claimed')
        return False
    command = []
    code, process_state, output = None, 'Interrupted', ''
    try:
        source_path = os.path.join(job['directory'], 'targets.txt')
        if os.path.isfile(target_source):
            shutil.copyfile(target_source, source_path)
        else:
            with open(source_path, 'x', encoding='utf-8') as file:
                file.write(target_source + '\n')
        command = [binary, protocol, source_path, *effective_extra]
        if ACTIVE_CONFIG.get("binary_sha256") and file_sha256(binary) != ACTIVE_CONFIG["binary_sha256"]:
            raise ValueError("Scanner binary changed since run authorization")
        code, process_state = capture_process(command, job['directory'], store.config.get('timeout', 600), live=False)
        with open(os.path.join(job['directory'], 'stdout.bin'), 'rb') as file:
            output = file.read().decode('utf-8', errors='replace')
    finally:
        store.finish_job(job, 'COMPLETE' if code == 0 and process_state == 'Exited' else
                         ('FAILED' if process_state == 'Exited' else process_state),
                         code, code == 0 and process_state == 'Exited', command)
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    raw_path = os.path.join(job['directory'], 'stdout.bin')
    rows = parse_nxc_output(
        output, targets,
        null_auth_attempt=uses_anonymous_nxc_credentials(effective_extra),
    )
    rows = [{field: redact_output_text(str(value)) for field, value in row.items()} for row in rows]
    columns = nxc_table_columns(protocol, queries)
    print_nxc_table(rows, columns, protocol=protocol)

    fieldnames = [field for field, _ in columns]
    csv_path = os.path.join(output_dir, f"nxc-{sanitize_filename(protocol)}-{timestamp}.csv")
    json_path = os.path.join(output_dir, f"nxc-{sanitize_filename(protocol)}-{timestamp}.json")
    with atomic_text(csv_path, newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows({field: csv_safe(row.get(field, "")) for field in fieldnames} for row in rows)
    with atomic_text(json_path) as file:
        json.dump([{field: row.get(field, "") for field in fieldnames} for row in rows], file, indent=2)

    print(c(C.GREEN, f"  [+] Saved NXC output: {raw_path}"))
    print(c(C.GREEN, f"  [+] Saved table data: {csv_path}, {json_path}"))
    if code != 0:
        print(c(C.RED, f"  [!] NetExec exited with status {code}. See raw output above."))
    with store.connect() as database:
        for target in targets:
            database.execute("UPDATE run_targets SET outcome=? WHERE run_id=? AND requested=?",
                             ("COMPLETE" if code == 0 and process_state == "Exited" else process_state,
                              store.run_id, target))
    store.end("Finished; review individual NetExec outcomes")
    return code == 0 and process_state == 'Exited'



# ═══════════════════════════════════════════════════════════════════════════════
#  PING
# ═══════════════════════════════════════════════════════════════════════════════

def ping_host(ip):
    if ACTIVE_SCOPE is not None:
        ip = ACTIVE_SCOPE.destinations(ip)[0]
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        timeout = "1000" if sys.platform == "darwin" else "1"
        cmd = ["ping", "-c", "1", "-W", timeout, ip]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    return r.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN FILE INSPECTION
# ═══════════════════════════════════════════════════════════════════════════════

def get_file_status(filepath):
    """Classify an Nmap normal-output report.

    COMPLETE    finished, results are whole
    DOWN        finished, but Nmap found 0 hosts up
    TIMEOUT     finished, but a host hit --host-timeout (results are partial)
    UNRESOLVED  finished, but the target never resolved (0 IP addresses)
    INCOMPLETE  no "Nmap done" line — interrupted or still running
    UNKNOWN     unreadable / missing
    """
    try:
        with open(filepath, "rb") as f:
            content = f.read().decode(errors="ignore")
    except Exception:
        return "UNKNOWN"
    tail = content[-4096:]
    if "Nmap done" not in tail:
        return "INCOMPLETE"
    if re.search(r"Nmap done.*\b0 IP addresses\b", tail):
        return "UNRESOLVED"
    if "due to host timeout" in content:
        return "TIMEOUT"
    if re.search(r"\(0 hosts? up\)", tail):
        return "DOWN"
    return "COMPLETE"


REPORT_STATUS_PROBLEMS = {
    "TIMEOUT": "Nmap hit --host-timeout before finishing (partial results kept); "
               "raise --host-timeout and rescan",
    "UNRESOLVED": "Nmap could not resolve the target (0 IP addresses scanned)",
    "INCOMPLETE": "Nmap exited without finishing the report",
    "UNKNOWN": "Nmap produced no report file",
}

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
    status_color = {"COMPLETE": C.GREEN, "DOWN": C.ORANGE}.get(status, C.YELLOW)
    if status == "DOWN":
        status += " (Nmap finished, 0 hosts up)"
    elif status in {"TIMEOUT", "UNRESOLVED"}:
        status += f" ({REPORT_STATUS_PROBLEMS[status]})"

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
#
#  Every scan writes <target>.txt (-oN) and <target>.xml (-oX). The XML is the
#  authoritative source — it separates hosts (a CIDR target covers many) and
#  carries product/version data. The normal output is the fallback for
#  interrupted scans (whose XML is truncated) and reports written by older
#  versions that had no XML.
# ═══════════════════════════════════════════════════════════════════════════════

def _xml_report_path(report_path):
    return f"{os.path.splitext(report_path)[0]}.xml"


def read_nmap_xml(xml_path):
    if os.path.getsize(xml_path) > 32 * 1024 * 1024:
        raise ValueError("Nmap XML exceeds the 32 MiB parser limit")
    with open(xml_path, "rb") as file:
        data = file.read()
    if b"\x00" in data or b"<!ENTITY" in data.upper() or re.search(br"<!DOCTYPE\b[^>]*\[", data, re.IGNORECASE):
        raise ValueError("XML entities and internal DTD subsets are refused")
    root = ET.fromstring(data)
    if root.tag != "nmaprun":
        raise ValueError("not an Nmap XML report")
    return root


def _hosts_from_xml(xml_path):
    root = read_nmap_xml(xml_path)
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        addresses = {addr.get("addrtype"): addr.get("addr") for addr in host.findall("address")}
        hostname = host.find("hostnames/hostname")
        entry = {
            "address": addresses.get("ipv4") or addresses.get("ipv6") or "",
            "hostname": hostname.get("name", "") if hostname is not None else "",
            "status": status.get("state", "unknown") if status is not None else "unknown",
            "ports": [],
        }
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = version = ""
            if service is not None:
                name = service.get("name", "")
                version = " ".join(part for part in (service.get("product", ""),
                                                     service.get("version", ""),
                                                     service.get("extrainfo", "")) if part)
            entry["ports"].append({
                "port": f"{port.get('portid')}/{port.get('protocol')}",
                "service": name or "unknown",
                "version": version,
            })
        hosts.append(entry)
    return hosts


_REPORT_HEADER = re.compile(r"^Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))")
_PORT_LINE = re.compile(r"^\s*(\d+/\w+)\s+open\s+(\S+)(?:\s+(.*\S))?\s*$")


def _hosts_from_normal_output(report_path):
    hosts = []
    current = None
    with open(report_path, "r", errors="ignore") as f:
        for line in f:
            header = _REPORT_HEADER.match(line)
            if header:
                name, address, bare = header.groups()
                current = {"address": address or bare, "hostname": name or "",
                           "status": "up", "ports": []}
                hosts.append(current)
                continue
            if current is None:
                continue
            if line.startswith("Host seems down") or "host down" in line.lower():
                current["status"] = "down"
            port = _PORT_LINE.match(line)
            if port:
                current["ports"].append({"port": port.group(1), "service": port.group(2),
                                         "version": port.group(3) or ""})
    return hosts


def parse_nmap_hosts(report_path):
    """Return per-host results for a target's report.

    Each host is {"address", "hostname", "status", "ports": [{"port",
    "service", "version"}]}; only open ports are listed. Returns [] when the
    report doesn't exist.
    """
    xml_path = _xml_report_path(report_path)
    if os.path.exists(xml_path):
        try:
            return _hosts_from_xml(xml_path)
        except (ET.ParseError, ValueError, OSError):
            pass   # truncated XML from an interrupted scan — use the text report
    if not os.path.exists(report_path):
        return []
    try:
        return _hosts_from_normal_output(report_path)
    except OSError:
        return []


def port_label(port):
    return f"{port['port']}/{port['service']}"


def parse_open_ports(filepath):
    """Return 'port/proto/service' strings for every open port in a report."""
    return [port_label(port) for host in parse_nmap_hosts(filepath) for port in host["ports"]]


def host_label(target, host):
    """Label a discovered host for display, relative to the target that found it.

    CIDR/range targets: "10.0.0.5 (10.0.0.0/24)"; hostname targets:
    "web.lab (10.0.0.5)"; otherwise just the address.
    """
    if not host or host == target:
        return target
    if is_network_target(target) or parse_last_octet_range(target):
        return f"{host} ({target})"
    return f"{target} ({host})"


def hosts_with_open_ports(report_path):
    """Return [(host_label, [port labels])] for hosts in a report that have open ports."""
    result = []
    for host in parse_nmap_hosts(report_path):
        if host["ports"]:
            label = host["address"] or host["hostname"]
            result.append((label, [port_label(port) for port in host["ports"]]))
    return result


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
        c(C.BOLD, "  Progress  [") + c(C.CYAN, bar) + c(C.BOLD, "]  ") +
        c(C.YELLOW + C.BOLD, f"{percent:.1f}%") +
        c(C.DIM,             f"  ({done}/{total})  {total - done} remaining")
    )
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  NMAP — BUILD COMMAND
# ═══════════════════════════════════════════════════════════════════════════════

def _build_nmap_command(target, output_file, nmap_extra, use_pn=False):
    cmd = [ACTIVE_CONFIG.get("binary", "nmap")]
    if ACTIVE_CONFIG.get("binary_sha256") and file_sha256(cmd[0]) != ACTIVE_CONFIG["binary_sha256"]:
        raise ValueError("Scanner binary changed since run authorization")

    # Show Nmap progress every 15 seconds
    if not has_nmap_option(nmap_extra, "--stats-every"):
        cmd.extend(["--stats-every", "15s"])

    if use_pn and not has_nmap_option(nmap_extra, "-Pn"):
        cmd.append("-Pn")

    if nmap_extra:
        cmd.extend(nmap_extra)

    xml_file = f"{os.path.splitext(output_file)[0]}.xml"
    destinations = ACTIVE_SCOPE.destinations(target) if ACTIVE_SCOPE is not None else [target]
    versions = {ipaddress.ip_address(address).version for address in destinations if _is_ip_literal(address)}
    if versions == {4, 6}:
        raise ValueError("Mixed IPv4/IPv6 hostname answers require separate address targets")
    if versions == {6} or (":" in target and "/" in target):
        cmd.append("-6")
    cmd.extend(["-oN", output_file, "-oX", xml_file, "--", *destinations])

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
    """Overwrite current line in-place (for live timer). No newline.

    Skipped when stdout isn't a terminal: in a log file or pipe each redraw
    would pile up as another copy of the line.
    """
    if not sys.stdout.isatty():
        return
    sys.stdout.write("\r" + text + "  ")
    sys.stdout.flush()

def _rclear():
    """Clear the current ticker line before printing real output."""
    if not sys.stdout.isatty():
        return
    sys.stdout.write("\r" + " " * 72 + "\r")
    sys.stdout.flush()


def run_nmap_scan(target, output_file, nmap_extra, use_pn=False):
    status, detail = execute_nmap(target, output_file, nmap_extra, use_pn, live=True)
    if status == 'Interrupted':
        raise KeyboardInterrupt
    if status == 'FATAL':
        print(detail)
        return 'FATAL'
    if status in {'CLAIMED', 'SKIPPED'}:
        return 'SKIPPED'
    return status in {'COMPLETE', 'DOWN'}


# Nmap refuses to run at all for configuration errors — a scan type that needs
# root, a bad port spec, a missing NSE script ("... QUITTING!"), or an unknown
# or incomplete option ("See the output of nmap -h ..."). Those fail
# identically for every host, so the run stops instead of burning through the
# whole list.
NMAP_FATAL_CONTEXT_LINES = 6
_NMAP_FATAL_MARKERS = ("QUITTING!", "See the output of nmap -h")


def nmap_fatal_reason(lines):
    """Return the lines explaining a fatal Nmap error, or None."""
    lines = [line for line in lines if line.strip()]
    if not any(marker in line for line in lines for marker in _NMAP_FATAL_MARKERS):
        return None
    return "\n".join(lines[-NMAP_FATAL_CONTEXT_LINES:])


def run_nmap_quiet(target, output_file, nmap_extra, use_pn, retries):
    for attempt in range(1, retries + 2):
        status, detail = execute_nmap(target, output_file, nmap_extra, use_pn)
        if status in {'COMPLETE', 'DOWN', 'FATAL', 'Interrupted', 'CLAIMED', 'SKIPPED'}:
            return status, attempt, detail
        if attempt <= retries:
            time.sleep(min(2 ** (attempt - 1), 8))
    return 'FAILED', retries + 1, detail


def print_open_ports_oneliner(ip, filepath):
    hosts = hosts_with_open_ports(filepath)
    if not hosts:
        print(c(C.DIM, "  No open ports found."))
        return []
    if len(hosts) == 1 and not is_network_target(ip) and not parse_last_octet_range(ip):
        print(c(C.GREEN + C.BOLD, "  Open  →  ") + c(C.WHITE, "  ".join(hosts[0][1])))
    else:
        for host, ports in hosts:
            print(c(C.GREEN + C.BOLD, f"  Open  →  {host:<16} ") + c(C.WHITE, "  ".join(ports)))
    return [port for _, ports in hosts for port in ports]


INVENTORY_FIELDS = ["target", "host", "hostname", "owner", "environment", "port_service", "version"]


def inventory_rows_for_target(output_dir, target, metadata):
    details = metadata.get(target, {})
    report = os.path.join(output_dir, f"{sanitize_filename(target)}.txt")
    rows = []
    for host in parse_nmap_hosts(report):
        for port in host["ports"]:
            rows.append({
                "target": target,
                "host": host["address"],
                "hostname": host["hostname"],
                "owner": details.get("owner", ""),
                "environment": details.get("environment", ""),
                "port_service": port_label(port),
                "version": port["version"],
            })
    return rows


def render_html_report(rows):
    """Return a standalone HTML page: per-host open ports plus a by-service summary."""
    esc = lambda value: html.escape(str(value or ""))
    hosts = sorted({(row.get("host") or row.get("target", "")) for row in rows})
    by_service = {}
    for row in rows:
        by_service.setdefault(row.get("port_service", ""), set()).add(
            row.get("host") or row.get("target", ""))

    host_rows = "\n".join(
        "<tr>" + "".join(f"<td>{esc(row.get(field))}</td>" for field in INVENTORY_FIELDS) + "</tr>"
        for row in rows
    ) or f"<tr><td colspan=\"{len(INVENTORY_FIELDS)}\">No open ports found.</td></tr>"
    service_rows = "\n".join(
        f"<tr><td>{esc(service)}</td><td>{len(service_hosts)}</td>"
        f"<td>{esc(', '.join(sorted(service_hosts)))}</td></tr>"
        for service, service_hosts in sorted(by_service.items(),
                                             key=lambda item: (-len(item[1]), item[0]))
    ) or "<tr><td colspan=\"3\">No open ports found.</td></tr>"
    headers = "".join(f"<th>{esc(field.replace('_', ' ').title())}</th>" for field in INVENTORY_FIELDS)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Scanrunner Inventory</title>"
        "<style>:root{color-scheme:light dark}body{font-family:system-ui,sans-serif;margin:2rem;"
        "line-height:1.4}table{border-collapse:collapse;margin-bottom:2rem;width:100%}"
        "th,td{border:1px solid #8886;padding:.4rem .6rem;text-align:left;vertical-align:top}"
        "th{background:#8882}.meta{opacity:.75}</style>"
        "<h1>Scanrunner Open-Port Inventory</h1>"
        f"<p class=\"meta\">Generated {esc(generated)} · {len(hosts)} host(s) with open ports · "
        f"{len(rows)} open port(s) · {len(by_service)} distinct service(s)</p>"
        f"<h2>By service</h2><table><tr><th>Port / Service</th><th>Hosts</th><th>Host list</th></tr>"
        f"{service_rows}</table>"
        f"<h2>By host</h2><table><tr>{headers}</tr>{host_rows}</table></html>"
    )


def write_inventory(output_dir, targets, metadata, write_html):
    """Write machine-readable port inventory files from completed normal output.

    Merges into any existing inventory rather than overwriting it outright:
    when several scanrunner processes (spawned terminal tabs) share one
    output directory, each only knows its own slice of targets, so a plain
    overwrite would erase whatever the other processes already wrote.
    """
    new_rows = []
    for target in targets:
        new_rows.extend(inventory_rows_for_target(output_dir, target, metadata))

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

        # Rows written by older versions lack host/hostname/version; fill blanks
        # so every row has the same shape.
        rows = [{field: redact_output_text(str(row.get(field, ""))) for field in INVENTORY_FIELDS} for row in rows]
        with atomic_text(csv_path, newline="") as file:
            writer = csv.DictWriter(file, fieldnames=INVENTORY_FIELDS)
            writer.writeheader()
            writer.writerows({field: csv_safe(value) for field, value in row.items()} for row in rows)
        with atomic_text(json_path) as file:
            json.dump(rows, file, indent=2)

        if write_html:
            with atomic_text(os.path.join(output_dir, "open-ports-report.html")) as file:
                file.write(render_html_report(rows))


# ═══════════════════════════════════════════════════════════════════════════════
#  SUMMARY BOX + OPEN PORTS TABLE
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(ips, completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file, output_dir, since=None):
    """Print outcome counts, reconcile every target, and list open ports.

    Counts cover only this target list, one outcome per target (its latest).
    With `since` (the run's start time), only outcomes logged during this run
    count — an outcome left over from an earlier run can't hide a target
    this run never reached.
    """
    targets = set(ips)
    outcomes = latest_outcomes(output_dir, since=since, log_paths={
        "completed": completed_file, "skipped": skipped_file,
        "no_ping": not_ping_file, "failed": failed_file,
    })
    outcomes = {target: outcome for target, outcome in outcomes.items() if target in targets}

    def with_outcome(name):
        return {target for target, outcome in outcomes.items() if outcome == name}

    completed_ips = with_outcome("completed")
    skipped_ips   = with_outcome("skipped")
    no_ping_ips   = with_outcome("no_ping")
    failed_ips    = with_outcome("failed")
    rescanned_ips = read_logged_ips(rescanned_file, since=since) & targets

    print()
    print(c(C.BOLD, "  ╔══════════════════════════════╗"))
    print(c(C.BOLD, "  ║       SCAN SUMMARY           ║"))
    print(c(C.BOLD, "  ╠══════════════════════════════╣"))
    print(c(C.BOLD, "  ║  ") + c(C.GREEN  + C.BOLD, f"  Completed : {len(completed_ips):<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.YELLOW + C.BOLD, f"  Skipped   : {len(skipped_ips):<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.CYAN   + C.BOLD, f"  Rescanned : {len(rescanned_ips):<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.ORANGE + C.BOLD, f"  Down/NoPing: {len(no_ping_ips):<5}") + c(C.BOLD, "        ║"))
    print(c(C.BOLD, "  ║  ") + c(C.RED    + C.BOLD, f"  Failed    : {len(failed_ips):<5}")    + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ╚══════════════════════════════╝"))

    # ── Reconciliation — every input target must land in some audit log ───────
    # This is the safety net: a target that isn't completed, skipped, logged as
    # unreachable, or logged as failed has NO recorded outcome at all (e.g. the
    # run was interrupted before reaching it). That must never pass silently.
    unaccounted = [ip for ip in ips if ip not in outcomes]
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

    # ── Open ports table across this list's completed targets ─────────────────
    # A target counts if it was ever completed (not just this run) so a
    # resumed run still shows the full picture; CIDR targets list each host.
    ever_completed = read_logged_ips(completed_file)
    host_ports = []
    for ip in ips:
        if ip not in ever_completed:
            continue
        report = os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")
        for host, ports in hosts_with_open_ports(report):
            host_ports.append((host_label(ip, host), ports))

    if host_ports:
        print()
        sep(C.CYAN, "═")
        print(c(C.CYAN + C.BOLD, "  OPEN PORTS SUMMARY"))
        sep(C.CYAN, "═")
        col = max(20, *(len(label) for label, _ in host_ports))
        print(c(C.BOLD, f"  {'HOST':<{col}}  OPEN PORTS"))
        sep()
        for label, ports in host_ports:
            ports_str = "  ".join(ports)
            print(c(C.WHITE, f"  {label:<{col}}") + "  " + c(C.GREEN, ports_str))
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
    if getattr(args, "allow_intrusive", False):
        cmd.extend(["--allow-intrusive", "--authorization-note", args.authorization_note])
    cmd.extend(["--engagement", getattr(args, "engagement", "default"),
                "--process-timeout", str(getattr(args, "process_timeout", 600))])
    cmd.extend(["--global-concurrency", str(getattr(args, "global_concurrency", 4)),
                "--subnet-concurrency", str(getattr(args, "subnet_concurrency", 2)),
                "--scan-rate", str(getattr(args, "scan_rate", 100))])
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


def _terminal_failed_to_start(process, grace=0.5):
    """Return whether a just-launched terminal exited with an error right away.

    Popen succeeding only means the terminal binary started; without a usable
    display it exits moments later and the tab's targets would never run.
    """
    try:
        return process.wait(timeout=grace) != 0
    except subprocess.TimeoutExpired:
        return False   # still running — the window is up


def _spawn_linux_terminal(command, title, cwd):
    if os.environ.get("TMUX"):
        try:
            process = subprocess.Popen(["tmux", "new-window", "-n", title, "-c", cwd, *command])
            if not _terminal_failed_to_start(process):
                return True
        except OSError:
            pass
    # GUI terminals need an X11/Wayland display (not available over plain SSH).
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    quoted_command = " ".join(shlex.quote(part) for part in command)
    candidates = []
    for terminal in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal"):
        path = shutil.which(terminal)
        if not path:
            continue
        if terminal == "gnome-terminal":
            candidates.append([path, "--title", title, "--working-directory", cwd, "--", *command])
        else:
            candidates.append([path, "-e", quoted_command])
    xterm = shutil.which("xterm")
    if xterm:
        candidates.append([xterm, "-T", title, "-e", *command])
    for candidate in candidates:
        try:
            process = subprocess.Popen(candidate, cwd=cwd)
        except OSError:
            continue
        if not _terminal_failed_to_start(process):
            return True
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
    Use --tabs N instead to split without this prompt, at any list size, and
    --no-auto-tabs to make sure this prompt never fires (e.g. a big list you
    always want to run one host at a time in this window).
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

    _launch_tabs(args, pending_ips, output_dir, tab_count)
    return True


def _launch_tabs(args, pending_ips, output_dir, tab_count):
    """Split pending_ips into tab_count parts and spawn a scanrunner tab for each.

    Shared by the interactive prompt (offer_terminal_tabs) and the explicit
    --tabs N flag. Caller is responsible for validating tab_count first.
    """
    tabs_dir = os.path.join(output_dir, "tabs")
    os.makedirs(tabs_dir, exist_ok=True)
    launched_at = run_start_time()
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
    # --status measures tab progress from the manifest's mtime; pin it to the
    # launch time, since fast tabs may log outcomes before this file is written.
    launch_epoch = launched_at.timestamp()
    os.utime(manifest_path, (launch_epoch, launch_epoch))

    print(c(C.GREEN + C.BOLD,
            f"\n  [+] Launched {tab_count} tab(s): {spawned} in terminal windows, "
            f"{backgrounded} running in background."))
    print(c(C.CYAN, f"  [i] All tabs write their reports directly into {output_dir}/."))
    print(c(C.CYAN, f"  [i] Target-to-tab manifest saved: {manifest_path}"))

    _watch_tab_progress(output_dir, pending_ips, since=launched_at)
    return True


def _watch_tab_progress(output_dir, pending_ips, poll_interval=3, since=None):
    """Live-poll the shared output files and render an aggregate dashboard.

    All spawned tabs write completed.txt/skipped.txt/failed.txt/etc. and per-
    host reports into the same output_dir this window already knows about, so
    overall progress can be read back without any inter-process signaling.
    Redraws in place; Ctrl+C detaches (the tabs keep scanning) rather than
    killing anything. Only outcomes logged at or after `since` (the launch
    time) count, so leftovers from an earlier run don't show as progress.
    """
    if not sys.stdout.isatty():
        print(c(C.YELLOW,
                "  [!] Not an interactive terminal — not tracking tab progress here. "
                f"Check {output_dir}/unaccounted.txt and the open-ports inventory when done.\n"))
        return

    retry_file     = os.path.join(output_dir, "retried.txt")

    total = len(pending_ips)
    pending_set = set(pending_ips)

    print(c(C.CYAN,
            "\n  [*] Watching combined progress across all tabs — "
            "Ctrl+C stops watching, tabs keep scanning.\n"))

    lines_printed = 0
    try:
        while True:
            outcomes  = {target: outcome for target, outcome
                         in latest_outcomes(output_dir, since=since).items()
                         if target in pending_set}
            completed = {t for t, o in outcomes.items() if o == "completed"}
            skipped   = {t for t, o in outcomes.items() if o == "skipped"}
            failed    = {t for t, o in outcomes.items() if o == "failed"}
            no_ping   = {t for t, o in outcomes.items() if o == "no_ping"}
            retried   = read_logged_ips(retry_file, since=since) & pending_set
            accounted = set(outcomes)
            remaining = total - len(accounted)

            open_port_hosts = open_port_total = 0
            for ip in completed:
                for _, ports in hosts_with_open_ports(
                        os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")):
                    open_port_hosts += 1
                    open_port_total += len(ports)

            done_frac = (len(accounted) / total) if total else 1.0
            filled    = int(30 * done_frac)
            bar       = "█" * filled + "░" * (30 - filled)

            block = [
                c(C.BOLD, "  Progress  [") + c(C.CYAN, bar) + c(C.BOLD, "]  ") +
                c(C.YELLOW + C.BOLD, f"{done_frac * 100:.1f}%") +
                c(C.DIM, f"  ({len(accounted)}/{total} accounted for)"),
                "  " +
                c(C.GREEN  + C.BOLD, f"Completed: {len(completed):<5}") +
                c(C.YELLOW + C.BOLD, f"  Skipped: {len(skipped):<5}") +
                c(C.RED    + C.BOLD, f"  Failed: {len(failed):<5}"),
                "  " +
                c(C.ORANGE + C.BOLD, f"Down/NoPing: {len(no_ping):<5}") +
                c(C.CYAN   + C.BOLD, f"  Retried: {len(retried):<5}") +
                c(C.DIM,             f"  Running/Queued: {max(remaining, 0):<5}"),
                c(C.GREEN, f"  Open ports so far: {open_port_total} across {open_port_hosts} host(s)"),
                "",
            ]

            if lines_printed:
                sys.stdout.write(f"\033[{lines_printed}A")
            for line in block:
                sys.stdout.write("\033[2K" + line + "\n")
            sys.stdout.flush()
            lines_printed = len(block)

            if len(accounted) >= total:
                break
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print(c(C.YELLOW,
                "\n  [~] Stopped watching — tabs are still running in the background. "
                f"Re-check {output_dir}/ any time.\n"))
        return

    print(c(C.GREEN + C.BOLD, "  [+] All tabs finished."))
    unaccounted_path = os.path.join(output_dir, "unaccounted.txt")
    if os.path.exists(unaccounted_path):
        print(c(C.RED, f"  [!] Some targets were unaccounted for — see {unaccounted_path}"))
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  RESUME
# ═══════════════════════════════════════════════════════════════════════════════

def previously_completed(ips, output_dir, completed_file):
    """Return the targets in ips that don't need scanning again.

    A target is done when its report is COMPLETE, or when it was logged as
    completed at or after its report was last written (marked done with [m],
    or a report written by a version without per-target files). A report
    overwritten after that log entry — e.g. a rescan that was interrupted —
    does not count, even though completed.txt still lists the target. A report
    whose host was down never counts, so --resume tries it again.
    """
    if ACTIVE_STORE is not None:
        pn = has_nmap_option(ACTIVE_CONFIG.get("options", []), "-Pn")
        return {target for target in ips if ACTIVE_STORE.completed(target, pn)}
    last_completed = {}
    for stamp, target in read_log_entries(completed_file):
        last_completed[target] = max(stamp, last_completed.get(target, datetime.min))
    done = set()
    for ip in ips:
        report = os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")
        if not os.path.exists(report):
            if ip in last_completed:
                done.add(ip)
            continue
        status = get_file_status(report)
        if status == "COMPLETE":
            done.add(ip)
        elif status != "DOWN" and ip in last_completed:
            written = datetime.fromtimestamp(int(os.path.getmtime(report)))
            if last_completed[ip] >= written:
                done.add(ip)
    return done


# ═══════════════════════════════════════════════════════════════════════════════
#  STATUS AND DIFF  (read-only review of output folders)
# ═══════════════════════════════════════════════════════════════════════════════

_NON_REPORT_TXT = {"completed.txt", "skipped.txt", "rescanned.txt", "not-pingip.txt",
                   "failed.txt", "retried.txt", "unaccounted.txt", "tab-manifest.txt"}


def find_reports(output_dir):
    """Return sorted paths of Nmap normal-output reports in output_dir."""
    reports = []
    try:
        names = sorted(os.listdir(output_dir))
    except OSError:
        return reports
    for name in names:
        path = os.path.join(output_dir, name)
        if not name.endswith(".txt") or name in _NON_REPORT_TXT or name.startswith("nxc-") \
                or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
        except OSError:
            continue
        if first_line.startswith("# Nmap"):
            reports.append(path)
    return reports


def collect_open_ports(output_dir):
    """Return {host: {port/proto: service}} across every report in output_dir."""
    hosts = {}
    for report in find_reports(output_dir):
        for host in parse_nmap_hosts(report):
            key = host["address"] or host["hostname"]
            if not key or host["status"] != "up":
                continue
            entry = hosts.setdefault(key, {})
            for port in host["ports"]:
                entry[port["port"]] = port["service"]
    return hosts


def print_status(output_dir):
    """Summarise an output folder without scanning anything. Returns an exit code."""
    if not os.path.isdir(output_dir):
        print(c(C.RED + C.BOLD, f"  [!] Output folder not found: {output_dir}"))
        return 1

    print(c(C.CYAN + C.BOLD, f"  STATUS — {os.path.abspath(output_dir)}"))
    sep()

    outcomes = latest_outcomes(output_dir)
    counts = Counter(outcomes.values())
    labels = (("completed", "Completed", C.GREEN), ("skipped", "Skipped", C.YELLOW),
              ("no_ping", "Down/NoPing", C.ORANGE), ("failed", "Failed", C.RED))
    print(c(C.BOLD, "  Latest outcome per target (all runs):"))
    for key, label, color in labels:
        print(c(color + C.BOLD, f"    {label:<12}: {counts.get(key, 0)}"))
    print(c(C.DIM, f"    {'Total':<12}: {len(outcomes)}"))

    manifest = os.path.join(output_dir, "tab-manifest.txt")
    if os.path.exists(manifest):
        planned = []
        with open(manifest, encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3 and parts[2]:
                    planned.extend(parts[2].split(","))
        since = datetime.fromtimestamp(int(os.path.getmtime(manifest)))
        done_since = latest_outcomes(output_dir, since=since)
        finished = sum(1 for target in planned if target in done_since)
        print()
        print(c(C.CYAN, f"  Tab run: {finished}/{len(planned)} target(s) have an outcome "
                        f"since the tabs launched ({since:%Y-%m-%d %H:%M:%S})."))

    unaccounted_path = os.path.join(output_dir, "unaccounted.txt")
    if os.path.exists(unaccounted_path):
        with open(unaccounted_path, encoding="utf-8") as f:
            unaccounted = [line.strip() for line in f if line.strip()]
        if unaccounted:
            print()
            print(c(C.RED + C.BOLD, f"  [!] {len(unaccounted)} target(s) listed in {unaccounted_path}"))

    reports = find_reports(output_dir)
    problems = [(path, get_file_status(path)) for path in reports]
    problems = [(path, status) for path, status in problems if status not in {"COMPLETE", "DOWN"}]
    print()
    print(c(C.BOLD, f"  Reports: {len(reports)} file(s), {len(problems)} not complete"))
    for path, status in problems:
        print(c(C.YELLOW, f"    {status:<11} {os.path.basename(path)}"))

    hosts = collect_open_ports(output_dir)
    services = Counter(f"{port}/{service}" for ports in hosts.values()
                       for port, service in ports.items())
    print()
    print(c(C.BOLD, f"  Open ports: {sum(services.values())} across "
                    f"{sum(1 for ports in hosts.values() if ports)} host(s)"))
    for service, count in services.most_common(10):
        print(c(C.GREEN, f"    {service:<28}") + c(C.DIM, f"{count} host(s)"))
    print()
    return 0


def diff_open_ports(old_hosts, new_hosts):
    """Compare two {host: {port: service}} maps.

    Returns {"opened": {host: [port/service]}, "closed": {...},
    "new_hosts": [...], "missing_hosts": [...]}. Hosts are only compared when
    both runs saw them up; otherwise they are listed as new or missing.
    The legacy `closed` key means no longer observed open, not tested closed.
    These maps do not establish comparable scan coverage or remediation.
    """
    opened, closed = {}, {}
    for host in sorted(set(old_hosts) & set(new_hosts)):
        old_ports, new_ports = old_hosts[host], new_hosts[host]
        added = sorted(set(new_ports) - set(old_ports))
        removed = sorted(set(old_ports) - set(new_ports))
        if added:
            opened[host] = [f"{port}/{new_ports[port]}" for port in added]
        if removed:
            closed[host] = [f"{port}/{old_ports[port]}" for port in removed]
    return {
        "opened": opened,
        "closed": closed,
        "new_hosts": sorted(set(new_hosts) - set(old_hosts)),
        "missing_hosts": sorted(set(old_hosts) - set(new_hosts)),
    }


def print_diff(old_dir, new_dir):
    """Print and save the open-port difference between two output folders."""
    for directory in (old_dir, new_dir):
        if not os.path.isdir(directory):
            print(c(C.RED + C.BOLD, f"  [!] Output folder not found: {directory}"))
            return 1
    old_hosts, new_hosts = collect_open_ports(old_dir), collect_open_ports(new_dir)
    diff = diff_open_ports(old_hosts, new_hosts)

    print(c(C.CYAN + C.BOLD, f"  DIFF — {old_dir}  →  {new_dir}"))
    print(c(C.DIM, f"  {len(old_hosts)} host(s) up before, {len(new_hosts)} host(s) up now"))
    print(c(C.YELLOW, "  Coverage equivalence not verified. Missing observations do not prove closure or remediation."))
    sep()
    if not any(diff.values()):
        print(c(C.GREEN, "  [+] No differences in open ports."))
    for host, ports in diff["opened"].items():
        print(c(C.RED + C.BOLD, f"  + {host:<18}") + c(C.RED, "  newly open: " + "  ".join(ports)))
    for host, ports in diff["closed"].items():
        print(c(C.YELLOW + C.BOLD, f"  ? {host:<18}") + c(C.YELLOW, "  no longer observed open: " + "  ".join(ports)))
    for host in diff["new_hosts"]:
        ports = "  ".join(f"{p}/{s}" for p, s in sorted(new_hosts[host].items())) or "no open ports"
        print(c(C.YELLOW + C.BOLD, f"  * {host:<18}") + c(C.YELLOW, f"  new host: {ports}"))
    for host in diff["missing_hosts"]:
        print(c(C.DIM, f"  ? {host:<18}  not seen up in the new run (down, filtered, or not scanned)"))

    diff_path = os.path.join(new_dir, "scan-diff.json")
    with open(diff_path, "w", encoding="utf-8") as f:
        json.dump({"old": os.path.abspath(old_dir), "new": os.path.abspath(new_dir),
                   "coverage_comparability": "Not verified",
                   "closed_interpretation": "No longer observed open; closure and remediation not established",
                   "generated": datetime.now().strftime(LOG_TIME_FORMAT), **diff}, f, indent=2)
    print()
    print(c(C.CYAN, f"  [i] Saved: {diff_path}\n"))
    return 0


def review_run_history(directory):
    path = Path(directory).resolve() / ".scanrunner" / "scanrunner.sqlite3"
    if not path.is_file():
        raise ValueError("No durable run database found in this directory")
    database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    database.row_factory = sqlite3.Row
    try:
        runs = [dict(row) for row in database.execute("SELECT * FROM runs ORDER BY started")]
        jobs = [dict(row) for row in database.execute("SELECT * FROM jobs ORDER BY started")]
    finally:
        database.close()
    verifier = object.__new__(RunStore)
    verifier.directory = str(path.parent.parent)
    for job in jobs:
        job["evidence_integrity"] = "Verified" if verifier.verify_job(job) else "Missing, corrupt, or unfinished"
        job.pop("manifest", None)
    return {"runs": runs, "jobs": jobs}


def handle_review_commands():
    """Run --status / --diff, which review output folders and never scan."""
    arguments = [arg for arg in sys.argv[1:] if arg != "--no-color"]
    if arguments and arguments[0] in {"--history", "--verify-evidence"}:
        values = [value for value in arguments[1:] if value != "--json"]
        if len(values) > 1:
            raise ValueError("usage: scanrunner --history/--verify-evidence [DIR] [--json]")
        result = review_run_history(values[0] if values else "results")
        print(json.dumps(result, indent=2))
        invalid = any(job["evidence_integrity"] != "Verified" for job in result["jobs"])
        sys.exit(1 if arguments[0] == "--verify-evidence" and invalid else 0)
    if not arguments or arguments[0] not in {"--status", "--diff"}:
        return
    global COLORS_ENABLED
    COLORS_ENABLED = "--no-color" not in sys.argv[1:]
    command, rest = arguments[0], arguments[1:]
    if command == "--status":
        if len(rest) > 1:
            print("scanrunner: error: usage: scanrunner --status [DIR]", file=sys.stderr)
            sys.exit(2)
        sys.exit(print_status(rest[0] if rest else "results"))
    if len(rest) != 2:
        print("scanrunner: error: usage: scanrunner --diff OLD_DIR NEW_DIR", file=sys.stderr)
        sys.exit(2)
    sys.exit(print_diff(rest[0], rest[1]))


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def preview_scan(args, targets, scope, exclusions):
    """Produce a local-only preview. DNS-dependent destinations stay unresolved."""
    commands = []
    if not targets:
        raise ValueError("Target file contains no usable targets")
    if not scope and scope is not None:
        raise ValueError("Authorized scope is empty")
    for target in targets:
        if not ScopeGuard._valid_entry(target):
            raise ValueError(f"Invalid target: {target}")
        literal = _is_ip_literal(target) or "/" in target or parse_last_octet_range(target)
        if literal:
            ScopeGuard([target], scope, exclusions, resolver=lambda *a, **k: ([], "Requires DNS validation"))
        if args.nxc:
            command = ["nxc", args.nxc, target, *args.nmap_extra]
            argv = redact_command(command)
        else:
            report = os.path.join(args.output, f"{sanitize_filename(target)}.txt")
            argv = _build_nmap_command(target, report, args.nmap_extra)
        commands.append({"target": target, "destinations": [target] if literal else [],
                         "scope_decision": "Validated locally" if literal else "Requires DNS validation before execution",
                         "argv": argv})
    preview = {"tool": "NetExec" if args.nxc else "Nmap", "profile": args.profile or "custom",
               "impact": "credentialed" if args.allow_intrusive else "potentially noisy",
               "required_privileges": "Administrator/root for raw-packet and OS detection modes" if
                   any(flag in args.nmap_extra for flag in ("-sS", "-sU", "-O")) else "Depends on scanner mode",
               "side_effects": "Execution sends network probes and writes raw evidence and reports",
               "output_directory": os.path.abspath(args.output), "scope": scope if scope is not None else targets,
               "exclusions": exclusions, "commands": commands,
               "dns": "Deferred until execution", "authorization": args.authorization_note or "Explicit target selection"}
    preview["traffic_limits"] = {"aggregate_nmap_pps": args.scan_rate,
                                 "global_workers": args.global_concurrency, "per_subnet_workers": args.subnet_concurrency}
    print(json.dumps(preview, indent=2))


def bounded_futures(executor, function, targets, limit):
    pending = {}
    iterator = iter(targets)
    for _ in range(limit):
        target = next(iterator, None)
        if target is not None:
            pending[executor.submit(function, target)] = target
    while pending:
        ready, _ = wait(pending, return_when=FIRST_COMPLETED)
        for future in ready:
            yield future, pending.pop(future)
            target = next(iterator, None)
            if target is not None:
                pending[executor.submit(function, target)] = target


def main():
    global COLORS_ENABLED, ACTIVE_SCOPE, ACTIVE_STORE, ACTIVE_CONFIG
    _save_terminal()
    handle_topic_help()
    handle_review_commands()
    args = parse_args()
    COLORS_ENABLED = not args.no_color
    ACTIVE_SCOPE = None
    ACTIVE_STORE = None
    ACTIVE_CONFIG = {}
    if args.split is None and args.split_size is None:
        requested = [normalize_target(args.ip)] if args.ip else load_targets(args.file)
        if args.nxc and args.nxc not in {"smb", "rdp", "ldap", "winrm", "ssh", "ftp", "mssql", "wmi", "vnc", "nfs"}:
            raise ValueError("Unsupported NetExec protocol")
        explicit_scope = load_scope(args.scope_file)
        exclusions = list(args.exclude)
        if args.exclude_file:
            exclusions.extend(load_targets(args.exclude_file))
        # Exclusions are enforced by ScopeGuard, including CIDR overlap. Remove
        # duplicate scanner exclusion flags so mutable files cannot change scope.
        if args.exclude or args.exclude_file:
            extras = list(args.nmap_extra)
            if args.exclude_file:
                extras = extras[:-2]
            if args.exclude:
                extras = extras[:-2]
            args.nmap_extra = extras
        validate_scan_options(args.nmap_extra, bool(args.nxc), args.allow_intrusive)
        if not args.nxc:
            ceiling = max(1, args.scan_rate // args.global_concurrency)
            for index, option in enumerate(args.nmap_extra):
                if option.split("=", 1)[0] in {"--min-rate", "--max-rate"}:
                    value = option.split("=", 1)[1] if "=" in option else args.nmap_extra[index + 1]
                    if not 0 < float(value) <= ceiling:
                        raise ValueError(f"Per-process rate must be between 0 and {ceiling} PPS")
            if not has_nmap_option(args.nmap_extra, "--max-rate"):
                args.nmap_extra.extend(["--max-rate", str(ceiling)])
        if "null-auth" in args.nxc_queries or "all" in args.nxc_queries:
            if not args.allow_intrusive:
                raise ValueError("Anonymous authentication requires explicit authorization and --allow-intrusive")
        if args.dry_run:
            preview_scan(args, requested, explicit_scope, exclusions)
            return
        try:
            ACTIVE_SCOPE = ScopeGuard(requested, explicit_scope, exclusions)
        except ValueError as error:
            print(f"scanrunner: Refusing targets outside --scope-file or invalid authorization: {error}", file=sys.stderr)
            raise SystemExit(1)
        binary = check_nxc_installed() if args.nxc else shutil.which("nmap")
        if binary is None:
            check_nmap_installed()
        version_result = subprocess.run([binary, "--version"], capture_output=True, timeout=10, check=False)
        version_text = (version_result.stdout + version_result.stderr).decode("utf-8", errors="replace").strip()
        if version_result.returncode != 0 or not version_text:
            raise ValueError("Cannot determine scanner version for a reproducible run")
        ACTIVE_CONFIG = {"tool": "nxc" if args.nxc else "nmap", "tool_version": version_text,
                         "binary": os.path.abspath(binary), "binary_sha256": file_sha256(binary),
                         "scope": ACTIVE_SCOPE.scope, "dns_answers": ACTIVE_SCOPE.answers,
                         "exclusions": exclusions, "profile": args.profile or "custom", "profile_version": 1,
                         "options": args.nmap_extra, "timeout": args.process_timeout,
                         "engagement": args.engagement, "skip_ping": args.skip_ping,
                         "nxc_queries": args.nxc_queries, "protocol": args.nxc,
                         "allow_intrusive": args.allow_intrusive, "authorization_note": args.authorization_note}
        ACTIVE_CONFIG.update(global_workers=args.global_concurrency, subnet_workers=args.subnet_concurrency,
                             scan_rate=args.scan_rate, parallel=args.parallel,
                             targets=requested,
                             skip_no_ping=args.skip_no_ping, retries=args.retries,
                             scope_version=hashlib.sha256(json.dumps(sorted(ACTIVE_SCOPE.scope)).encode()).hexdigest())
        ACTIVE_STORE = RunStore(args.output, ACTIVE_CONFIG)
        CANCEL_EVENT.clear()
        signal.signal(signal.SIGINT, request_cancel)
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
    # Outcomes logged from here on belong to this run; the summary reconciles
    # against these only, so leftovers from an earlier run can't hide a target.
    run_started = run_start_time()

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
    if not ips:
        print(c(C.RED + C.BOLD, "  [!] Target file contains no usable targets."))
        sys.exit(1)

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

    def report_path(target):
        return os.path.join(output_dir, f"{sanitize_filename(target)}.txt")

    def write_reports():
        write_inventory(output_dir, ips, metadata, args.html_report)

    def finish():
        write_reports()
        print_summary(ips, completed_file, skipped_file, rescanned_file,
                      not_ping_file, failed_file, output_dir, since=run_started)
        ACTIVE_STORE.end("Finished; review per-job outcomes and coverage")

    # ── Resume — single prompt ────────────────────────────────────────────────
    completed_ips = set()
    if os.path.exists(completed_file) or args.resume:
        all_done = previously_completed(ips, output_dir, completed_file)
        if all_done:
            print(c(C.BLUE + C.BOLD, f"  Found {len(all_done)} previously completed IP(s)."))
            if args.resume:
                ch = "r"
            elif args.yes:
                ch = "f"
            else:
                ch = safe_input(
                    c(C.CYAN, "  [r] Resume (skip completed)  [f] Fresh (review all)  -> ")
                ).lower()
            if ch == "r":
                completed_ips = all_done
                # Log each one for this run: all_done includes hosts detected
                # purely from their report files, which may never have been
                # logged, and the end-of-run reconciliation only counts
                # outcomes recorded during this run.
                for ip in ips:
                    if ip in completed_ips:
                        log_to_file(completed_file, ip)
                print(c(C.GREEN,
                        f"  [+] Resuming — {len(completed_ips)} IP(s) will be skipped.\n"))
            else:
                print(c(C.YELLOW, "  [+] Fresh run — all IPs will be reviewed.\n"))

    pending_ips   = [ip for ip in ips if ip not in completed_ips]
    total_pending = len(pending_ips)

    if total_pending == 0:
        print(c(C.GREEN, "  [+] All IPs already completed. Nothing to do."))
        finish()
        return

    if args.tabs is not None:
        if args.tabs > total_pending:
            print(c(C.RED,
                    f"  [!] --tabs {args.tabs} exceeds the {total_pending} pending target(s) "
                    f"— enter a number from 2 to {total_pending}."))
            sys.exit(1)
        _launch_tabs(args, pending_ips, output_dir, args.tabs)
        ACTIVE_STORE.end("Delegated; review child run outcomes")
        return

    if offer_terminal_tabs(args, pending_ips, output_dir):
        ACTIVE_STORE.end("Delegated; review child run outcomes")
        return

    print(c(C.CYAN + C.BOLD, f"  [*] {total_pending} IP(s) queued.\n"))

    nmap_uses_pn = has_nmap_option(args.nmap_extra, "-Pn")
    if nmap_uses_pn:
        print(c(C.YELLOW,
                "  [*] -Pn detected: wrapper ping checks are disabled.\n"))

    def needs_wrapper_ping(target):
        return not nmap_uses_pn and not args.skip_ping and not is_network_target(target)

    def print_fatal_stop():
        print(c(C.RED + C.BOLD,
                "\n  [x] Stopping: Nmap refused to run with these arguments/privileges, so every "
                "remaining host would fail the same way."))
        print(c(C.RED, "      Fix the Nmap arguments (or run with the needed privileges) and "
                       "re-run with --resume. Unscanned targets are listed as unaccounted."))

    if args.parallel > 1:
        # Same decision as a serial --yes run: a complete report is skipped
        # (and logged, so reconciliation accounts for it); anything else is scanned.
        parallel_targets = []
        for ip in pending_ips:
            if ACTIVE_STORE.completed(ip, has_nmap_option(args.nmap_extra, "-Pn")):
                log_to_file(skipped_file, ip)
                print(c(C.YELLOW, f"  [~] Skipped {ip} (complete report already exists)"))
            else:
                parallel_targets.append(ip)
        print(c(C.CYAN, f"  [*] Running {len(parallel_targets)} scan(s) with {args.parallel} workers.\n"))

        fatal_seen = threading.Event()

        def scan_one(target):
            # Once one scan hits a fatal Nmap error, queued scans are not started.
            # They get no log entry, so the summary reports them as unaccounted.
            if fatal_seen.is_set() or CANCEL_EVENT.is_set():
                return "CANCELLED", 0, ""
            if needs_wrapper_ping(target) and not ping_host(target):
                return "NO_PING", 0, ""
            status, attempts, detail = run_nmap_quiet(
                target, report_path(target), args.nmap_extra, nmap_uses_pn, args.retries)
            if status == "FATAL":
                fatal_seen.set()
            return status, attempts, detail

        fatal_detail = None
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            for future, ip in bounded_futures(executor, scan_one, parallel_targets, args.parallel):
                status, attempts, detail = future.result()
                if attempts > 1:
                    log_to_file(retry_file, ip)
                if status == "COMPLETE":
                    log_to_file(completed_file, ip)
                    open_count = len(parse_open_ports(report_path(ip)))
                    print(c(C.GREEN, f"  [+] Completed {ip} ({attempts} attempt(s), "
                                     f"{open_count} open port(s))"))
                elif status == "DOWN":
                    log_to_file(not_ping_file, ip)
                    print(c(C.ORANGE, f"  [-] {ip}: Nmap reports the host down (0 hosts up)"))
                elif status == "NO_PING":
                    log_to_file(not_ping_file, ip)
                    print(c(C.ORANGE, f"  [-] {ip} did not respond to ping; logged as no-ping"))
                elif status == "FAILED":
                    log_to_file(failed_file, ip)
                    print(c(C.RED, f"  [x] Failed {ip} after {attempts} attempt(s): {detail}"))
                elif status == "FATAL":
                    log_to_file(failed_file, ip)
                    fatal_detail = fatal_detail or detail
        if fatal_detail:
            print(c(C.RED + C.BOLD, "\n  [x] Nmap stopped with a fatal error:"))
            for line in fatal_detail.splitlines():
                print(c(C.RED, f"      {line}"))
            print_fatal_stop()
        finish()
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

            output_file = report_path(ip)

            # ── Existing scan file ───────────────────────────────────────────
            action = None   # "scan" | "skip"

            if os.path.exists(output_file):
                display_existing_scan(output_file)
                while True:
                    if args.yes:
                        ch = "s" if ACTIVE_STORE.completed(ip, has_nmap_option(args.nmap_extra, "-Pn")) else "r"
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
                        log_to_file(skipped_file, ip)
                        print(c(C.YELLOW, f"  [~] Acknowledged {ip}; completion requires validated scanner evidence."))
                        action = "skip"
                        break
                    elif ch == "v":
                        view_full_report(output_file)
                    elif ch == "q":
                        print(c(C.RED + C.BOLD, "\n  Quitting."))
                        restore_terminal()
                        finish()
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

            if needs_wrapper_ping(ip) and not ping_host(ip):
                print(c(C.ORANGE + C.BOLD, f"  [-] {ip} did not respond to ping."))

                # -ok / --skip-no-ping is intentionally opt-in. It changes only
                # the wrapper ping-failure decision: no prompt, no -Pn fallback.
                # --yes makes the same decision, since nobody can answer the prompt.
                if args.skip_no_ping or args.yes:
                    log_to_file(not_ping_file, ip)
                    reason = "-ok enabled" if args.skip_no_ping else "--yes"
                    print(c(C.ORANGE, f"  [~] {reason}: logged {ip} as no-ping and skipped."))
                    done_count += 1
                    continue

                ping_choice = ""
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
                if ping_choice == "n":
                    done_count += 1
                    continue
            elif needs_wrapper_ping(ip):
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
            failure_reason = ""
            while True:
                result = run_nmap_scan(ip, output_file, args.nmap_extra, use_pn)
                if result is True:
                    # Wait up to 2s for nmap to flush the file
                    for _ in range(4):
                        if os.path.exists(output_file):
                            break
                        time.sleep(0.5)
                    report_status = get_file_status(output_file)
                    if report_status not in {"COMPLETE", "DOWN"}:
                        result = False
                        failure_reason = REPORT_STATUS_PROBLEMS[report_status]
                elif result is False:
                    failure_reason = "Nmap exited with an error"
                if result is not False or attempt >= args.retries:
                    break
                attempt += 1
                log_to_file(retry_file, ip)
                print(c(C.YELLOW, f"  [~] Retrying {ip} ({attempt}/{args.retries}): {failure_reason}"))
            elapsed = round(time.time() - start, 2)

            if result == "SKIPPED":
                log_to_file(skipped_file, ip)

            elif result == "FATAL":
                log_to_file(failed_file, ip)
                print_fatal_stop()
                break

            elif result is True:
                print(c(C.GREEN + C.BOLD, f"\n  [+] Nmap finished {ip} in {elapsed}s"))
                if report_status == "DOWN":
                    log_to_file(not_ping_file, ip)
                    print(c(C.ORANGE, f"  [-] Nmap reports {ip} down (0 hosts up); "
                                      "logged as down/no-ping."))
                    if not use_pn:
                        print(c(C.DIM, "      Add -Pn if the host blocks Nmap's discovery probes."))
                else:
                    log_to_file(completed_file, ip)
                    print(c(C.GREEN, f"  [+] Saved report for {ip}"))
                    print_open_ports_oneliner(ip, output_file)
            else:
                print(c(C.RED + C.BOLD, f"\n  [x] Scan failed for {ip}  ({elapsed}s): {failure_reason}"))
                log_to_file(failed_file, ip)

            done_count += 1
            print()

    except KeyboardInterrupt:
        print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted. Saving progress..."))
        restore_terminal()

    # Final progress bar — 100% when every target was processed
    progress_bar(done_count, total_pending)
    finish()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        if ACTIVE_STORE is not None:
            ACTIVE_STORE.end("Failed; review preserved partial evidence")
        print(f"scanrunner: error: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        CANCEL_EVENT.set()
        if ACTIVE_STORE is not None:
            ACTIVE_STORE.end("Interrupted")
        restore_terminal()
        sys.exit(130)

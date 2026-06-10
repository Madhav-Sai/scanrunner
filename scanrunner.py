#!/usr/bin/env python3
"""
scanrunner.py — Automated Nmap wrapper  by madhav
"""

import os
import sys
import re
import signal
import shlex
import shutil
import time
import tty
import termios
import select
import queue
import threading
import argparse
import subprocess
from datetime import datetime


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

def c(color, text):
    return f"{color}{text}{C.RESET}"

def sep(color=C.DIM, char="─", width=70):
    print(c(color, char * width))

def banner():
    art = r"""
  _   _ __  __    _    ____
 | \ | |  \/  |  / \  |  _ \
 |  \| | |\/| | / _ \ | |_) |
 | |\  | |  | |/ ___ \|  __/
 |_| \_|_|  |_/_/   \_\_|    SCANNER
                               by madhav
"""
    print(c(C.CYAN    + C.BOLD, art))
    print(c(C.DIM, "  Automated Nmap wrapper — resume • stream • skip • color\n"))


# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL SAFETY
# ═══════════════════════════════════════════════════════════════════════════════

_original_term_settings = None

def _save_terminal():
    global _original_term_settings
    if sys.stdin.isatty():
        try:
            _original_term_settings = termios.tcgetattr(sys.stdin.fileno())
        except Exception:
            pass

def restore_terminal():
    global _original_term_settings
    if _original_term_settings is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN,
                              _original_term_settings)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def log_to_file(filename, data):
    with open(filename, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {data}\n")

def count_unique_ips(path):
    if not os.path.exists(path):
        return 0
    seen = set()
    with open(path) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 2:
                seen.add(parts[-1].strip())
    return len(seen)

def sanitize_filename(ip):
    return ip.replace(":", "_").replace("/", "_")

def check_nmap_installed():
    if shutil.which("nmap") is None:
        print(c(C.RED + C.BOLD, "\n  [!] nmap not found in PATH. Install nmap first."))
        sys.exit(1)

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


# ═══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        prog="scanrunner.py",
        description="Automated Nmap wrapper by madhav",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 scanrunner.py -f alive.txt -o results -sV -A -vv\n"
            "  python3 scanrunner.py -i 10.0.0.0/24 -o scans -sS -T4 -p-\n"
            "  python3 scanrunner.py -i 192.168.1.5 -o out --script vuln -sV\n"
            "  sudo python3 scanrunner.py -f ips.txt -o results -sS -O -T4\n"
        )
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--file",   metavar="FILE",
                     help="Text file with one IP/host per line")
    src.add_argument("-i", "--ip",     metavar="TARGET",
                     help="Single IP or CIDR subnet  (e.g. 10.0.0.0/24)")
    parser.add_argument("-o", "--output", metavar="DIR", default="results",
                        help="Output folder  (default: results)")

    args, nmap_extra = parser.parse_known_args()
    args.nmap_args   = " ".join(nmap_extra)
    return args


# ═══════════════════════════════════════════════════════════════════════════════
#  PING
# ═══════════════════════════════════════════════════════════════════════════════

def ping_host(ip):
    r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

def _build_nmap_command(target, output_file, nmap_args, use_pn=False):
    cmd = ["nmap"]
    if use_pn:
        cmd.append("-Pn")
    if nmap_args.strip():
        try:
            cmd.extend(shlex.split(nmap_args))
        except ValueError as e:
            print(c(C.RED, f"  [!] Invalid nmap arguments: {e}"))
            sys.exit(1)
    # -oN BEFORE '--'; '--' immediately before target so target never
    # gets misread as a flag even if it starts with '-'
    cmd.extend(["-oN", output_file, "--", target])
    return cmd


# ═══════════════════════════════════════════════════════════════════════════════
#  NMAP — RUN WITH LIVE OUTPUT + KEY CONTROLS
#
#  Space   → SIGWINCH to nmap process  (triggers nmap's built-in status line)
#            This is the only reliable method — writing to stdin does NOT work
#            because nmap detects stdin is a pipe and disables that feature.
#
#  Ctrl+X  → skip_flag   — terminate nmap, move to next host
#  Ctrl+C  → abort_flag  — terminate nmap, restore terminal, print summary, exit
#
#  stdout is read in a SEPARATE THREAD and put into a queue so that the
#  key-watcher is always responsive — even when nmap produces no output
#  (e.g. waiting on filtered ports).  Previously a blocking for-loop meant
#  Ctrl+X/Ctrl+C were only checked between lines arriving.
# ═══════════════════════════════════════════════════════════════════════════════

def run_nmap_scan(target, output_file, nmap_args, use_pn=False):
    cmd = _build_nmap_command(target, output_file, nmap_args, use_pn)

    print(c(C.DIM, "  Command : " + " ".join(cmd)))
    sep(C.DIM, "─", 70)

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,   # explicitly no stdin pipe — lets nmap
                                        # detect a real tty for its own status
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
    except FileNotFoundError:
        print(c(C.RED, "  [!] nmap binary not found."))
        return False

    skip_flag  = threading.Event()
    abort_flag = threading.Event()
    status_requested = threading.Event()
    _proc_done = threading.Event()

    line_queue   = queue.Queue()
    stdin_is_tty = sys.stdin.isatty()

    # ── stdout reader thread ──────────────────────────────────────────────────
    # Reads nmap output in background and feeds into queue.
    # Sentinel None signals end of output.
    def _read_stdout():
        try:
            for raw in proc.stdout:
                line_queue.put(raw)
        except Exception:
            pass
        finally:
            line_queue.put(None)   # sentinel

    reader = threading.Thread(target=_read_stdout, daemon=True)
    reader.start()

    # ── key watcher thread ────────────────────────────────────────────────────
    def _watch_keys():
        if not stdin_is_tty:
            return
        fd = sys.stdin.fileno()
        try:
            tty.setraw(fd)
            while not skip_flag.is_set() and not _proc_done.is_set() \
                    and not abort_flag.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch == "\x18":           # Ctrl+X — skip host
                        skip_flag.set()
                        break
                    elif ch == "\x03":         # Ctrl+C — full abort
                        abort_flag.set()
                        break
                    elif ch == " ":            # Space  — show scan status
                        status_requested.set()
        except Exception:
            pass
        finally:
            restore_terminal()

    watcher    = threading.Thread(target=_watch_keys, daemon=True)
    scan_start = time.time()
    watcher.start()
    last_status_update = 0

    # ── terminal width — read once ────────────────────────────────────────────
    try:
        term_width = shutil.get_terminal_size(fallback=(120, 24)).columns
    except Exception:
        term_width = 120
    PREFIX_LEN = 10   # "  [MM:SS] " without ANSI codes

    # ── main output loop — non-blocking via queue ─────────────────────────────
    while True:
        if skip_flag.is_set() or abort_flag.is_set():
            break

        if status_requested.is_set():
            elapsed = int(time.time() - scan_start)
            mins, secs = divmod(elapsed, 60)
            print()
            print(c(C.CYAN + C.BOLD,
                    f"  [STATUS] Target={target} | Elapsed={mins:02d}:{secs:02d} | PID={proc.pid}"))
            status_requested.clear()


        try:
            raw_line = line_queue.get(timeout=0.2)
        except queue.Empty:
            # No output yet — check if process ended
            if proc.poll() is not None and line_queue.empty():
                break
            continue

        if raw_line is None:           # sentinel — stdout closed
            break

        line    = raw_line.rstrip()
        elapsed = int(time.time() - scan_start)
        mins, secs = divmod(elapsed, 60)
        ts      = c(C.DIM, f"  [{mins:02d}:{secs:02d}] ")

        # Truncate to fit terminal cleanly
        max_content = term_width - PREFIX_LEN - 1
        if len(line) > max_content:
            line = line[:max_content - 3] + "..."

        if not line.strip():
            continue   # suppress blank lines
        elif any(x in line for x in ["open", "Discovered"]):
            print(ts + c(C.GREEN, line))
        elif any(x in line for x in ["closed", "filtered"]):
            print(ts + c(C.DIM, line))
        elif any(x in line for x in ["WARNING", "WARN", "failed", "Failed"]):
            print(ts + c(C.YELLOW, line))
        elif line.startswith("Nmap scan report") or line.startswith("Host is"):
            print(ts + c(C.CYAN + C.BOLD, line))
        elif line.startswith("Nmap done"):
            print(ts + c(C.GREEN + C.BOLD, line))
        elif "%" in line and "remaining" in line:
            # nmap status line triggered by Space/SIGWINCH
            print(ts + c(C.MAGENTA + C.BOLD, line))
        else:
            print(ts + c(C.WHITE, line))

    # ── cleanup ───────────────────────────────────────────────────────────────
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
        raise KeyboardInterrupt   # caught by main()'s try/except

    if skip_flag.is_set():
        sep(C.YELLOW, "─")
        print(c(C.YELLOW + C.BOLD, f"  [~] Skipped {target}."))
        return "SKIPPED"

    proc.wait()
    sep(C.DIM, "─")
    return proc.returncode == 0


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


# ═══════════════════════════════════════════════════════════════════════════════
#  SUMMARY BOX + OPEN PORTS TABLE
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file, output_dir):
    completed = count_unique_ips(completed_file)
    skipped   = count_unique_ips(skipped_file)
    rescanned = count_unique_ips(rescanned_file)
    no_ping   = count_unique_ips(not_ping_file)
    failed    = count_unique_ips(failed_file)

    print()
    print(c(C.BOLD, "  ╔══════════════════════════════╗"))
    print(c(C.BOLD, "  ║       SCAN SUMMARY           ║"))
    print(c(C.BOLD, "  ╠══════════════════════════════╣"))
    print(c(C.BOLD, "  ║  ") + c(C.GREEN  + C.BOLD, f"  Completed : {completed:<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.YELLOW + C.BOLD, f"  Skipped   : {skipped:<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.CYAN   + C.BOLD, f"  Rescanned : {rescanned:<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.ORANGE + C.BOLD, f"  No Ping   : {no_ping:<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.RED    + C.BOLD, f"  Failed    : {failed:<5}")    + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ╚══════════════════════════════╝"))

    # ── Open ports table across all completed hosts ───────────────────────────
    host_ports = {}
    if os.path.exists(completed_file):
        with open(completed_file) as f:
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
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    _save_terminal()
    banner()

    args = parse_args()
    check_nmap_installed()

    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    # ── Build target list ─────────────────────────────────────────────────────
    if args.ip:
        ips = [args.ip.strip()]
        print(c(C.CYAN, f"  Target   : {args.ip}"))
    else:
        if not os.path.exists(args.file):
            print(c(C.RED + C.BOLD, f"  [!] File not found: {args.file}"))
            sys.exit(1)
        raw = []
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip = strip_inline_comment(line)   # handle "10.0.0.1 # note"
                if ip:
                    raw.append(ip)
        seen: set = set()
        ips = []
        for ip in raw:
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        print(c(C.CYAN, f"  File     : {args.file}  ({len(ips)} unique targets)"))

    print(c(C.CYAN, f"  Output   : {output_dir}"))

    # ── --host-timeout warning ────────────────────────────────────────────────
    if args.nmap_args:
        print(c(C.CYAN, f"  Nmap args: {args.nmap_args}"))
        if "--host-timeout" not in args.nmap_args:
            print(c(C.YELLOW,
                    "  [!] No --host-timeout set. A hung host will block forever.\n"
                    "      Consider adding: --host-timeout 10m"))
    else:
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

    # ── Resume — single prompt ────────────────────────────────────────────────
    completed_ips = set()
    if os.path.exists(completed_file):
        with open(completed_file) as f:
            all_done = {line.split("|")[-1].strip() for line in f if line.strip()}
        if all_done:
            print(c(C.BLUE + C.BOLD, f"  Found {len(all_done)} previously completed IP(s)."))
            ch = safe_input(
                c(C.CYAN, "  [r] Resume (skip completed)  [f] Fresh (review all)  -> ")
            ).lower()
            if ch == "r":
                completed_ips = all_done
                print(c(C.GREEN,
                        f"  [+] Resuming — {len(completed_ips)} IP(s) will be skipped.\n"))
            else:
                print(c(C.YELLOW, "  [+] Fresh run — all IPs will be reviewed.\n"))

    pending_ips   = [ip for ip in ips if ip not in completed_ips]
    total_pending = len(pending_ips)

    if total_pending == 0:
        print(c(C.GREEN, "  [+] All IPs already completed. Nothing to do."))
        print_summary(completed_file, skipped_file, rescanned_file,
                      not_ping_file, failed_file, output_dir)
        return

    print(c(C.CYAN + C.BOLD, f"  [*] {total_pending} IP(s) queued.\n"))

    # ── Scan loop ─────────────────────────────────────────────────────────────
    done_count = 0   # IPs fully processed before current — used for progress bar

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

                def _show_menu():
                    print(
                        c(C.CYAN,   "\n  [s] Skip      ") +
                        c(C.YELLOW, "[r] Rescan     ") +
                        c(C.GREEN,  "[m] Mark done  ") +
                        c(C.BLUE,   "[v] View full  ") +
                        c(C.RED,    "[q] Quit")
                    )

                _show_menu()
                while True:
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
                        _show_menu()
                    elif ch == "q":
                        print(c(C.RED + C.BOLD, "\n  Quitting."))
                        restore_terminal()
                        print_summary(completed_file, skipped_file, rescanned_file,
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
            print(c(C.DIM, f"\n  Pinging {ip} ..."))
            use_pn = False

            if not ping_host(ip):
                print(c(C.ORANGE + C.BOLD, f"  [-] {ip} did not respond to ping."))
                while True:
                    ping_choice = safe_input(
                        c(C.YELLOW, "  Run nmap with -Pn anyway? [y/n]: ")
                    ).lower()
                    if ping_choice == "y":
                        use_pn = True
                        break
                    elif ping_choice == "n":
                        log_to_file(not_ping_file, ip)
                        print(c(C.ORANGE, f"  Logged {ip} as no-ping. Skipping."))
                        break
                    else:
                        print(c(C.RED, "  [!] Enter y or n."))
                if ping_choice == "n":
                    done_count += 1
                    continue
            else:
                print(c(C.GREEN, f"  [+] {ip} is alive."))

            # ── Run scan ─────────────────────────────────────────────────────
            print(c(C.MAGENTA + C.BOLD, f"\n  [>] Scanning {ip}"))
            if sys.stdin.isatty():
                print(c(C.DIM,
                        "      Space = status   "
                        "Ctrl+X = skip host   "
                        "Ctrl+C = exit\n"))

            start  = time.time()
            result = run_nmap_scan(ip, output_file, args.nmap_args, use_pn)
            elapsed = round(time.time() - start, 2)

            if result == "SKIPPED":
                log_to_file(skipped_file, ip)

            elif result is True:
                print(c(C.GREEN + C.BOLD, f"\n  [+] Completed {ip} in {elapsed}s"))
                log_to_file(completed_file, ip)
                # Wait up to 2s for nmap to flush the file
                for _ in range(4):
                    if os.path.exists(output_file):
                        break
                    time.sleep(0.5)
                if os.path.exists(output_file):
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
    print_summary(completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file, output_dir)


if __name__ == "__main__":
    main()

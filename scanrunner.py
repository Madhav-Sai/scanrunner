#!/usr/bin/env python3
"""
nmapscan_full_fixed.py — Automated Nmap wrapper
  • Resume sessions   • Skip-while-scanning (Ctrl+X)
  • Color output      • Full audit log
"""

import os
import sys
import shlex
import shutil
import time
import tty
import termios
import threading
import subprocess
from datetime import datetime


# ═══════════════════════════════════════════════════════════════════════════════
#  COLORS  (pure ANSI — zero dependencies)
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

def banner():
    art = r"""
  _   _ __  __    _    ____
 | \ | |  \/  |  / \  |  _ \
 |  \| | |\/| | / _ \ | |_) |
 | |\  | |  | |/ ___ \|  __/
 |_| \_|_|  |_/_/   \_\_|    SCANNER  by madhav
                                
"""
    print(c(C.CYAN + C.BOLD, art))
    print(c(C.MAGENTA + C.BOLD, name))
    print(c(C.DIM, "  Automated Nmap wrapper — resume • skip • color\n"))


# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL SAFETY
#  All raw-mode usage is funnelled through this module so we always
#  have ONE canonical "restore" path, no matter how the program exits.
# ═══════════════════════════════════════════════════════════════════════════════

_original_term_settings = None

def _save_terminal():
    """Save the current terminal settings (called once at startup)."""
    global _original_term_settings
    if sys.stdin.isatty():
        _original_term_settings = termios.tcgetattr(sys.stdin.fileno())

def restore_terminal():
    """Restore terminal to the state saved at startup. Safe to call multiple times."""
    global _original_term_settings
    if _original_term_settings is not None:
        try:
            termios.tcsetattr(
                sys.stdin.fileno(),
                termios.TCSADRAIN,
                _original_term_settings
            )
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def log_to_file(filename, data):
    with open(filename, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {data}\n")


def count_unique_ips(path):
    """Count unique IPs in a log file — ignores duplicate lines."""
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
    """Replace characters invalid in filenames (IPv6 colons, CIDR slashes)."""
    return ip.replace(":", "_").replace("/", "_")


def check_nmap_installed():
    if shutil.which("nmap") is None:
        print(c(C.RED + C.BOLD, "[!] 'nmap' not found in PATH. Install nmap first."))
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
#  PING
# ═══════════════════════════════════════════════════════════════════════════════

def ping_host(ip):
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


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
        print(c(C.DIM, "─" * 70))
        print(c(C.CYAN, f"  Last {lines} lines of existing scan"))
        print(c(C.DIM, "─" * 70))
        for line in content[-lines:]:
            print(c(C.DIM, line.rstrip()))
        print(c(C.DIM, "─" * 70))
    except Exception as e:
        print(c(C.RED, f"[!] Error reading file: {e}"))


def display_existing_scan(filepath):
    status = get_file_status(filepath)
    stat   = os.stat(filepath)
    modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    size_kb  = round(stat.st_size / 1024, 2)
    status_color = C.GREEN if status == "COMPLETE" else C.YELLOW

    print(c(C.BLUE + C.BOLD, "\n╔══ Existing Scan Found " + "═" * 46))
    print(c(C.BLUE + C.BOLD, "║"))
    print(c(C.BLUE + C.BOLD, "║  ") + f"Status   : {c(status_color + C.BOLD, status)}")
    print(c(C.BLUE + C.BOLD, "║  ") + f"Modified : {c(C.WHITE, modified)}")
    print(c(C.BLUE + C.BOLD, "║  ") + f"Size     : {c(C.WHITE, str(size_kb) + ' KB')}")
    print(c(C.BLUE + C.BOLD, "╚" + "═" * 68))
    show_last_lines(filepath)


def view_full_report(filepath):
    pager = "less" if shutil.which("less") else "cat"
    subprocess.run([pager, filepath])


# ═══════════════════════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ═══════════════════════════════════════════════════════════════════════════════

def progress_bar(current, total):
    percent  = (current / total) * 100
    filled   = int(40 * current / total)
    bar      = "█" * filled + "░" * (40 - filled)
    print()
    print(
        c(C.BOLD, f"  Progress  [{c(C.CYAN, bar)}{C.BOLD}]  ") +
        c(C.YELLOW + C.BOLD, f"{percent:.1f}%") +
        c(C.DIM, f"  ({current}/{total})  {total - current} remaining")
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE TIMER
# ═══════════════════════════════════════════════════════════════════════════════

class LiveTimer:
    """Prints a live elapsed-time ticker on a background thread."""

    def __init__(self):
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._start  = None

    def start(self):
        self._start = time.time()
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        sys.stdout.write("\r" + " " * 70 + "\r")
        sys.stdout.flush()

    def _run(self):
        while not self._stop.is_set():
            elapsed = int(time.time() - self._start)
            mins, secs = divmod(elapsed, 60)
            sys.stdout.write(
                "\r" + c(C.MAGENTA,
                    f"  ⏱  Scanning ...  {mins:02d}:{secs:02d}  "
                    f"(Ctrl+X to skip this host)")
            )
            sys.stdout.flush()
            time.sleep(1)


# ═══════════════════════════════════════════════════════════════════════════════
#  SKIP-WHILE-SCANNING
#
#  Design:
#   • nmap runs via Popen (non-blocking)
#   • _watch_for_skip() runs on a daemon thread in raw-terminal mode
#   • The main loop polls proc.poll() every 0.3 s
#   • When nmap finishes naturally, _proc_done is set so the watcher thread
#     unblocks and exits — terminal is restored immediately (BUG 2 fix)
#   • If stdin is not a TTY (piped/redirected), skip-watcher is disabled
#     gracefully instead of crashing (BUG 1 fix)
# ═══════════════════════════════════════════════════════════════════════════════

def run_nmap_scan(ip, output_file, custom_args, use_pn=False):
    cmd = _build_nmap_command(ip, output_file, custom_args, use_pn)
    print(c(C.DIM, "\n  Command: " + " ".join(cmd)) + "\n")

    try:
        proc = subprocess.Popen(cmd)
    except FileNotFoundError:
        print(c(C.RED, "[!] nmap binary not found — cannot scan."))
        return False

    skip_flag  = threading.Event()   # set by watcher when Ctrl+X pressed
    _proc_done = threading.Event()   # set by main loop when nmap exits

    # ── BUG 1 FIX: only enter raw mode if stdin is a real TTY ────────────────
    stdin_is_tty = sys.stdin.isatty()

    def _watch_for_skip():
        if not stdin_is_tty:
            return   # silently disabled — no TTY to read from

        fd = sys.stdin.fileno()
        try:
            tty.setraw(fd)
            while not skip_flag.is_set() and not _proc_done.is_set():
                # ── BUG 2 FIX: use select() with timeout so we don't block
                # forever on read(1) after nmap finishes ─────────────────────
                import select
                ready, _, _ = select.select([sys.stdin], [], [], 0.3)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch == "\x18":   # Ctrl+X
                        skip_flag.set()
                        break
        except Exception:
            pass
        finally:
            # Always restore terminal when this thread exits
            restore_terminal()

    watcher = threading.Thread(target=_watch_for_skip, daemon=True)
    timer   = LiveTimer()

    watcher.start()
    timer.start()

    # ── Main poll loop ────────────────────────────────────────────────────────
    while proc.poll() is None:
        if skip_flag.is_set():
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            _proc_done.set()
            timer.stop()
            restore_terminal()   # BUG 7 FIX: explicit restore before returning
            print(c(C.YELLOW + C.BOLD, f"\n  [~] Skipped {ip} by user request."))
            return "SKIPPED"
        time.sleep(0.3)

    # nmap finished naturally
    _proc_done.set()              # BUG 2 FIX: unblocks the watcher's select loop
    watcher.join(timeout=1)       # wait for watcher to restore terminal
    timer.stop()
    restore_terminal()            # guarantee restore even if watcher didn't run
    return proc.returncode == 0


def _build_nmap_command(ip, output_file, custom_args, use_pn=False):
    cmd = ["nmap"]
    if use_pn:
        cmd.append("-Pn")
    try:
        cmd.extend(shlex.split(custom_args))
    except ValueError as e:
        print(c(C.RED, f"[!] Invalid nmap arguments: {e}"))
        sys.exit(1)
    cmd.extend(["--", ip, "-oN", output_file])
    return cmd


# ═══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary(completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file):
    completed = count_unique_ips(completed_file)
    skipped   = count_unique_ips(skipped_file)
    rescanned = count_unique_ips(rescanned_file)
    no_ping   = count_unique_ips(not_ping_file)
    failed    = count_unique_ips(failed_file)

    print("\n")
    print(c(C.BOLD, "  ╔══════════════════════════════╗"))
    print(c(C.BOLD, "  ║       SCAN SUMMARY           ║"))
    print(c(C.BOLD, "  ╠══════════════════════════════╣"))
    print(c(C.BOLD, "  ║  ") + c(C.GREEN   + C.BOLD, f"✔  Completed : {completed:<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.YELLOW  + C.BOLD, f"~  Skipped   : {skipped:<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.CYAN    + C.BOLD, f"↺  Rescanned : {rescanned:<5}") + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.ORANGE  + C.BOLD, f"⊘  No Ping   : {no_ping:<5}")   + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ║  ") + c(C.RED     + C.BOLD, f"✘  Failed    : {failed:<5}")    + c(C.BOLD, "         ║"))
    print(c(C.BOLD, "  ╚══════════════════════════════╝"))
    print()
    print(c(C.GREEN + C.BOLD, "  [✔] All done!\n"))


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # Save terminal state at the very start so restore_terminal() always works
    _save_terminal()

    banner()

    if len(sys.argv) != 4:
        print(c(C.YELLOW, f"  Usage  : {sys.argv[0]} <alive.txt> <output_folder> '<nmap_args>'"))
        print(c(C.DIM,    f"  Example: {sys.argv[0]} alive.txt results '-sV -A -vv'"))
        sys.exit(1)

    alive_file  = sys.argv[1]
    output_dir  = sys.argv[2]
    custom_args = sys.argv[3]

    check_nmap_installed()

    if not os.path.exists(alive_file):
        print(c(C.RED + C.BOLD, f"[!] File not found: {alive_file}"))
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    completed_file = os.path.join(output_dir, "completed.txt")
    skipped_file   = os.path.join(output_dir, "skipped.txt")
    rescanned_file = os.path.join(output_dir, "rescanned.txt")
    not_ping_file  = os.path.join(output_dir, "not-pingip.txt")
    failed_file    = os.path.join(output_dir, "failed.txt")

    # ── Resume ───────────────────────────────────────────────────────────────
    completed_ips = set()
    if os.path.exists(completed_file):
        try:
            resume = input(c(C.CYAN, "  Resume previous session? [y/n]: ")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted. Exiting cleanly."))
            restore_terminal()
            sys.exit(0)

        if resume == "y":
            with open(completed_file) as f:
                completed_ips = {
                    line.split("|")[-1].strip()
                    for line in f if line.strip()
                }
            print(c(C.GREEN, f"  [+] Resuming — {len(completed_ips)} IP(s) already completed."))

    # ── Load & deduplicate ───────────────────────────────────────────────────
    with open(alive_file) as f:
        raw_ips = [line.strip() for line in f if line.strip()]

    seen_input: set = set()
    ips = []
    for ip in raw_ips:
        if ip not in seen_input:
            seen_input.add(ip)
            ips.append(ip)

    pending_ips   = [ip for ip in ips if ip not in completed_ips]
    total_pending = len(pending_ips)
    scanned_count = 0

    if total_pending == 0:
        print(c(C.GREEN, "  [+] All IPs already completed. Nothing to do."))
        print_summary(completed_file, skipped_file, rescanned_file,
                      not_ping_file, failed_file)
        return

    print(c(C.CYAN + C.BOLD, f"\n  [*] {total_pending} IP(s) queued for scanning.\n"))

    # ── Scan loop ─────────────────────────────────────────────────────────────
    try:
        for ip in pending_ips:
            scanned_count += 1
            progress_bar(scanned_count, total_pending)

            print(c(C.CYAN  + C.BOLD, f"\n  ┌─ Target {'─' * 41}"))
            print(c(C.WHITE + C.BOLD, f"  │  {ip}"))
            print(c(C.CYAN  + C.BOLD, f"  └{'─' * 49}"))

            output_file = os.path.join(output_dir, f"{sanitize_filename(ip)}.txt")

            # ── Existing scan file ───────────────────────────────────────────
            if os.path.exists(output_file):
                display_existing_scan(output_file)

                file_choice = None
                while True:
                    try:
                        file_choice = input(
                            c(C.CYAN,   "\n  [s] Skip  ") +
                            c(C.YELLOW, "[r] Rescan  ") +
                            c(C.BLUE,   "[v] View  ") +
                            c(C.RED,    "[q] Quit") +
                            c(C.BOLD,   " → ")
                        ).strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted. Exiting cleanly."))
                        restore_terminal()
                        sys.exit(0)

                    if file_choice == "s":
                        log_to_file(skipped_file, ip)
                        print(c(C.YELLOW, f"  [~] Skipped {ip}"))
                        break
                    elif file_choice == "r":
                        log_to_file(rescanned_file, ip)
                        print(c(C.CYAN, f"  [↺] Rescanning {ip}"))
                        break
                    elif file_choice == "v":
                        view_full_report(output_file)
                    elif file_choice == "q":
                        print(c(C.RED + C.BOLD, "\n  [!] Quitting."))
                        restore_terminal()   # BUG 7 FIX
                        sys.exit(0)
                    else:
                        print(c(C.RED, "  [!] Invalid option — s / r / v / q"))

                if file_choice == "s":
                    continue

            # ── Ping ─────────────────────────────────────────────────────────
            print(c(C.DIM, f"\n  [+] Pinging {ip} ..."))
            use_pn = False

            if not ping_host(ip):
                print(c(C.ORANGE + C.BOLD, f"  [-] {ip} did not respond to ping."))

                ping_choice = None
                while True:
                    try:
                        ping_choice = input(
                            c(C.YELLOW, "  Run Nmap with -Pn? [y/n]: ")
                        ).strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted. Exiting cleanly."))
                        restore_terminal()
                        sys.exit(0)

                    if ping_choice == "y":
                        use_pn = True
                        break
                    elif ping_choice == "n":
                        log_to_file(not_ping_file, ip)
                        print(c(C.ORANGE, f"  [⊘] {ip} logged as no-ping."))
                        break
                    else:
                        print(c(C.RED, "  [!] Please enter y or n."))

                if ping_choice == "n":
                    continue
            else:
                print(c(C.GREEN, f"  [+] {ip} is alive."))

            # ── Run scan ─────────────────────────────────────────────────────
            print(c(C.MAGENTA + C.BOLD, f"\n  [>] Starting scan on {ip}"))
            if sys.stdin.isatty():
                print(c(C.DIM, "  Tip: Press Ctrl+X at any time to skip this host.\n"))

            start  = time.time()
            result = run_nmap_scan(ip, output_file, custom_args, use_pn)
            elapsed = round(time.time() - start, 2)

            if result == "SKIPPED":
                log_to_file(skipped_file, ip)

            elif result is True:
                print(c(C.GREEN + C.BOLD, f"\n  [✔] Completed {ip} in {elapsed}s"))
                log_to_file(completed_file, ip)
                if not os.path.exists(output_file):
                    print(c(C.YELLOW, f"  [!] nmap exited OK but wrote no output file for {ip}"))
                    log_to_file(failed_file, ip)

            else:
                print(c(C.RED + C.BOLD, f"\n  [✘] Scan failed for {ip}  ({elapsed}s)"))
                log_to_file(failed_file, ip)

    # BUG 6 FIX: graceful Ctrl+C anywhere in the scan loop ───────────────────
    except KeyboardInterrupt:
        print(c(C.RED + C.BOLD, "\n\n  [!] Interrupted by user (Ctrl+C). Saving progress..."))
        restore_terminal()

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(completed_file, skipped_file, rescanned_file,
                  not_ping_file, failed_file)


if __name__ == "__main__":
    main()

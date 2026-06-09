╔══════════════════════════════════════════════════════════════════════════════╗
║                     NMAP AUTOMATION SCANNER — README                       ║
║                         badboy.py                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

  A fully interactive, color-coded Nmap wrapper for scanning large lists
  of IP addresses — with session resume, live skip (Ctrl+X), audit logs,
  and a clean summary at the end.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • Python 3.6+      (uses f-strings, threading, tty, termios, shlex)
  • nmap             must be installed and in PATH
  • Linux / macOS    (uses POSIX tty/termios for Ctrl+X detection)
  • Run as root      recommended — many nmap scan types require root (e.g. -sS)

  Install nmap:
    Debian/Ubuntu  →  sudo apt install nmap
    RHEL/CentOS    →  sudo yum install nmap
    macOS          →  brew install nmap


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  USAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  python3 badboy.py <alive.txt> <output_folder> '<nmap_args>'

  Arguments:
    alive.txt       Path to a plain-text file with one IP per line
    output_folder   Folder where scan results and logs will be saved
                    (created automatically if it doesn't exist)
    nmap_args       Any nmap flags, passed as a single quoted string

  Examples:
    python3 badboy.py alive.txt results '-sV -A -vv'
    python3 badboy.py targets.txt /opt/scans '-sS -p 1-65535 -T4'
    python3 badboy.py ips.txt out '--script vuln -sV'
    sudo python3 badboy.py alive.txt scans '-sS -O -sV -T4 -vv'


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INPUT FILE FORMAT  (alive.txt)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  One IP address per line. Blank lines and duplicates are ignored.

  Supported formats:
    192.168.1.1           IPv4 address
    10.0.0.0/24           CIDR range (passed directly to nmap)
    fe80::1               IPv6 address (filename sanitized automatically)
    scanme.nmap.org       Hostnames also work

  Example alive.txt:
    10.10.10.1
    10.10.10.5
    192.168.0.254
    172.16.0.1


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OUTPUT FILES  (saved in your output_folder)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  <ip>.txt          Raw nmap output for each scanned host
                    (IPv6 colons replaced with underscores in filename)

  completed.txt     Log of all successfully completed scans
                    Format: YYYY-MM-DD HH:MM:SS | <ip>

  skipped.txt       IPs skipped manually (via menu or Ctrl+X during scan)

  rescanned.txt     IPs that had an existing scan file and were rescanned

  not-pingip.txt    IPs that did not respond to ping AND user chose not
                    to use -Pn

  failed.txt        IPs where nmap exited with a non-zero return code,
                    or where nmap finished but wrote no output file


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FEATURES IN DETAIL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ① SESSION RESUME
  ─────────────────
  If a completed.txt already exists in the output folder, the tool asks
  if you want to resume. Choosing [y] loads all previously completed IPs
  and skips them in the current run. Choosing [n] starts fresh but does
  NOT delete the existing logs — old entries are preserved.

  ② EXISTING SCAN DETECTION
  ──────────────────────────
  Before scanning any IP, the tool checks if a <ip>.txt file already exists.
  If it does, it shows:
    • Status     — COMPLETE (if "Nmap done" found in file) or INCOMPLETE
    • Modified   — Last modified timestamp
    • Size       — File size in KB
    • Preview    — Last 15 lines of the scan output

  Then asks what to do:
    [s]  Skip      — move to next IP, log to skipped.txt
    [r]  Rescan    — overwrite the existing file, log to rescanned.txt
    [v]  View      — open full file in 'less' (falls back to 'cat')
    [q]  Quit      — exit immediately, progress is already saved in logs

  ③ PING CHECK
  ─────────────
  Before launching nmap, the tool pings the target once (-c 1 -W 1 timeout).
    • Host alive  → proceed directly to nmap scan
    • No response → asks: "Run Nmap with -Pn? [y/n]"
        [y] → adds -Pn flag to skip host discovery in nmap
        [n] → logs IP to not-pingip.txt and moves to next target

  ④ SKIP WHILE SCANNING  (Ctrl+X)
  ─────────────────────────────────
  While nmap is running you will see a live timer:
    ⏱  Scanning ...  00:43  (Ctrl+X to skip this host)

  Press Ctrl+X at any time to:
    • Immediately terminate the nmap process (SIGTERM, then SIGKILL if needed)
    • Log the IP to skipped.txt
    • Restore your terminal to normal
    • Move on to the next IP

  Note: Ctrl+X works by putting the terminal in raw mode on a background
  thread. If stdin is not a TTY (e.g. script is piped), this feature is
  automatically disabled without crashing.

  ⑤ COLOR CODING
  ───────────────
  Cyan     — progress bar, headers, prompts
  Green    — host alive, scan completed successfully
  Yellow   — skipped IPs, incomplete scans, warnings
  Magenta  — live scan timer
  Orange   — no-ping hosts
  Red      — failed scans, errors, quit
  Dim/Grey — existing scan file preview, nmap command display

  ⑥ PROGRESS BAR
  ───────────────
  Shown before each target. Counts only PENDING IPs (already-completed
  ones are excluded from the denominator so progress is accurate).
    Progress  [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  20.0%  (2/10)  8 remaining

  ⑦ SCAN SUMMARY
  ───────────────
  At the end (or after Ctrl+C), a summary box is printed:
    ╔══════════════════════════════╗
    ║       SCAN SUMMARY           ║
    ╠══════════════════════════════╣
    ║  ✔  Completed : 47           ║
    ║  ~  Skipped   : 3            ║
    ║  ↺  Rescanned : 2            ║
    ║  ⊘  No Ping   : 5            ║
    ║  ✘  Failed    : 1            ║
    ╚══════════════════════════════╝

  Counts are unique IPs — an IP rescanned twice is counted once.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GRACEFUL EXIT HANDLING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Ctrl+C (anywhere)  → Catches KeyboardInterrupt, restores terminal,
                        prints summary of progress so far, then exits cleanly.
                        Progress already written to completed.txt is preserved.

  Ctrl+X (mid-scan)  → Skips the current host only. Continues to next IP.

  [q] in menu        → Exits immediately. Terminal is restored first.

  All three paths guarantee the terminal is returned to normal state —
  your shell won't be left in broken raw mode.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  BUGS FIXED FROM ORIGINAL VERSION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  #1  failed_file was dead code — placed after success guard, unreachable
  #2  custom_args.split() broke quoted arguments (e.g. --script "x,y")
      → Fixed with shlex.split()
  #3  'choice' variable leaked between scopes (file menu vs ping menu)
      → Renamed to file_choice / ping_choice
  #4  No nmap binary check — crashed with raw FileNotFoundError
      → Added check_nmap_installed() at startup
  #5  less hard-coded in view_full_report — fails on minimal systems
      → Falls back to cat if less not found
  #6  IPv6 addresses created invalid filenames (colons)
      → sanitize_filename() replaces : and / with _
  #7  count_lines() counted log lines not unique IPs
      → Replaced with count_unique_ips()
  #8  Duplicate IPs in alive.txt were scanned multiple times
      → Deduplicated with order preserved before scan loop
  #9  Progress counter included already-completed IPs
      → Progress now runs over pending_ips only
  #10 tty.setraw() crashed if stdin was piped/redirected (not a TTY)
      → isatty() guard — skip-watcher silently disabled if no TTY
  #11 Terminal left in raw mode if nmap finished before Ctrl+X pressed
      → select() with timeout in watcher; _proc_done event unblocks it
  #12 No graceful Ctrl+C handling — traceback on keyboard interrupt
      → try/except KeyboardInterrupt wraps entire scan loop
  #13 sys.exit(0) from [q] menu left terminal in raw mode during scan
      → restore_terminal() called before every sys.exit()


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  COMMON NMAP ARG COMBINATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Quick service detection:
    '-sV -T4'

  Full aggressive scan (requires root):
    '-sS -sV -O -A -T4 -p-'

  Top 1000 ports + version + scripts:
    '-sV -sC -T4'

  Vulnerability scripts:
    '--script vuln -sV'

  Stealth + slow (IDS evasion):
    '-sS -T1 -f'

  Web app focused:
    '-sV -p 80,443,8080,8443 --script http-title,http-headers'

  All ports (slow but thorough):
    '-sV -p 1-65535 -T4'

  Note: Wrap your args in single quotes to prevent shell expansion.
  Note: -oN (normal output) is always added automatically by this script.
        You do NOT need to add it yourself.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TIPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • Always run with sudo if using -sS, -sU, -O, or raw packet scans.
    Without root, nmap silently falls back to -sT (TCP connect) which is
    slower and more detectable.

  • Use -T4 for speed on a local network. Use -T2 or -T1 when going
    through slow links or avoiding IDS detection.

  • Use screen or tmux if scanning hundreds of hosts — lets you detach
    and reconnect without losing the session.

  • The output_folder is safe to reuse across days. Just say [y] to
    resume and the script picks up exactly where it left off.

  • Partial scan files (from Ctrl+X) are kept on disk. When that IP
    comes up again, you'll be prompted to skip or rescan.

  • To scan a subnet quickly first, run with '-sn' (ping scan only)
    to generate your alive.txt, then run this tool on the results.
    Example:
      nmap -sn 192.168.1.0/24 -oG - | grep Up | awk '{print $2}' > alive.txt
      sudo python3 badboy.py alive.txt results '-sV -A -T4'


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  KNOWN LIMITATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • Linux/macOS only. The tty/termios modules are POSIX-only.
    Windows is not supported.

  • Scans are sequential (one at a time). Parallel scanning is not
    implemented. Use tmux with multiple instances if you need parallelism.

  • No timeout per scan. A single host could hang nmap indefinitely.
    Use Ctrl+X to skip, or add --host-timeout to your nmap_args,
    e.g. '--host-timeout 5m -sV -A'

  • The script does not parse nmap output. It stores raw .txt files.
    For parsed results, add -oX alongside -oN manually in your nmap_args,
    or post-process with tools like nmap-parse-output.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FILE STRUCTURE AFTER A RUN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  results/
  ├── 10.10.10.1.txt          ← raw nmap output
  ├── 10.10.10.5.txt
  ├── 192.168.0.254.txt
  ├── fe80__1.txt             ← IPv6 (colon replaced with _)
  ├── completed.txt           ← audit log of finished scans
  ├── skipped.txt             ← manually skipped + Ctrl+X skipped
  ├── rescanned.txt           ← hosts that were rescanned
  ├── not-pingip.txt          ← no ping + user chose not to use -Pn
  └── failed.txt              ← nmap returned non-zero exit code


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

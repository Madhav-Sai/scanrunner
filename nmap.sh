#!/usr/bin/env bash
# nmap.sh - improved in-place two-line status display
# Usage: PARALLEL=<N> ./nmap.sh <nmap-args...> <ip-file>
# Example: PARALLEL=2 ./nmap.sh -sV -A ip.txt

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: PARALLEL=<N> $0 <nmap-args...> <ip-file>"
  exit 2
fi

IP_FILE="${!#}"
NMAP_ARGS=("${@:1:$#-1}")
PARALLEL="${PARALLEL:-1}"

command -v nmap >/dev/null 2>&1 || { echo "nmap required"; exit 3; }
command -v tee >/dev/null 2>&1 || { echo "tee required"; exit 4; }

if [ ! -r "$IP_FILE" ]; then
  echo "Cannot read IP file: $IP_FILE" >&2
  exit 5
fi

OUTDIR="results"
mkdir -p "$OUTDIR"

sanitize() { printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }

# load hosts (skip blank & comment lines)
mapfile -t HOSTS < <(awk '!/^($|[[:space:]]*#)/{gsub(/^[[:space:]]+|[[:space:]]+$/,""); print}' "$IP_FILE")
TOTAL=${#HOSTS[@]}
[ "$TOTAL" -gt 0 ] || { echo "No hosts found in $IP_FILE"; exit 6; }

TD=$(mktemp -d)
DONE="$TD/done.log"
NOTIFY="$TD/notify.log"
: > "$DONE"
: > "$NOTIFY"

# concurrency FIFO
FIFO="$TD/sem.$$"
mkfifo "$FIFO"
# seed tokens
{
  for ((i=0;i<PARALLEL;i++)); do printf '%s\n' tok; done
} >"$FIFO" &

# scan one host: append to per-host file and tee live output to terminal
scan_host() {
  local ip="$1"
  local fname outfile
  fname="$(sanitize "$ip").txt"
  outfile="$OUTDIR/$fname"

  printf '### nmap %s %s\n' "${NMAP_ARGS[*]}" "$ip" | tee -a "$outfile"
  printf '### started: %s\n\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee -a "$outfile"

  # show live output and save to file
  nmap "${NMAP_ARGS[@]}" "$ip" 2>&1 | tee -a "$outfile"

  printf '\n### finished: %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee -a "$outfile"

  printf '%s\n' "$ip" >> "$DONE"
  # concise notify entry
  printf '%s | saved: %s\n' "$ip" "$outfile" >> "$NOTIFY"
  printf '---%s---\n' "$ip" >> "$NOTIFY"
  tail -n 3 "$outfile" >> "$NOTIFY"
  printf '\n' >> "$NOTIFY"
}

# improved monitor: two-line in-place update using ANSI clear (ESC[K)
monitor_pid=
monitor() {
  # print two empty lines as a place-holder so cursor positioning is consistent
  printf '\n\n'
  while true; do
    sleep 0.5
    local done_count in_progress pct last_msg
    done_count=$(wc -l < "$DONE" 2>/dev/null || echo 0)
    in_progress=$(( TOTAL - done_count ))
    # compute percent safely (TOTAL > 0)
    pct=$(( done_count * 100 / TOTAL ))

    # last notify message (most recent "IP | saved: path" + last 3-line snippet)
    if [ -s "$NOTIFY" ]; then
      # show the most recent short line (the last "IP | saved: ..." entry)
      last_msg=$(grep -E '^[^ ]+ \| saved:' "$NOTIFY" | tail -n1 2>/dev/null || echo "")
      # if no short line found, fallback to last 3 lines of notify
      [ -n "$last_msg" ] || last_msg=$(tail -n 3 "$NOTIFY" 2>/dev/null || echo "No files saved yet.")
    else
      last_msg="No files saved yet."
    fi

    # Move cursor up two lines to overwrite previous status, then clear lines and print new status
    printf '\033[2A'         # move up 2 lines
    printf '\r\033[K'       # clear current line
    printf 'Scanning: total=%d completed=%d in-progress=%d (%d%%)\n' "$TOTAL" "$done_count" "$in_progress" "$pct"
    printf '\r\033[K'       # clear next line
    # limit length of last_msg to terminal width (~200 chars) to avoid wrapping ugliness:
    printf '%s\n' "$last_msg"
    # if finished, break and leave final status visible
    if [ "$done_count" -ge "$TOTAL" ]; then
      break
    fi
  done
}

# start monitor in background
monitor & monitor_pid=$!

# open fifo on fd3
exec 3<>"$FIFO"
for ip in "${HOSTS[@]}"; do
  # wait for a token
  read -r -u 3 token || true
  {
    scan_host "$ip"
    # return token
    printf '%s\n' "$token" >&3
  } &
done

# wait for all scans to finish
wait

# cleanup
exec 3>&-
rm -f "$FIFO"
wait "$monitor_pid" 2>/dev/null || true

# final summary
echo
echo "All scans complete. Results saved in: $OUTDIR"
echo "Summary: total=$TOTAL completed=$(wc -l < "$DONE")"
ls -1 "$OUTDIR" | sed 's/^/  /'
rm -rf "$TD"

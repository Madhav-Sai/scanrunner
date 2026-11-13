# scanrunner -ok addon

New option:

- `-ok`
- `--skip-no-ping`

Behavior:
- Keeps scanrunner's normal wrapper ping check.
- If a target responds, scan normally.
- If a target does not respond, log it to `not-pingip.txt` and skip it automatically.
- The existing `Run nmap with -Pn anyway? [y/n]` prompt is unchanged when `-ok` is not supplied.
- `-Pn` and `--skip-ping` keep their existing meanings.
- NXC mode rejects `-ok` because it is an Nmap workflow option.

Example:

```bash
scanrunner -f file.txt -o nmap -ok -sV -A
```

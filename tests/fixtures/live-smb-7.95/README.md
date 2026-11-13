# Live Samba captures

Captured from four owned, isolated Docker targets on 2026-11-13 using Nmap 7.95 and Samba 4.22.11-Debian. The source run used ScanRunner commit `82dda00` and Debian Trixie. No client data appears in these files.

The original execution is https://github.com/Madhav-Sai/scanrunner/actions/runs/43402938570. Full workflow artifacts expire after 14 days. These exact raw XML and independent wire/configuration proof bytes preserve the eight cases for offline replay. Dataset paths are shortened while artifact hashes remain unchanged.

Nmap 7.95 emitted colon-separated dialect names, including `2:1:0` and `3:1:1`, that the preceding rule revision did not recognize. All eight cases originally abstained. The independently verified labels were retained during the compatibility fix.

Run `python -B scanrunner.py benchmark tests/fixtures/live-smb-7.95/dataset.json --destination live-795-benchmark.json` from the repository root to replay these controlled captures without network activity. This dataset shares the configuration matrix of the 7.93 captures and has correlated samples.

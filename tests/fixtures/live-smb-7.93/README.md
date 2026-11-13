# Live Samba captures

Captured from four owned, isolated Docker targets on 2026-11-13 using Nmap 7.93 and Samba 4.17.12-Debian. The source run used ScanRunner commit `7d45c34`. No client data appears in these files.

Source execution and downloadable complete evidence are available at https://github.com/Madhav-Sai/scanrunner/actions/runs/43402380573. Workflow artifacts expire after 14 days. This directory retains the exact raw XML and independent protocol/configuration proof bytes needed to reproduce the eight-case benchmark. Dataset artifact paths are shortened for repository use. SHA-256 values preserve the original artifact identities.

Each label combines effective server settings with a separate wire negotiation client. The original detector abstained on all eight cases because Nmap 7.93 emits compact dialect names such as `311`. These captures protect the compatibility fix and the existing conservative evidence gates.

Run `python -B scanrunner.py benchmark tests/fixtures/live-smb-7.93/dataset.json --destination live-capture-benchmark.json` from the repository root. This replays preserved live output without network activity. Four related configurations with two checks constitute a small, correlated controlled sample.

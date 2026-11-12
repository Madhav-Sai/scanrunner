# Synthetic regression evidence

All data in this directory is invented for offline tests. Addresses use documentation ranges. No file represents an executed scan or a verified vulnerability. Script text is deliberately contradictory; it is evidence for future conservative rules, never analyst approval.

`nmap-mixed.xml` covers multiple hosts, IPv4/IPv6, TCP/UDP, open/closed/filtered/open|filtered, host-down and script evidence. `nmap-partial.xml` and `nmap-broken.xml` exercise rejected XML. Empty output is created explicitly by the tests. `scenarios.json` supplies CIDR, DNS multi-answer, timeout and failed-process data without live resolution or processes. NetExec output includes positive, negative, ambiguous and contradictory textual observations; no confirmation semantics are implied.

Run `python -B -m unittest discover -s tests -v`. Workflow children use `offline_runtime/sitecustomize.py` to route scanners to Python fixtures and deny DNS, shell/GUI launch and other executables. The separately controlled localhost integration requires `SCANRUNNER_TEST_REAL_NMAP=1` and Nmap; leave it unset for offline development.

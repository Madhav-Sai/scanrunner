# Remaining roadmap implementation

The active request covers five P1 tasks and thirteen P2/P3 upgrades. Acceptance follows working CLI paths, regression counterexamples and recorded verification. The existing live SMB score continues to describe its original measured matrix.

## P1 implementation

Observation records now include scanner/check identity, parser revision, execution preconditions, raw hash, exact source location and conservative evaluation. Protocol contracts cover RDP negotiation, TLS protocol/cipher output, certificate validity at observation time, SSH algorithm offers, explicit FTP authentication and controlled DNS recursion. Open management-associated ports produce exposure observations. Missing evidence and contradictory data retain inconclusive outcomes.

The stock DNS NSE result lacks an independently verified canary answer and nonrecursive control. The controlled native DNS probe requires an owned canary name, known IPv4 answer and explicit canary authorization. Native FTP sends anonymous USER/PASS commands and records the raw replies. Custom ports preserve their directly connected endpoint. Both probes enforce scope, engagement exclusions/expiry and immutable evidence before permitting analyst review.

```powershell
python scanrunner.py probe ftp-anon --ip 127.0.0.1 --scope-file owned-scope.txt --authorization-note OWNED_LAB --dry-run
python scanrunner.py probe dns-recursion --ip 127.0.0.1 --scope-file owned-scope.txt --canary-name owned.example.invalid --expected-answer 192.0.2.99 --canary-authorized --authorization-note OWNED_LAB --dry-run
python scanrunner.py inventory --output results --format xlsx --destination inventory.xlsx
python scanrunner.py report --output results --format xlsx --destination assessment.xlsx
```

XLSX export uses optional `openpyxl` from `requirements-optional.txt`. It preserves text cell types, prevents formula evaluation, rejects oversized cells and publishes atomically. Technical reports include coverage, inventory, findings, run metadata and retest events. Existing JSON/CSV/HTML workflows remain available.

Finding records include explicit CVSS placeholders, affected addresses/hostnames, test conditions, analyst notes and retest status. CVSS values remain `Not determined` until a supported reviewed scoring workflow exists. Final confirmation continues to require evidence and analyst approval.

The profile catalog adds `safe-baseline`, `ssh-audit`, `dns-audit`, `ad-discovery` and `tls-audit`. TLS cipher enumeration now requires explicit authorization because it performs repeated handshakes. The installer completion catalog includes the same profiles. Application version 1.5.0 and parser revision 4 invalidate older completion fingerprints. Rule revision 4 requires renewed analyst review for earlier confirmed findings.

The optional workbook dependency was installed into the project-local `.venv-roadmap` environment for actual round-trip tests. Core imports remain independent of that package. CI explicitly installs the optional dependency to exercise workbook tests on every supported platform.

Current local verification is 190 passes and one gated Nmap skip across 191 tests. Native FTP testing runs against an owned local TCP service. Controlled DNS packet tests verify transaction IDs, question association, expected answers, refusal, malformed packets and compression cycles. Additional live environments remain necessary before assigning accuracy figures to the new rules.

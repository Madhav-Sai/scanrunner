# Resume ScanRunner work

The user resumed work on 2026-11-13 and requested visible running status. The requested final completion marker is `MADHAV`, after the agreed work is complete. Full roadmap completion has not been established.

## Current state after live Docker verification

- Work remains on `D:\scanrunner`, branch `main`. Commit/push and controlled lab testing are authorized. The local Windows host has no Docker/WSL installation. Docker runs on owned GitHub Actions Ubuntu runners.
- Application source at `06625e3` passed all six jobs in CI run `43403567993`. Regression results are 181 passes and one gated live-Nmap skip, plus 26/26 independent safety guards. Quality checks include 18 Python sources and the installer archive.
- Final live Bookworm run `43403568737` and Trixie run `43403574409` both passed. Together they assessed 16 labeled cases across four Samba policies per runtime and two SMB checks. Counts are 8 TP, 8 TN, zero FP, zero FN and zero abstentions. Eight CLI scans, eight evidence-integrity checks, eight persisted-observation checks and both real localhost Nmap tests passed.
- Nmap 7.93/Samba 4.17.12 and Nmap 7.95/Samba 4.22.11 are measured. Independent wire negotiation plus effective Samba configuration established labels. General field accuracy beyond the small correlated SMB matrix remains unmeasured.
- Pilot runs exposed compact and colon-separated dialect aliases. Rule revision 3 handles observed aliases and canonicalized contradictions. Exact original XML/proof bytes are committed under `tests/fixtures/live-smb-7.93` and `tests/fixtures/live-smb-7.95`. Previously confirmed findings need renewed analyst review before final export under the new rule.
- `LIVE_ACCURACY_REPORT.md`, `audit-live-smb-runs.json` and both `audit-benchmark-live-*.json` hold the report and measurements. Complete downloads, including failed pilots, are retained locally under ignored `lab-evidence/RUN_ID` directories. Workflow artifacts expire after 14 days.
- Formal P0 acceptance review closes P0-04/06/08. Accepted backlog is 21/39, comprising P0 12/12 and P1 9/14. Remaining P1 tasks are 04/05/07/10/12. P2/P3 retain 13 future-upgrade entries. No further rule or integration was accepted by the SMB lab work.
- The workflow `.github/workflows/controlled-lab.yml` is manual and supports either Debian runtime. It uses internal networks, no published ports, dropped scanner capabilities, fresh evidence directories, explicit scope and project-scoped cleanup. Repeated runs are excluded from the 16-case final sample.

The sections below preserve the pre-lab resumption history and original implementation plan. Their older counts and pending lab statements are superseded by this section.

## Saved state before the live lab

- Work in `D:\scanrunner` on `main`, remote `https://github.com/Madhav-Sai/scanrunner.git`.
- Python is `C:\Users\MadhavaRaoR\AppData\Local\Programs\Python\Python312\python.exe`.
- Application version is 1.4.0. Core evidence parser revision is 3.
- The application consists of `scanrunner.py`, `scanrunner_assessment.py`, `scanrunner_findings.py` and `scanrunner_benchmark.py`. Windows installation validates and copies the companion modules.
- The latest saved verification is **175 passing tests, zero failures/errors, one gated localhost-Nmap skip**, plus **26/26 independent audit guards passing**. `audit-metrics-nxc-coverage.json` contains hashes matching the current source.
- CI run **43246878880** passed all six jobs for **a98ef43**. A subsequent finding-provenance change passed the local suite and is included in this save. Check its new CI run after resuming.
- The provenance change records observation time and scanner/parser identity in findings, and actual addresses/port/transport/time in retest proof.
- `SCANRUNNER_CODEX_MASTER_PLAN.md` currently accepts **18/39** tasks, comprising P0 9/12 and P1 9/14. P2/P3 remain open. P0-04, P0-06 and P0-08 still need their formal acceptance review. The latter two have substantial verified follow-up fixes.

## Implemented and verified

Normalized Nmap inventory preserves exact port states, OS confidence, host/address associations, provenance and history. Engagement scope/exclusions constrain scans and imports. Metadata and approved address aliases survive rescans. Exports redact recognized secrets, escape content and protect private evidence paths.

Findings require explicit reviewer decisions. Confirmation gates check positive supported evidence, prerequisites, reviewed impact/remediation, origin trust for imports, timestamps/versions, artifact integrity and approval hashes. Final exports reparse evidence. Retests retain history and require equivalent evidence plus reviewer approval for verified remediation. Executive and technical reports separate candidates and confirmed counts.

Two conservative structured Nmap rules support SMB signing requirements and SMBv1 negotiation. Host-script endpoint derivation is recorded when a sole eligible SMB endpoint and compatible arguments support it. Multiple eligible endpoints or custom script arguments remain inconclusive. Actual lab scans should initially select only port 445 to exercise the supported association.

NetExec coverage now accounts for requested addresses, fields, protocol and selected port. Sparse CIDR coverage returns exit 1 with partial/inconclusive state and retained facts. `coverage.json` is hashed and independently recomputed before completion. Per-target outcomes persist before derived exports. Explicit logon rejection differs from access denial. Hash credentials prevent anonymous injection, and generic progress text cannot become an OS claim. Default SMB enumeration requires `--allow-intrusive --authorization-note` because upstream NetExec performs null/optional Guest probes. RDP `all` queries do not inject blank SMB credentials. Query/protocol mismatches are rejected. Parser revision 3 invalidates older completion fingerprints.

The Windows inventory lock race has a deterministic regression and repeated passing end-to-end tests. Invalid ports, contradictory/impossible Nmap counters, duplicate completion/state evidence, empty output, mixed endpoints, unsolicited hosts, missing artifacts and tampering have guards.

## Next task authorized by the user

The user suggested creating small Docker systems and testing live. They authorized a controlled Docker lab. Docker Desktop/CLI and WSL are absent on this Windows machine. No runtime was installed and no host settings were changed. No Docker lab files have been created yet.

Use the existing **GitHub Actions Ubuntu runner with Docker**, avoiding host installation. Repository push and CI work are already authorized. Build a dedicated isolated lab with four Samba configurations forming a two-by-two matrix of SMBv1 enabled/disabled and SMB signing optional/required. Use an internal Docker network, fixed lab-only addresses, no published service ports and project-scoped cleanup.

Suggested implementation steps:

1. Build a small Samba target image and Python/Nmap runner image. Record resolved image IDs, package/tool versions and hashes.
2. Start four targets with explicit minimum SMB protocol and signing policy. Capture `testparm` effective settings, configuration hashes, startup argv and server version as proof.
3. Independently verify actual behavior before assigning labels. A separate minimal SMB negotiation client can read SMB2 security-mode bits and test SMB1 negotiation. Combine reachable-server proof with effective configuration for rejection cases. Ground truth must be independent of ScanRunner/Nmap output.
4. Run ScanRunner through its normal CLI against only those container IPs, selecting TCP 445 and `smb-protocols,smb2-security-mode`, bounded timeouts/rates and explicit lab authorization. Use connect scanning with `--unprivileged`, `-sT`, `-Pn`, `-n` and `--disable-arp-ping` so the runner can operate without extra host privileges.
5. Create a `controlled-lab` benchmark manifest binding each exact endpoint/check, raw scanner artifact/hash, independent ground-truth proof/hash, reviewer/method/time and label. Preserve all actual artifacts, logs and failures.
6. Run the production benchmark, inspect mismatches, add real lab regression captures, fix justified defects and rerun. Upload evidence artifacts through the lab workflow and download/review them locally.
7. Report per-check sample counts, precision, recall, false-positive rate, abstentions, coverage and uncertainty. Four configurations with two checks provide only eight initial labeled cases. Expand coverage before generalizing beyond that lab.

The current six-case dataset at `tests/fixtures/detection-benchmark/dataset.json` is explicitly synthetic. Its results in `audit-benchmark-synthetic.json` establish fixture behavior. Real-world/lab accuracy remains unmeasured until the live lab actually runs.

RDP NLA, TLS, SSH, DNS recursion, anonymous FTP rules, optional XLSX and later integrations remain open. A Linux Samba lab initially validates only the two supported SMB checks. Broader detection accuracy needs additional independently known service configurations.

## Reproduction and caveats

```powershell
$env:PYTHONUTF8='1'
$env:PYTHONDONTWRITEBYTECODE='1'
& 'C:\Users\MadhavaRaoR\AppData\Local\Programs\Python\Python312\python.exe' -B scripts/audit_metrics.py --output audit-metrics-nxc-coverage.json
& 'C:\Users\MadhavaRaoR\AppData\Local\Programs\Python\Python312\python.exe' -B scripts/audit_safety.py --output audit-safety-nxc-coverage.json
& 'C:\Users\MadhavaRaoR\AppData\Local\Programs\Python\Python312\python.exe' -B scripts/check_quality.py
```

The live Nmap test remains gated because Nmap is absent locally. Earlier pending questions requested a labeled environment and portable-Nmap approval. The user's Docker proposal supplies the preferred environment approach, and containerized Nmap can avoid a Windows installation. Installing Docker/WSL on Windows would involve separate host changes and has not been approved or performed.

The existing `.gitattributes` preserves exact benchmark XML bytes and recognizes CRLF. Keep it when updating evidence hashes. Historical code worktrees at `D:\scanrunner-audit-ffef34b` and `D:\scanrunner-evidence-fixes` are older audit baselines. Use the main workspace for current work.

Read `AUDIT.md`, `IMPROVEMENT_REPORT.md`, `DEEP_AUDIT_SCORECARD.md` and the master plan for acceptance details. Preserve raw evidence, keep ambiguous results inconclusive and require analyst approval. All verification so far used synthetic scanner fixtures and controlled local Python process tests. No public/client target was scanned.

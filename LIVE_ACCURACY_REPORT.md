# Live detection accuracy report

## Measured result on 2026-11-13

ScanRunner commit `06625e3`, rule revision 3, correctly assessed **16 of 16 labeled live cases** across two Docker runtimes. There were **zero false positives, zero false negatives and zero abstentions** in the final runs. All eight scanner executions returned success, all eight CLI evidence-integrity checks passed, and all eight persisted-observation checks matched the independently verified endpoint and control settings. Each runtime also passed the real localhost Nmap regression.

| Runtime | Nmap | Samba | Correct assessments | False positives | False negatives | Abstentions |
| --- | --- | --- | --- | --- | --- | --- |
| Debian Bookworm | 7.93 | 4.17.12-Debian | 8/8 | 0 | 0 | 0 |
| Debian Trixie | 7.95 | 4.22.11-Debian | 8/8 | 0 | 0 | 0 |

The final Bookworm execution is run 43403568737. The final Trixie execution is run 43403574409. Both completed successfully, uploaded evidence and removed their owned containers and networks. [Bookworm run](https://github.com/Madhav-Sai/scanrunner/actions/runs/43403568737), [Trixie run](https://github.com/Madhav-Sai/scanrunner/actions/runs/43403574409)

## Per-check results

Each row below describes one check on one runtime, with two positive and two negative ground-truth labels.

| Check | Runtime | TP | TN | FP | FN | Abstentions | Precision | Operational recall | Coverage |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SMBv1 negotiation | Bookworm | 2 | 2 | 0 | 0 | 0 | 100% | 100% | 100% |
| SMB signing requirement | Bookworm | 2 | 2 | 0 | 0 | 0 | 100% | 100% | 100% |
| SMBv1 negotiation | Trixie | 2 | 2 | 0 | 0 | 0 | 100% | 100% | 100% |
| SMB signing requirement | Trixie | 2 | 2 | 0 | 0 | 0 | 100% | 100% | 100% |

For each row, the nominal Wilson 95% interval for correct-assessment rate is **51.0–100%** from four cases. Precision and recall each have a **34.2–100%** interval from two positive cases. The false-positive-rate interval is **0–65.8%** from two negative cases. The configurations and checks are correlated. These binomial intervals describe sample-size uncertainty under their independence assumption, and their applicability to heterogeneous deployments remains unestablished. Repeated pilot runs and offline replays are excluded from the final 16-case count.

## How ground truth was established

Four owned Samba containers implement the cross product of SMBv1 enabled/disabled and signing optional/required. Each container records its effective `testparm` settings, exact configuration hash, Samba binary hash, version, startup argv and capture time. A separate minimal wire client verifies SMB1 negotiation and SMB2.1 signing-required bits before ScanRunner runs. Raw request/response bytes are retained. The labels require configuration and wire evidence to agree.

ScanRunner runs through its normal CLI using TCP connect scanning, exactly port 445, the two selected NSE scripts, explicit target allowlisting and bounded timeouts/concurrency. The runtime network is internal with no published service ports. The scanner drops Linux capabilities. The CLI observations view must preserve the exact endpoint, supported rule outcome and `Needs Verification` status. Automated assessments retain analyst-review requirements.

The benchmark reads original scanner XML through production normalization and rules. Ground-truth proofs and scanner artifacts are SHA-256 bound to each case. A missing usable artifact remains an abstention in the labeled denominator. Server configuration disagreement stops measurement and retains the failure evidence.

## Defects found and repaired

The first Bookworm run completed four scans but abstained on all eight cases. Nmap 7.93 emits compact dialect names such as `202` and `311`, while the rules expected dotted names. The fix accepts the observed compact aliases. [Original Bookworm failure](https://github.com/Madhav-Sai/scanrunner/actions/runs/43402380573)

The subsequent Trixie test completed four scans but abstained on all eight cases. Nmap 7.95 emitted colon-separated dialect names such as `2:1:0` and `3:1:1`. The fix maps those exact observed aliases to the same canonical dialects. Contradictory aliases for one dialect remain inconclusive, and unknown dialect evidence remains inconclusive. [Original Trixie failure](https://github.com/Madhav-Sai/scanrunner/actions/runs/43402938570)

Exact failing XML and independent proof bytes are retained under `tests/fixtures/live-smb-7.93` and `tests/fixtures/live-smb-7.95`. They reproduce both compatibility defects. The finding rule revision advanced to 3. Existing confirmed findings require renewed explicit analyst review under the current rule before final export, using the existing review command and evidence gates.

## Reproduction and evidence

Dispatch `.github/workflows/controlled-lab.yml` with either supported Debian image. Runtime versions, package inventory, image identities, script hashes, server proof, scanner XML/stdout/stderr, SQLite state, CLI integrity checks and observation exports are in each workflow artifact. Full artifacts have a 14-day retention period. Downloads are retained locally under `lab-evidence/43403568737` and `lab-evidence/43403574409`, which are excluded from Git.

`audit-live-smb-runs.json` records source revision, final run URLs, benchmark/dataset hashes, counts, versions and CLI verification outcomes. `audit-benchmark-live-bookworm.json` and `audit-benchmark-live-trixie.json` preserve the final production benchmark results. Raw final evidence remains available in the local downloads and workflow artifacts. The repository fixtures permanently retain the original defect-producing captures and independent proofs.

```powershell
python -B -m unittest discover -s tests -v
python -B scripts/check_quality.py
python -B scripts/audit_safety.py
python -B scanrunner.py benchmark tests/fixtures/live-smb-7.93/dataset.json --destination replay-793.json
python -B scanrunner.py benchmark tests/fixtures/live-smb-7.95/dataset.json --destination replay-795.json
gh workflow run controlled-lab.yml -f base_image=debian:bookworm-slim
gh workflow run controlled-lab.yml -f base_image=debian:trixie-slim
```

The complete offline suite currently contains 182 tests, with 181 passes and one explicitly gated live-Nmap skip. Both container runtimes execute that live test separately and pass it. CI run 43403177631 passed all six Linux/Windows/macOS and Python 3.10/3.12 jobs, including 26/26 independent safety guards, quality/packaging checks and the synthetic benchmark. [Cross-platform CI](https://github.com/Madhav-Sai/scanrunner/actions/runs/43403177631)

CI run 43403567993 also passed all six jobs at the final lab harness revision `06625e3`. [Final application and harness CI](https://github.com/Madhav-Sai/scanrunner/actions/runs/43403567993)

## Remaining drawbacks and next accuracy upgrades

General real-world detection accuracy remains **unmeasured** beyond this controlled SMB matrix. The measured correct-assessment rate is **100% for these 16 cases**. A whole-product 10/10 rating lacks a defined acceptance scale and sufficient representative evidence.

- Expand independently labeled controls across Windows SMB, additional Samba versions, SMB1-only services, port 139, IPv6, authentication policies and per-dialect behavior. This lab independently negotiates SMB2.1 and uses Samba's global configuration to corroborate the signing label.
- Include live unreachable, closed, filtered, interrupted, slow, contradictory and custom-port conditions. Current negative findings cases are reachable hardened services. Existing offline fixtures cover many execution and ambiguity failures.
- Validate actual NetExec versions and their authorization/coverage behavior. Its current regression evidence uses fixtures and mocks. The live lab exercises Nmap.
- Add separately validated evidence contracts and live positive/negative controls for RDP NLA, TLS, SSH, DNS recursion and anonymous FTP before implementing their finding rules. The optional integration roadmap remains in `IMPROVEMENT_REPORT.md`.
- Separate development and held-out evaluation datasets, with independent label review and stable image/package snapshots. These two runtime versions exposed real compatibility defects, but shared configurations and Linux Samba implementations limit representativeness.
- Add durable evidence retention and versioned scanner support matrices. Current package resolution is recorded on each run, and mutable base tags can change future runtime contents.
- Measure throughput, observed network traffic and NSE load separately. The configured PPS budget covers Nmap discovery and port scanning. NSE, OS and version probes have separate traffic behavior. Concurrency coordination shares an output store.
- Preserve the explicit analyst confirmation workflow. Reviewer identity currently uses a local attestation. Enterprise identity, independent review and signed evidence manifests remain future upgrades.

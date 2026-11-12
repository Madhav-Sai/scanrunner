# Detection evidence fixes and accuracy measurement

2026-11-12 follow-up to the deep audit. **Real-world vulnerability detection accuracy is still unmeasured.** No labeled real-world or controlled-lab dataset has been evaluated. Passing synthetic tests cannot supply that number. ScanRunner orchestrates and interprets Nmap/NetExec; its parser correctness and the underlying scanners' detection performance require separate measurement.

## Verified corrections

Nine of the ten previously failing independent checks now pass:

- Empty or unrecognized NetExec output cannot become a completed scan merely because the process exited zero.
- Contradictory SMB/RDP fields remain `Inconclusive`, including subsequent repeated values.
- Generic `[+]` messages cannot establish anonymous authentication. An explicit blank-credential result and an explicitly attempted blank login are required. Recognized conflicting authentication results remain inconclusive.
- Unsolicited result addresses are excluded. Scoped execution uses its pinned destination list when interpreting output.
- Different protocols and ports retain separate rows; SMB security facts cannot migrate to an RDP endpoint.
- Nmap evidence rejects malformed ports, unsupported transport/state values and contradictory host-up counts, including down-scan contradictions.
- The completion API requires scanner artifacts; Nmap evidence is revalidated centrally. Resume checks the required artifact set and hashes.
- Anonymous `smb-os-discovery` sessions require explicit authorization opt-in.

Additionally, NetExec summaries say **unverified observations** and require analyst verification. Green output does not claim an asset is safe. Fingerprints and manifests now record application/parser revisions, so old completion decisions are not reused under changed evidence semantics. Original artifacts remain intact; users may need to rescan after this parser change.

## Results and limits

| Measurement | Audited baseline | After these fixes |
| --- | --- | --- |
| Independent offline guard probes | 16/26 pass | 25/26 pass |
| Regression suite | 121 pass, 1 gated skip | 132 pass, 1 gated skip |
| Regression failures / errors | 0 / 0 locally | 0 / 0 locally |
| Real-world precision, recall, false-positive rate | Unmeasured | Unmeasured |

See `audit-metrics-evidence-fixes.json` and `audit-safety-fixed.json` for source hashes and individual results. The artifact-tampering probe was strengthened to require a successful baseline before tampering. The 26 probe names and denominator remain unchanged. Eleven additional regression methods include positive, negative, ambiguous, contradictory, endpoint-mismatch and lock-contention cases with subtests. Two older tests were corrected: their fixtures previously admitted an unrequested host and asserted successful Nmap completion without Nmap artifacts.

Commands executed with the installed Python 3.12 interpreter:

```powershell
python -B scripts/audit_metrics.py --output audit-metrics-evidence-fixes.json
python -B scripts/audit_safety.py --output audit-safety-fixed.json
python -B scripts/check_quality.py
git diff --check
```

The safety command intentionally still exits 1: **advertised profiles disagree with the execution policy** (DA-10). Adding the anonymous-session guard also makes `smb-audit` require opt-in. Do not weaken the policy to make this check pass. Profile redesign/deprecation remains pending. Cross-platform CI must validate these changes separately.

### Windows inventory repair (DA-11)

A subsequent full run reproduced four inventory rows instead of six. A deterministic contention test then reproduced `PermissionError`: `_FileLock` read the lock byte before attempting to acquire it, and Windows denies reads of another handle's locked byte. Removing this unnecessary read/write lets contending writers reach the acquisition/retry loop. The new test fails on the previous implementation and passes with the fix. Windows permits locking beyond EOF; see [Microsoft's locking contract](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/locking?view=msvc-170). The full suite passes after this repair; repeated tab-export validation is also recorded below. This repairs the reproduced cause, while cross-platform CI acceptance remains pending.

Artifact-integrity review now distinguishes an incomplete/failed/imported job's preserved evidence from the required evidence for a successfully completed scanner job. Absent process streams on an import cannot imply tampering, and an incomplete scan cannot become resumable success.

Repeated Windows end-to-end validation: ten independent executions of `TabEndToEndTests.test_headless_tabs_fall_back_to_background_and_all_targets_finish` passed (16.393 seconds), each requiring all six target rows after three background workers finish. The earlier repair commit `6622e82` passed all six CI jobs in run `43229417358`; the subsequent lock/import-integrity correction still requires its own CI run.

All scanner output in these tests is synthetic. Process tests run local Python helpers. The real localhost Nmap integration remains gated and was skipped. No public/client scans or new scanner installations were performed.

## What is needed for a real detection score

Use an expressly authorized isolated lab, or sanitized outputs paired with independently verified ground truth. Imported output measures interpretation only; end-to-end accuracy requires actually executing the pinned scanner/check against the labeled lab.

Record each test's target, protocol/port, expected setting, method used to independently establish that setting, scanner version, argv, authorization, raw evidence hash, parser revision and observed outcome. Cover SMBv1 enabled/disabled, signing required/not required, RDP NLA enabled/disabled, allowed/rejected anonymous sessions, unreachable hosts, filtered ports, authentication errors and conflicting responses. Include multiple server/tool versions and realistic failure cases. A banner or an open port cannot serve as the ground-truth label for these controls.

For each individual check, count true positives (TP), false positives (FP), true negatives (TN), false negatives (FN), and inconclusive/not-tested results separately. Publish:

- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN), with missed eligible positives and abstentions reported explicitly.
- False-positive rate = FP / (FP + TN).
- Assessment coverage = determinate eligible cases / all eligible cases.
- Raw sample counts and uncertainty intervals; an undefined denominator is `Not measurable`.

Do not discard errors, timeouts or abstentions to inflate the score. Report them by ground-truth class and explain their effect on operational detection coverage. Use an independently reviewed holdout set after fixes; tuning and reporting on the same examples overstates performance. A fixture pass percentage must never be presented as field detection accuracy, and an automated observation does not become an analyst-confirmed vulnerability.

The next measurement depends on the user's labeled evidence or controlled lab details. Until those exist, the defensible result is the verified bug-fix evidence above, with field accuracy explicitly pending.

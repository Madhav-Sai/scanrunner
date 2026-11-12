# ScanRunner deep audit scorecard

> Follow-up fixes: [EVIDENCE_ACCURACY_FOLLOWUP.md](EVIDENCE_ACCURACY_FOLLOWUP.md) records 132 passing regressions, one gated skip and 25/26 independent guards passing after repairs. The measurements below remain the historical baseline. Real-world accuracy is still unmeasured; DA-10 remains open; the reproduced DA-11 lock defect is repaired locally, pending cross-platform validation.

The implementation audited at `ffef34b57e4e1dd552ed2401006f359bad1058e9` passes its local regression suite, but independent adversarial checks reproduce important evidence and interpretation gaps. A later CI run on the same application/test source also reproduced an intermittent Windows inventory-export failure. Its real-world vulnerability detection accuracy remains unmeasured. The earlier assessment that all P0 acceptance criteria were complete was premature. SR-P0-04, SR-P0-06, SR-P0-08, SR-P0-11 and SR-P0-12 are reopened.

Audit date is 2026-11-12. The pushed implementation was examined in an isolated worktree. Uncommitted P1 inventory changes were measured separately. Scanner processes and DNS were mocked, and process-lifecycle tests used controlled local Python programs. The live localhost Nmap integration remains explicitly gated.

| Measurement | Pushed implementation | Uncommitted working tree |
| --- | --- | --- |
| Tests scheduled | 122 | 127 |
| Tests passed | 121 | 126 |
| Failures / errors | 0 / 0 | 0 / 0 |
| Gated integration tests | 1 | 1 |
| Executed regression test pass rate | 100% | 100% |
| Independent audit checks passed | 16 / 26 | 16 / 26 |
| Independent audit-check score | **61.5 / 100** | **61.5 / 100** |
| Advertised profiles accepted by the execution policy | 6 / 10 | 6 / 10 |
| Real-world vulnerability precision / recall | Unmeasured | Unmeasured |

The latest completed CI run observed during this audit passed **five of six jobs**. Windows/Python 3.10 recorded 120 passes, one failure and one gated test, while the other five jobs passed. The failure is DA-11 below. It occurs on the same application and regression-test source as the earlier green run. The application/test diff between `ffef34b` and report commit `c93f8f9` is empty. [Latest observed CI run](https://github.com/Madhav-Sai/scanrunner/actions/runs/43225397121)

The 61.5 score is the unweighted pass fraction of the 26 named checks in `scripts/audit_safety.py`. The checks were selected during source review to examine authorization, output validation, interpretation, artifact requirements and profile compatibility. They form a targeted audit set. They do not represent the prevalence of conditions in customer networks, an external benchmark, or a statistical estimate of vulnerability detection accuracy.

The earlier baseline CI run passed all six combinations, covering Ubuntu, Windows and macOS with Python 3.10 and 3.12. Each combination ran 122 scheduled tests, with 121 passes and the gated localhost integration. That historical run totals 726 successful test invocations and six gated invocations across the matrix. The subsequent failure establishes a remaining stability gap. [Earlier CI evidence](https://github.com/Madhav-Sai/scanrunner/actions/runs/43218961543)

The gated test is `test_workflow.RealNmapTests.test_scan_localhost_listener`. It requires Nmap and `SCANRUNNER_TEST_REAL_NMAP=1`. Actual Nmap/NetExec execution, native terminal interaction, real Kali deployments and operational scan throughput were not exercised in this audit. Scanner compatibility results currently come from synthetic fixtures.

Stdlib trace measured 1,789 of 2,831 executable lines in `scanrunner.py`, or 63.19%, and 63 of 238 in `install.py`, or 26.47%, inside the test process. CLI subprocess tests execute additional code outside that measurement. These are limited in-process line measurements, and full-suite branch coverage remains unmeasured. The metric collector records this limitation in its JSON output.

## Reproduced findings

Priorities below concern assessment reliability and authorization policy. They are engineering priorities, with no assigned CVSS scores or invented CVEs. Source links point to the audited pushed commit.

| ID | Priority | Reproduction and observed behavior | Consequence / required correction |
| --- | --- | --- | --- |
| DA-01 | High | A mocked NetExec process exits 0 with empty stdout/stderr. Its job becomes `COMPLETE` with `parser_ok=1`. Probe `empty_netexec_not_marked_complete` fails. | Empty output can appear successfully tested. Parse associated results before assigning completion, and retain distinct empty/inconclusive outcomes. |
| DA-02 | High | Two SMB lines for the same endpoint report `signing:True` and `signing:False`. The parser returns `False`. Probe `netexec_contradiction_is_inconclusive` fails. | Contradictory evidence can become an apparently positive weakness. Preserve both observations and require resolution. |
| DA-03 | High | `[+] Enumeration finished` becomes `null_auth=Success` when `null_auth_attempt=True`. Probe `netexec_generic_success_not_authentication_proof` fails. | An unrelated success marker can be interpreted as authentication proof. Require a documented authentication-specific result and matching endpoint/context. |
| DA-04 | High | `validate_scan_options(["--script", "smb-os-discovery"], allow_intrusive=False)` succeeds. The official script documentation describes starting a session with an anonymous account. | Authentication can run through an NSE path without the documented credential opt-in. Apply the same explicit authorization policy to authentication-capable scripts and preview their side effects. |
| DA-05 | Medium | A NetExec SMB row for `198.51.100.1` appears in normal results when the requested target is only `192.0.2.1`. Probe `netexec_unsolicited_hosts_excluded` fails. | Unrequested output can contaminate scoped reports. Validate result subjects and retain rejected observations separately with a clear explanation. The reproduction demonstrates output contamination and performs no off-scope scan. |
| DA-06 | Medium | SMB signing data on port 445 is retained after an RDP line changes the row's port to 3389. Probe `netexec_protocol_evidence_not_cross_associated` fails. | Facts can be attributed to the wrong service. Key observations by host, protocol and port, with parser compatibility checks. |
| DA-07 | Medium | XML with `portid="not-a-port"` and otherwise valid completion evidence returns `('COMPLETE', True)`. Probe `malformed_port_cannot_complete` fails. | Parseable XML can still contain invalid service data. Validate field types, ranges, transport and state semantics before accepting parser success. |
| DA-08 | Medium | Normal output says zero hosts up, while XML contains an up host and declares `up="0"`. Validation returns `('DOWN', True)`. Probe `contradictory_down_xml_cannot_validate` fails. | Conflicting host evidence can pass validation. Reconcile host counters and individual records for both complete and down outcomes. |
| DA-09 | Medium, defense in depth | Direct calls to `RunStore.finish_job(..., "COMPLETE", 0, True, ...)` with no scan artifacts can make `completed()` return true. Probe `completion_api_requires_scan_artifacts` fails. | A future caller can bypass evidence requirements through the storage API. Enforce tool-specific required artifacts and validation provenance centrally. This reproduction uses the internal API. Normal Nmap execution has an additional validation path. |
| DA-10 | Compatibility limitation | `web`, `vuln`, `full-fast` and `web-enum` are advertised but their configured arguments are rejected by the execution policy. Probe `advertised_profiles_match_execution_policy` fails. | Four profile choices cannot execute. Replace them with reviewed, bounded profiles or explicitly remove/deprecate the choices. Retain the safety restrictions during that repair. |
| DA-11 | High, intermittent CI reproduction | The Windows/Python 3.10 background-tab test completes its target/run waits, then finds four inventory rows where six are expected. This occurs in CI run 43225397121 after an earlier all-green matrix. | Concurrent export reliability remains unresolved. Preserve failed fixture artifacts, reproduce writer interleavings and repair the export transaction. The prior unbuffered-file correction did not eliminate the failure. Root cause remains under investigation. |

DA-01 is in `_run_nxc_command`, where process exit determines parser success before results are parsed. [Source](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L2132)

DA-02, DA-03, DA-05 and DA-06 arise in `parse_nxc_output`, which overwrites fields, accepts a generic success marker, admits unsolicited hosts and drops the protocol discriminator. The default terminal view also labels inferred boolean conditions as findings while the analyst verification workflow remains unfinished. [Parser source](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L1950), [terminal view](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L2060)

DA-04 uses a real documented script behavior with a mocked policy check. The script's session behavior was verified against primary documentation. [Nmap smb-os-discovery documentation](https://nmap.org/nsedoc/scripts/smb-os-discovery.html), [allowlist source](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L1140)

DA-07 and DA-08 occur in `validate_nmap_evidence`. DA-09 concerns the contract between `finish_job` and `completed`. DA-10 concerns the profile catalog's compatibility with the allowlist. [Nmap validation](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L1039), [job completion](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L799), [resume](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L841), [profiles](https://github.com/Madhav-Sai/scanrunner/blob/ffef34b57e4e1dd552ed2401006f359bad1058e9/scanrunner.py#L54)

Two additional design limitations sit outside the frozen 26-check score. Nmap documents that its min/max packet-rate options affect port scanning and host discovery, with other features using their own timing. ScanRunner's broad aggregate-rate wording therefore needs correction and separate validation for other probe types. Application/parser version provenance also needs an explicit resume/reinterpretation policy. SR-P0-08 is reopened for the traffic-control claim. [Nmap timing documentation](https://nmap.org/book/man-performance.html)

DA-11 also sits outside the frozen 26-check score. The score remains 16/26 to preserve the audit set and its meaning. The separate regression/CI failure must also be resolved before accepting release readiness. [Failing CI job evidence](https://github.com/Madhav-Sai/scanrunner/actions/runs/43225397121)

## Accuracy and release assessment

Vulnerability precision, recall, false-positive rate and false-negative rate require labeled ground truth, representative tool versions and a defined supported ruleset. Those measurements are currently unavailable. A numerical overall detection accuracy would be unsupported.

The passing guards include empty-scope rejection, mixed DNS rejection, DNS-change rejection, extra-target rejection, unreviewed NSE rejection, explicit NetExec credential opt-in, side-effect-free dry run, XML entity rejection, conservative UDP ambiguity handling, nonzero exit rejection, host association checks, timeout rejection, artifact tampering detection, duplicate ownership rejection, CSV neutralization and secret-pattern redaction.

The release still requires the reproduced interpretation and completion defects to be repaired, independent probes to pass, and the analyst confirmation/retest workflow to meet its acceptance criteria. The existing checks support continued development and fixture-based use. Final client vulnerability findings need analyst validation.

The working tree contains an unfinished P1 inventory module, installer companion-module handling and five additional inventory tests. Those changes have 126 passing tests and one gated integration, but are uncommitted and excluded from the pushed-version assessment. Finding-rule validation, analyst approval, retest conclusions, XLSX, optional integrations and the P3 roadmap remain incomplete. Current passing inventory tests establish behavior on their synthetic cases.

## Reproduction and evidence

Run against the pushed snapshot with an isolated checkout or worktree.

```powershell
python -B scripts/audit_metrics.py --repo D:\scanrunner-audit-ffef34b --output audit-metrics-pushed.json --coverage
python -B scripts/audit_safety.py --repo D:\scanrunner-audit-ffef34b --output audit-safety-pushed.json
```

Run against the working tree with `--repo` omitted. Set `PYTHONUTF8=1` and `PYTHONDONTWRITEBYTECODE=1` when reproducing on Windows. This audit used Python 3.12.10 from the approved per-user installation.

`audit_safety.py` exits 1 when any expected guard fails. Its 26 checks are separate from the historical regression suite and are currently a manually invoked audit gate. They are not included in the existing CI test count. An initial working-tree probe run had an import-path error in the audit harness. The harness was corrected and the result was rerun before recording the final score.

Machine-readable evidence is retained in `audit-metrics-pushed.json`, `audit-metrics-working.json`, `audit-safety-pushed.json`, `audit-safety-working.json` and `audit-ci-latest.json`. Source SHA-256 values bind the recorded results to the tested code. Stdlib syntax/safety checks and installer archive checks were also run. No production/client scan evidence was modified during the audit.

The local master plan was restored from the original UTF-8 document to repair encoding damage introduced while updating checkboxes. The original Downloads document remains intact. Historical progress entries remain in the repository copy, with a new top-level notice explaining the reopened acceptance criteria.

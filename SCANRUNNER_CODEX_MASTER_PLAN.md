# ScanRunner — Codex Master Development Plan and TODO

> Profile follow-up closes DA-10 with documented compatibility changes, authorization-aware profile probes, CLI coverage and completion consistency. Current results are 134 regression passes, one gated skip and 26/26 targeted guards passing. See IMPROVEMENT_REPORT.md. No additional roadmap acceptance checkbox is closed by this increment.

> Evidence repair follow-up: see EVIDENCE_ACCURACY_FOLLOWUP.md. Nine previously failing guard checks now pass; 132 regression tests pass with one gated skip. DA-10 remains open; the reproduced DA-11 lock defect is repaired locally, pending cross-platform acceptance. No additional roadmap task is accepted as complete. Real-world accuracy still requires labeled lab evidence.

> Deep audit update, 2026-11-12. SR-P0-04, SR-P0-06, SR-P0-08, SR-P0-11 and SR-P0-12 are reopened. Earlier completion notes are superseded by DEEP_AUDIT_SCORECARD.md and the independent probe results.

> **Repository:** `https://github.com/Madhav-Sai/scanrunner`
> **Primary platform:** Kali Linux
> **Other platforms:** Linux, macOS, Windows (preserve existing support where implemented)
> **Mission:** Turn ScanRunner into a dependable, offline-first, terminal-first network VAPT assessment assistant while preserving existing features and minimizing false positives, disruptive scan behavior, and reporting mistakes.

## How Codex must use this file

**This is an executable engineering specification and a living TODO list.** Read the entire document, inspect the checked-out repository, and make changes incrementally. Update the checkboxes **only after** implementing a feature, running relevant tests, and satisfying its acceptance criteria. Track discoveries and blockers in this same document or in linked engineering documents.

**Start with an audit, not a rewrite.** The feature inventory below reflects earlier public documentation and may differ from the actual checked-out code. Treat everything as a hypothesis until verified in source and tests. Never assume a feature is missing merely because it appears on the checklist. Preserve stable CLI behavior and existing capabilities.

**Most important safety requirement:** A goal of *zero false positives* is not technically guaranteeable from automated scanning. Accordingly, the system must be engineered to **never silently turn an uncertain signal into a confirmed security vulnerability**. Prefer an explicit **`Needs Verification`**, **`Inconclusive`**, or **`Not Tested`** outcome over a confident but unsupported claim. Likewise, avoid false negatives by distinguishing *not observed* from *tested and absent*. The system must not automatically issue a final client-ready “Confirmed” finding without sufficiently strong, reproducible evidence and analyst approval.

---

## 1. Role, scope, and success criteria

Act as a senior Python engineer, offensive-security tool developer, quality engineer, and network VAPT reporting specialist.

### Scope

- Authorized network infrastructure scanning, enumeration, service inventory, configuration assessment, evidence tracking, analyst-reviewed findings, remediation retesting, and client-safe exports.
- Nmap and NetExec are primary existing integrations. Additional tools must be **optional**, **explicitly enabled**, and installed separately when needed.
- Work offline wherever possible; no mandatory cloud API, paid service, or AI API.
- Remain a small, maintainable CLI application. A local TUI is optional; a web dashboard is **not** a default requirement.

### Definition of success

An assessor can (1) define a client engagement and scope, (2) select and preview an appropriate scan profile, (3) run bounded, authorized scans, (4) safely resume/retry and preserve history, (5) view an accurate normalized asset inventory, (6) review potentially relevant security observations with source evidence, (7) explicitly verify or reject findings, (8) compare retest evidence with a baseline, and (9) export trustworthy technical and stakeholder-friendly results.

### Hard constraints

1. **Never perform real scans of public or client targets during development or tests.** Use fixtures, mocked subprocesses, and expressly controlled local test environments.
2. **Never fabricate** CVEs, affected versions, exploitability, CVSS vectors/scores, severity, confirmation status, references, remediation success, hostnames, scan timestamps, or tool execution results.
3. **Do not equate** an open port, banner, product/version string, NSE label, or unauthenticated scan inference with proof of exploitability.
4. **Never overwrite or delete original scan evidence** through normal scan, retry, resume, compare, or report generation workflows.
5. Enforce user-provided authorization scope, with fail-closed behavior when scope cannot be validated; provide safe preview/dry-run behavior.
6. Do not enable credentials-based attacks, password spraying, brute force, exploitation, or disruptive NSE/Nuclei checks automatically. Require separately documented explicit authorization and opt-in for any intrusive operation.
7. No hidden network calls or telemetry; never upload client data automatically.
8. Avoid introducing regressions; preserve existing CLI flags, known report formats, installation paths, and cross-platform behavior when feasible. Clearly document intentional breaking changes.
9. Do not report a task complete if the code or tests have not actually been run.
10. Do not install tools, change system settings, run large scans, or make destructive edits without clearly stating the impact and verifying permissions and scope.

---

## 2. Existing functionality: verify before changing

The publicly described version reportedly contains some or all of the following. **Codex must confirm each against code and tests, mark verified/unverified in `AUDIT.md`, and improve rather than duplicate.**

- Nmap orchestration and custom arguments.
- NetExec integration.
- Scan profiles and templates.
- Multi-host jobs and parallel execution.
- Terminal-tab splitting.
- Resume, skip, rescan, and failure tracking.
- Scope-file validation.
- Nmap XML parsing.
- CSV/JSON inventory exports.
- Basic HTML port reporting.
- Scan status and open-port change comparisons.
- Installer, shell completion, and multi-OS support.

Potential engineering risks to audit (not pre-judged bugs): file-backed status under concurrency, misleading resume conditions, report overwrite, DNS-to-IP scope drift, subprocess hangs, high-load scans, partial XML handling, ambiguous service/version data, scan-history diffs, and insufficient retest proof.

---

## 3. Priority roadmap / living TODO

Checkboxes are intentionally unchecked. Assign actual issue links, commit hashes, test evidence, and implementation status as work proceeds. **P0 must precede P1/P2 unless dependency analysis justifies otherwise.**

### P0 — Repository audit, safety, and reliability

- [x] **SR-P0-01 — Baseline audit.** Read `README.md`, release/add-on notes, entry points, parser, scan execution, data stores, NetExec integration, reports, packaging, and tests. Run existing tests (or record precisely why they cannot run). Deliver `AUDIT.md`: verified current features, reproducible defects, risks, prioritized gaps, dependencies, and safe migration approach. **Accept:** every claimed existing feature references code paths and/or test evidence.
- [x] **SR-P0-02 — Create regression fixtures.** Save representative sanitized Nmap XML, service scripts, normal/empty/partial/broken outputs, NetExec output, IPv4/IPv6, CIDR, DNS multi-answer, TCP/UDP, host down, filtered ports, and process failures. **Accept:** fixtures are synthetic or explicitly sanitized; baseline tests pass without contacting live client hosts.
- [x] **SR-P0-03 — Scope enforcement.** Validate exact authorized addresses/CIDRs/hostnames, exclude lists, DNS resolution, and any scan target derived from plugin output. Revalidate resolved IPs immediately before execution; reject out-of-scope resolved addresses and redirect/crawl pivots by default. Handle IPv4/IPv6 and DNS rebinding/race risk conservatively. **Accept:** deny-by-default tests for mixed in/out-of-scope DNS answers and target expansion.
- [ ] **SR-P0-04 — Dry run and impact preview.** Display exact command argv, tool, target addresses, scan profile, required privileges, traffic intensity, side effects, and output destinations without executing. **Accept:** dry-run tests assert zero spawned scanner processes or network actions.
- [x] **SR-P0-05 — Durable state and versioned runs.** Introduce lightweight SQLite state or justify an equally robust alternative. Track engagement IDs, immutable run IDs, targets, command fingerprints, jobs, timestamps, exit codes, parser success, status transitions, and artifact locations. Use transactions and appropriate SQLite busy handling. **Accept:** concurrent updates cannot corrupt state; all previous raw outputs remain intact.
- [ ] **SR-P0-06 — Correct completion and resume semantics.** Completion requires validated process outcome **and** sufficient, parseable, associated result evidence; failure/timeout/partial/empty responses are different states. Resume checks tool version, normalized target, arguments, profile, scope, and other consequential options via stable fingerprint. **Accept:** changing a relevant option cannot silently mark work as completed.
- [x] **SR-P0-07 — Robust subprocess management.** Use argument arrays (no unsafe `shell=True`), sensible timeouts, graceful cancellation, bounded retries/backoff, child process cleanup, and reliable Ctrl+C handling. **Accept:** interrupted scans preserve partial evidence; do not become “Completed.”
- [ ] **SR-P0-08 — Concurrency safeguards.** Add optional global/per-subnet concurrency and scan-rate ceilings, atomic updates, unique job ownership, and controlled backpressure. **Accept:** deterministic tests cover concurrent workers, crashes, duplicate claims, and retries.
- [x] **SR-P0-09 — Raw evidence preservation.** Save exact stdout/stderr, original XML, exit status, command argv with secrets redacted, scanner version, UTC timestamps, and relevant config in immutable run-specific paths. Hash raw evidence (SHA-256). **Accept:** generation/retest cannot change earlier run artifacts; missing/corrupt artifacts are flagged.
- [x] **SR-P0-10 — Secure local data handling.** Prevent path traversal, unsafe XML entity expansion, command injection, log credential leaks, excessive filesystem permissions, and accidental exports of secrets or personal data. **Accept:** negative security tests and basic dependency checks pass.
- [ ] **SR-P0-11 — Backwards compatibility.** Document current CLI syntax and defaults before refactoring; provide migration/back-compat behavior for output paths and metadata. **Accept:** existing CLI regression suite and packaging tests pass.
- [ ] **SR-P0-12 — CI quality gate.** Add lint/static analysis, automated tests, fixture-based integration tests, and packaging checks. **Accept:** CI is reproducible without external scan targets or mandatory optional tools.

### P1 — Accurate inventory and everyday VAPT productivity

- [ ] **SR-P1-01 — Normalized asset model.** Capture input target, resolved addresses, individual discovered hosts, DNS names with source, IPv4/IPv6, OS guesses with confidence, TCP/UDP port state, service/product/version, timestamp, scanner/run identity, and raw evidence references. **Accept:** CIDR-to-multiple-host and hostname-to-multiple-IP mappings are preserved; no cross-host result leakage.
- [ ] **SR-P1-02 — Inventory enrichment.** Add assessor-managed engagement/customer, subnet, asset owner, site/location, environment, criticality, tags, and notes. **Accept:** metadata is distinct from scanner observations and survives rescans.
- [ ] **SR-P1-03 — Accurate service-state normalization.** Distinguish `open`, `closed`, `filtered`, `open|filtered`, `unknown`, unreachable, skipped, and not tested. Distinguish TCP from UDP. **Accept:** exports never label `open|filtered` as confirmed `open` or missing results as closed.
- [ ] **SR-P1-04 — Evidence-linked observation engine.** Parse only documented, tested outputs and emit standardized observations with check ID/version, host/port/protocol, test preconditions, raw artifact hash, line/field evidence, outcome, and confidence. **Accept:** all machine-generated observations trace back to preserved scanner data.
- [ ] **SR-P1-05 — Conservative finding rules.** Add independently tested checks for SMBv1, SMB signing requirements, RDP NLA, TLS protocol/cipher/certificate issues, SSH algorithms, DNS recursion, anonymous FTP **only if positively tested**, and exposed management interfaces as *exposure observations* rather than default vulnerabilities. **Accept:** each rule has positive, negative, ambiguous, contradictory, and malformed fixtures.
- [ ] **SR-P1-06 — Human verification workflow.** Statuses: `Not Tested`, `Potential`, `Needs Verification`, `Confirmed`, `False Positive`, `Accepted Risk`, `Inconclusive`, `Remediated (Verified)`. Require analyst approval, timestamp, and supporting evidence before `Confirmed`. **Accept:** no ambiguous machine result can create a confirmed client finding by default.
- [ ] **SR-P1-07 — High-quality finding template.** Include title, concise plain-language description, affected targets (IP/hostname/port), severity and vector **only when justified**, impact, evidence, remediation, references, test limitations, analyst notes, and retest status. **Accept:** missing values display `Not determined` or `Not tested`, never guessed values.
- [ ] **SR-P1-08 — Accurate baseline and retest matching.** Match stable finding identity plus affected asset/service/check, preserving history even if IP/hostname changes. Compare old/new **equivalent** evidence. **Accept:** an absent port, host down, scanner failure, blocked access, or missing plugin never automatically counts as remediation.
- [ ] **SR-P1-09 — Clear retest outcome model.** Distinguish `Still Present`, `Potentially Remediated`, `Remediated (Verified)`, `Not Retested`, `Inconclusive`, `Unable to Assess`. **Accept:** verification requires the relevant control was retested with comparable scope and adequate test quality.
- [ ] **SR-P1-10 — Useful exports.** Extend (do not unnecessarily replace) CSV, JSON, HTML, and add `.xlsx` using an optional maintained library. Include inventory, findings, run metadata, error/coverage summary, retest outcomes, evidence references, and analyst notes. **Accept:** a round-trip schema test checks row counts, IP/host/port association, status, dates, and proper escaping; no formula injection in spreadsheets.
- [ ] **SR-P1-11 — Executive and technical views.** Provide scope summary, tested/pending/failed assets, coverage limitations, open service counts, potential vs confirmed findings, severity only for confirmed/justified findings, and remediation progress. **Accept:** summaries do not imply complete coverage when there were failed/skipped/not-tested targets.
- [ ] **SR-P1-12 — Scan profiles upgrade.** Audit existing profiles and add only missing, documented profiles for fast TCP discovery, full TCP, common UDP, web enumeration, TLS, SMB, RDP, SSH, DNS, AD service discovery, and non-intrusive baseline. **Accept:** every profile previews argv/required privileges/risk, enforces scope, and supports bounded user overrides.
- [ ] **SR-P1-13 — Safe import workflow.** Ingest historical Nmap XML and optional tool output without rerunning scans; validate origin, parser version, target identity, and imported-evidence trust. **Accept:** imports are marked as imported and do not pretend to be newly executed scans.
- [ ] **SR-P1-14 — Search/filter/status CLI.** Filter by engagement, IP/CIDR, hostname, site, owner, service, port, protocol, run, status, and finding state. Provide readable progress, queued job review, and failed target retry. **Accept:** no regression in non-interactive usage and JSON output remains machine-readable.

### P2 — Optional extensions, never at the expense of accuracy

- [ ] **SR-P2-01 — Plugin adapter contract.** Separate availability/version detection, argv creation, opt-in impact approval, execution, output parsing, normalization, error handling, and fixture-based tests. **Accept:** missing plugins do not break core scanning.
- [ ] **SR-P2-02 — NetExec result enhancement.** Improve structured capture for supported, approved SMB/RDP/AD configuration observations without credential attacks by default. **Accept:** NXC output ambiguities produce `Needs Verification`, not confirmed weaknesses.
- [ ] **SR-P2-03 — Optional `httpx` enrichment.** Discover HTTP properties from scoped, explicitly selected targets without automatic off-scope following. **Accept:** no redirect to out-of-scope addresses; collected data labels confidence and tool source.
- [ ] **SR-P2-04 — Optional `testssl.sh` integration.** Parse supported TLS protocol/cipher/certificate results with parser compatibility tests. **Accept:** conflicting test results are surfaced instead of silently selecting the worst outcome.
- [ ] **SR-P2-05 — Optional Nuclei integration.** Require reviewed, explicitly approved templates, pinned template identity/version, severity/impact policy, and opt-in execution. Treat template matches as *unverified* unless the template and proof meet a documented confirmation standard **and analyst approves**. **Accept:** no implicit scan escalation, default exploitation, or automatic confirmed CVEs.
- [ ] **SR-P2-06 — Offline vulnerability reference support.** Optional manually downloaded/versioned advisory data; correlate versions conservatively with distro backports and vendor advisories. **Accept:** banner-only CVE matches remain potential; source/currency/uncertainty recorded.
- [ ] **SR-P2-07 — Lightweight local TUI.** Assessment selection, queue/status view, host and findings browser, reviewer decisions, evidence viewer, and export launcher. **Accept:** TUI is optional and does not degrade CLI or offline use.
- [ ] **SR-P2-08 — Optional local scheduling/notifications.** Clearly configured scheduled jobs and privacy-safe notifications; revalidate scope/authorization at each execution. **Accept:** no hidden recurring scan or leaked client results.
- [ ] **SR-P2-09 — Privacy-safe sharing.** Anonymized report exports, redaction preview, and export allowlist for sensitive fields. **Accept:** test data with credentials/tokens remains absent from safe-share outputs.

### P3 — Consider only after P0/P1 stability

- [ ] **SR-P3-01 — Modular rule packs** with stable IDs, schema, versioning, explicit evidence requirements, and regression fixture coverage.
- [ ] **SR-P3-02 — Asset lifecycle/trend analytics** with explicit confidence/coverage indicators and subnet/site comparisons.
- [ ] **SR-P3-03 — Engagement templates and reusable report layouts** with client-safe fields and independently testable output schemas.
- [ ] **SR-P3-04 — Optional signed/attested report manifest** binding scans, parser/rules versions, analyst approval, and exported evidence hashes.

---

## 4. False-positive prevention: non-negotiable policy

### 4.1 Understand the limits

Automated scanner results have uncertainty. The software **must minimize false positives**, but must **not promise zero false positives**. The same applies to false negatives: lack of a detection is not proof of safety. A finding is a verified conclusion, whereas a scan result is an observation. The difference must exist in data models, CLI labels, exports, reports, and tests.

### 4.2 Four distinct layers

1. **Raw evidence:** unaltered original tool output with file hash, command, scope, tool/version, timestamp, exit status, and source metadata.
2. **Normalized observation:** parsed fact that can be traced to an exact raw artifact plus location (XML XPath, field, or line range where feasible). Keep original parser details.
3. **Candidate finding:** rule-based interpretation with explicit detection logic, required evidence, confidence, exceptions, limitations, and supporting/contradictory observations; defaults to `Potential` or `Needs Verification`.
4. **Confirmed finding:** analyst-approved assessment with reproducible technical support, applicable service/asset identification, correct security-control interpretation, and recorded review identity/time. Automated confirmation may produce a *recommendation* only, not silently publish a confirmed client report.

### 4.3 Fail-closed evidence gate

A candidate MUST NOT be labeled confirmed or included in **confirmed vulnerability totals** unless all applicable items are satisfied:

- The authorized target, actual IP, protocol, service, and port are reliably associated.
- The relevant check actually ran, completed in a valid state, and its output parsed without critical errors.
- Required preconditions were met (e.g., negotiated protocol, reachable service, correct endpoint, permission level, valid TLS handshake).
- Evidence specifically supports the claimed condition, not simply the presence of a service or a tool-reported keyword.
- No unresolved contradictory evidence exists; if it does, mark `Inconclusive` or `Needs Verification`.
- Rule version and definition are known; there is a test fixture that reproduces the detector's positive and negative behavior.
- The observation is current enough for the report and comes from the correct assessment run.
- A reviewer explicitly verifies impact wording, affected targets, severity/CVSS applicability, and remediation advice.

A missing prerequisite, scanner timeout, malformed output, unauthorized scope, or ambiguous response => **`Not Tested` / `Inconclusive` / `Needs Verification`**, never a positive security claim.

### 4.4 Specific detection pitfalls and required guards

| Signal | Prohibited shortcut | Required behavior |
|---|---|---|
| Port 445 open | “SMB signing disabled” | Determine SMB dialect and whether signing is required from verified negotiation/check output; ambiguous state = `Needs Verification`. |
| Port 3389 open | “RDP NLA disabled” | Require a specific, validated protocol-level check; a reachable RDP port alone proves only exposure. |
| TLS 1.0/1.1 | “Vulnerable” from an unsupported or failed probe | Require a successful handshake establishing the specific protocol on the correct endpoint/SNI; report tested versions and failures distinctly. |
| TLS certificate error | “Expired certificate” for every trust error | Separately evaluate validity dates, chain trust, hostname mismatch, self-signed status, SNI, and observation time. |
| SSH banner/version | “Known CVE exploitable” | Check vendor/distro patch and backport context; banner-only identification is `Potential` at most. |
| Product/version banner | “Critical CVE” | Correlate authoritative applicable advisories and configuration prerequisites; do not create confirmed CVEs from a banner. |
| DNS recursion | “Open resolver” because port 53 is open | Require a suitably scoped recursion test and validated response semantics; avoid mixing authoritative and recursive behavior. |
| FTP port 21 | “Anonymous FTP allowed” | Require an explicitly permitted authentication attempt and positive result; do not infer from banner. |
| Missing port on rescan | “Fixed” | Ensure same target, protocol, scan coverage, reachability, and adequate control-specific evidence; otherwise `Inconclusive`. |
| No scanner finding | “Secure” | State `Not observed in tested scope`, with scan coverage and limitations. |
| Nuclei match | “Confirmed exploitable” | Treat as candidate unless evidence and applicability independently reviewed. |
| Nmap OS guess | “Confirmed Windows/Linux version” | Label OS detection confidence and preserve alternate guesses where available. |
| `open|filtered` UDP | “Open service” | Keep exact ambiguous state and document inability to determine openness. |

### 4.5 Rules and severity governance

- Each detection rule has a unique stable ID, version, category, references, prerequisites, data-source compatibility, positive evidence requirements, counterexamples, known false-positive cases, and fixtures.
- Severity is not equivalent to certainty. Preserve **severity**, **confidence**, **verification status**, and **impact** as separate fields.
- CVSS score/vector may only be included where applicable, supported, and manually verified. Otherwise write `Not determined` rather than inventing a number.
- Any live enrichment from external CVE feeds must be opt-in; record source URL, retrieval date, local dataset version, product identification confidence, vendor patch status, and advisory applicability.
- Use configurable policy for whether `Potential` findings appear in draft reports; exclude them by default from final **confirmed finding counts**, and visibly label all draft candidate findings.
- Do not automatically change a confirmed analyst decision on subsequent runs. Create a new status/retest event and flag discrepancies for reviewer resolution.
- A future optional AI helper may summarize evidence but **must never manufacture observations, bypass evidence gates, modify original results, or approve findings.** AI must not be required.

### 4.6 Tests specifically aimed at false positives

For every finding rule, provide at least:

- A positive, correctly identified fixture.
- A clear negative fixture.
- An ambiguous/inconclusive fixture.
- A malformed/partial/timeout fixture.
- A contradiction fixture.
- A mismatched-host/port/protocol fixture.
- A check that missing evidence does not produce `Confirmed`.
- A check that final-report counts include only appropriately approved findings.

**Block merging** if any rule misclassifies a deliberately ambiguous or negative fixture as confirmed. Record and triage new false-positive reports as regression fixtures.

---

## 5. Proposed architecture (adapt to actual repository)

Favor straightforward Python modules and stable interfaces rather than a wholesale rewrite:

```text
scanrunner/
  cli/                 # CLI parser and user experience
  core/                # engagement, scope, scheduler, runs, subprocess lifecycle
  models/              # asset, service, evidence, observation, finding, retest
  storage/             # SQLite migrations and artifact paths
  parsers/             # Nmap XML, NetExec, optional plugin formats
  rules/               # documented conservative checks
  integrations/        # Nmap, NetExec, optional adapters
  reports/             # CSV, JSON, HTML, optional XLSX
  tui/                 # optional local interface
  tests/               # fixtures, mocks, unit, integration, regression
```

**This layout is illustrative.** Reuse existing module structure when possible and do not create empty modules for appearance.

### Minimum record schema

- `Engagement`: ID, client/project label, owner, explicit authorized scope, exclusions, dates, scope version.
- `Run`: ID, engagement ID, profile/version, tool/version, normalized argv, configuration fingerprint, started/ended UTC timestamps, outcome, impact classification.
- `Target`: requested target, resolved address set, scope decision, identity provenance.
- `Asset`: stable internal ID, observed IP(s), hostname(s), tags, site, owner, classification, source provenance.
- `ServiceObservation`: asset/run IDs, IP, port, transport, exact port state, service/product/version, parser version, raw evidence reference, confidence.
- `SecurityObservation`: check/rule ID/version, subject identity, observed condition, check execution state, evidence location, corroboration/contradiction.
- `Finding`: stable finding ID, candidate/confirmed status, analyst record, title, conditions, impact, severity/CVSS if justified, remediation, references, confidence.
- `RetestEvent`: finding ID, baseline run/evidence, new run/evidence, comparable coverage check, reviewer decision, conclusion.
- `Artifact`: filename, run ID, type, SHA-256, size, timestamp, retention policy, redaction metadata.

### CLI behavior (examples, not mandatory exact syntax)

Commands should be discoverable through `--help`, support `--json` where sensible, and preserve existing flags:

```bash
scanrunner engagement create --name customer-assessment --scope scope.txt
scanrunner scan --engagement customer-assessment --profile safe-baseline --dry-run
scanrunner scan --engagement customer-assessment --profile safe-baseline
scanrunner status --engagement customer-assessment
scanrunner inventory --engagement customer-assessment --format xlsx
scanrunner findings --engagement customer-assessment --status needs-verification
scanrunner retest --engagement customer-assessment --baseline RUN_ID --dry-run
scanrunner report --engagement customer-assessment --format html
```

These are **desired examples**. Adapt to the established CLI if adding subcommands would create incompatibilities.

---

## 6. Scanning and scope safety

- An engagement must store explicit allowlisted CIDRs/IPs/hostnames and exclusions; **user-supplied scan arguments cannot bypass scope**. Detect potential scope-extending flags, redirects, imported host lists, and plugin-discovered targets.
- DNS can resolve to multiple A/AAAA records and change between import, preview, and execution. Record all answers with resolution times, validate each destination, and reject unapproved destination addresses. A failed or changing lookup must not silently expand scope.
- Prefer controlled subprocess execution without shell interpolation. Record safely redacted argv and resolved binary paths/versions.
- Show expected impact per profile: default-safe, potentially noisy, credentialed, or intrusive. Explicit opt-in for high-impact modes; do not include risky operations in default profiles.
- Avoid automatically interpreting a network-level ICMP failure as a host being down when other services may be reachable; retain scan methods and limitations.
- Provide timeouts, bounded retries, global/per-subnet rate limits, optional maintenance windows, and clear abort behavior.
- Use local test fixtures for development; **do not scan the repository owner’s websites, client networks, or example IPs** to prove functionality.

---

## 7. Reporting quality bar

All exports must distinguish **tested**, **not tested**, **unreachable**, **failed**, **inconclusive**, **candidate**, and **analyst-confirmed** states. Do not use a generic `N/A` where the reason matters.

### Technical inventory export

Suggested columns: `S.No.`, `Engagement`, `Site`, `Subnet`, `IP Address`, `Hostname`, `Transport`, `Port`, `Port State`, `Service`, `Product`, `Version`, `OS (Confidence)`, `Scan Run`, `Observed At`, `Evidence`, `Notes`.

### Findings export

Suggested fields: `Finding ID`, `Title`, `Description`, `Affected Targets (IP, hostname, port)`, `Status`, `Confidence`, `Severity (if justified)`, `CVSS Vector/Score (if verified)`, `Impact`, `Evidence`, `Reproduction/Check Conditions`, `Remediation`, `References`, `Reviewer`, `Review Date`, `Retest Outcome`.

### Summary export

- Include total in-scope targets, discovered hosts, successfully scanned hosts, skipped/not-tested/failed hosts, and overall coverage.
- Count **confirmed** findings separately from **potential/needs-verification** observations.
- Clearly label which target types, protocols, port ranges, scan techniques, and time ranges were used.
- Preserve exact timestamps and timezone display conventions; use UTC for storage.
- State explicitly that an automated scan is a time-bound assessment, not proof of complete security.
- Defend against CSV/Excel formula injection, HTML injection, broken Unicode, invalid IP formatting, and accidental secret disclosure.

### Retest reporting

Show `Original Evidence`, `New Evidence`, `Comparability`, `Outcome`, and `Reviewer`. When evidence is insufficient or the test could not complete, use `Inconclusive` / `Unable to Assess`, **not** `Remediated`.

---

## 8. Codex execution procedure

### Step A — Baseline (mandatory first)

1. Read repository files and this entire plan.
2. Print the current code architecture and existing CLI feature map.
3. Run existing tests and retain test output or clearly record failures.
4. Produce `AUDIT.md` with **verified** present features, confirmed defects, risks, dependencies, and scope of proposed changes.
5. Update this document only to reflect confirmed duplicates, obsolete requests, and audit findings; **do not check off implementation tasks merely because a feature exists** unless it meets the acceptance criteria and is tested.

### Step B — Implement P0 in small increments

For each task:

1. Explain the problem and user-visible impact.
2. Make the smallest safe code change.
3. Add positive, negative, ambiguous, and regression tests where applicable.
4. Execute the tests and capture results.
5. Update docs and the task checkbox only when verified.
6. Report changed files, behavioral impact, compatibility risk, and next task.

Do not proceed to optional feature expansion while core state, scope, and evidence safety remain unreliable.

### Step C — Add P1 findings only with gating

For every proposed scanner finding rule:

1. Define exactly what constitutes evidence of the claim.
2. Identify conditions that could produce false positives.
3. Add multiple positive, negative, ambiguous and contradictory fixtures.
4. Implement a conservative parser and rule evaluation.
5. Make analyzer output *unverified* by default.
6. Require explicit analyst confirmation in the workflow.
7. Check final-report counts and language for accidental overstatement.

Do **not** ship a check if the evidence semantics are unclear; mark it `Blocked: insufficient validated evidence` with rationale and required next tests.

### Step D — Optional integrations

Integrate P2 tools individually. Avoid requiring users to install all of them. Pin/record relevant external tool and rule/template versions. Preserve raw output and local-only operation.

### Step E — Final review

- Run the complete regression suite and security tests.
- Confirm no live public/client scan was performed during testing.
- Confirm old run evidence was never overwritten.
- Confirm all report claims have linked evidence and correct approval status.
- Confirm ambiguous and timeout fixtures do not generate confirmed vulnerabilities.
- Check packaging, upgrade migration, CLI help, and documentation.
- Record unfinished work, risk acceptance, and test limitations.

---

## 9. Reporting cadence for Codex

After each implementation milestone, provide a concise structured progress summary:

```text
Completed task IDs:
Files changed:
Behavior implemented:
Evidence and false-positive guards:
Tests executed (exact commands):
Results (pass/fail/skip):
Compatibility or migration risks:
Open blockers:
Next recommended task:
```

**Do not claim tests passed when not run. Do not claim a scanner finding is confirmed without specific supporting evidence and reviewer approval. Do not claim a missing observation is proof of remediation.**

---

## 10. Final instruction to Codex

**Begin now by auditing the checked-out ScanRunner repository and producing `AUDIT.md`. Then reconcile this plan with the actual code and start P0 tasks in the safest dependency order.** Treat the checkboxes as the single living project backlog. Do not try to complete everything in one large commit. Favor correctness, provenance, defensible evidence, clear `Inconclusive` states, explicit analyst verification, and regression safety over the number of new integrations.

**The desired result is a reliable VAPT assistant, not a tool that generates confident-looking but unverified findings.**


## Checkout progress (2026-11-12)
See AUDIT.md for the baseline source audit, verification limits, and prioritized migration. Baseline tests could not start: no usable Python interpreter found. All acceptance checkboxes remain unchecked. Repository copy is the living backlog; the original Downloads document is unchanged.


### Increment 1 verified
SR-P0-02 accepted: synthetic fixtures and offline Windows-compatible scanner mocks; regression-tests.log records 98 tests, 97 passed and 1 explicit real-Nmap opt-in skip. See AUDIT.md for exact command, baseline failures, scope limits and compatibility notes. P0-01 remains in progress; all other tasks remain unchecked. Missing-port diff wording fixed conservatively; P1 retest acceptance remains unmet. The earlier Python blocker is resolved by the approved per-user installation. Next: SR-P0-03.

### Increment 3
SQLite run/job/target state, transactional claims, bounded capture and retries, immutable evidence manifests, fingerprint/hash resume gates, shared concurrency ceilings, secure storage, injection guards and compatibility tests are implemented. See AUDIT.md and verification-p0-release.log for test evidence. P0-12 remains pending the first CI execution across all operating systems.

## Deep audit and improvement report, 2026-11-12

DEEP_AUDIT_SCORECARD.md records the independent assessment. The pushed baseline has 121 passing regression tests and one gated integration test, while 16 of 26 targeted audit checks pass. Ten failing checks remain open. These measurements do not establish real-world vulnerability accuracy. SR-P0-04, SR-P0-06 and SR-P0-08 are reopened for authorization/impact, completion semantics and traffic-control limitations. IMPROVEMENT_REPORT.md describes corrections, future upgrades, optional integrations, drawbacks, acceptance criteria and accuracy benchmarking. No P1/P2/P3 task is accepted as complete by these reports.

### Subsequent CI evidence
CI run 43225397121 passed five of six jobs on unchanged application/test source. Windows/Python 3.10 reproduced an intermittent tab-export failure with four inventory rows instead of six. DA-11 is documented in the scorecard and improvement report. SR-P0-11 and SR-P0-12 are reopened alongside the existing scope/impact, completion and concurrency work. The 26-check audit score remains fixed at 16/26.

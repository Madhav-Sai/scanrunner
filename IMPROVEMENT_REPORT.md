# ScanRunner improvement and integration report

This report recommends the next upgrades based on the 2026-11-12 deep audit of pushed implementation `ffef34b`. The evidence, ten reproduced findings and score methodology are recorded in `DEEP_AUDIT_SCORECARD.md`. Recommendations below are proposed work and require their own implementation and acceptance evidence.

The measured local baseline is 121 passing regression tests, one gated integration test and 16 passing independent audit checks out of 26. An earlier CI matrix passed all six jobs, while the latest observed run passed five of six and exposed an intermittent Windows export failure. Real-world vulnerability precision and recall remain unmeasured. The immediate priority is reliable interpretation of evidence and authorization, followed by the analyst workflow and individually reviewed optional adapters.

## Current drawbacks and required improvements

| Drawback | Effect on an assessor | Recommended improvement | Priority / backlog |
| --- | --- | --- | --- |
| Background-tab export can finish with four rows instead of six in Windows CI | Valid scanned observations can disappear from the derived inventory | Retain failing fixture artifacts, reproduce concurrent interleavings and repair the export transaction with repeated cross-platform validation | Immediate, DA-11 and SR-P0-08/11/12 |
| Empty NetExec output can be marked complete | Failed coverage can look successfully tested | Require associated, parseable evidence before completion and classify empty, timeout, partial and inconclusive outcomes | Immediate, DA-01 and SR-P0-06 |
| Contradictory or generic NetExec messages become definite values | False-positive candidate observations and avoidable analyst work | Preserve source lines, recognize version-specific result semantics and retain contradictory facts for review | Immediate, DA-02/03 and SR-P2-02 |
| Result rows can admit unsolicited hosts or mix SMB/RDP facts | Wrong affected assets, ports and remediation instructions | Associate every observation with engagement, requested target, actual IP, protocol, port, run and check | Immediate, DA-05/06 and SR-P1-01/04 |
| Authentication-capable NSE passes the default policy | Scan impact can exceed the documented credential opt-in | Classify each script's behavior and require explicit authorization for authentication-capable selections | Immediate, DA-04 and SR-P0-04 |
| XML parsing validates structure more thoroughly than field semantics | Malformed ports or contradictory host counts can appear valid | Validate numeric ranges, transports, states, counters and associated subjects before parser success | Immediate, DA-07/08 and SR-P0-06/10 |
| Storage completion trusts caller flags | Future adapters can bypass the intended evidence gate | Require tool-specific artifacts, validator identity/version and an immutable validation record | Immediate, DA-09 and SR-P0-06/09 |
| Four advertised profiles fail execution policy | A listed workflow can stop before scanning | Define reviewed profiles with matching help, argv, privileges, side effects and risk classifications | Next, DA-10 and SR-P0-11 / SR-P1-12 |
| A full analyst approval and retest workflow remains unfinished | Client-ready conclusions lack a complete review trail | Add finding decisions and retest events with reviewer identity, UTC time, supporting evidence and explicit comparability | Next, SR-P1-06/08/09 |
| Benchmark coverage is synthetic and tool execution is mocked | Real scanner compatibility and accuracy have unknown limits | Add separately authorized controlled-lab validation with independently established ground truth | Next, SR-P1-05 and CI expansion |
| CLI subprocess branch coverage is unmeasured | Passing tests can leave substantial execution paths unexamined | Measure child-process coverage and add semantic/mutation tests for the critical gates | Next, SR-P0-12 |
| Immutable evidence and repeated legacy snapshots consume disk | Large engagements can exhaust storage | Add storage estimates, free-space checks, explicit archive/export operations and retention policies that preserve original evidence during normal workflows | Later, SR-P0-09 and lifecycle work |
| Current code combines CLI, policy, execution, state and reporting | Changes to one workflow can affect others | Extract modules around tested interfaces as features stabilize, with compatibility and installer payload tests | Incremental engineering work |

Nmap documents that `--max-rate` controls port scanning and host discovery, while other features use their own timing. ScanRunner currently describes its rate budget broadly. Update the wording and define separate controls for version detection, NSE, tool jobs and HTTP requests. Verify effective traffic in a controlled lab before advertising an aggregate all-traffic ceiling. This is an additional documented design limitation, outside the frozen 26-check score. [Nmap timing documentation](https://nmap.org/book/man-performance.html)

Record the ScanRunner version, parser version, rule-pack version, configuration schema version and validation-policy identity with each run. The present fingerprint captures many command and scope inputs, but application/parser provenance also needs an explicit upgrade policy. After parser changes, revalidate preserved evidence under the new parser and record a new interpretation event. Keep the original interpretation available for review.

## Prioritized upgrade sequence

| Stage | Deliverable | Dependencies | Acceptance evidence | Relative effort |
| --- | --- | --- | --- | --- |
| 1. Core corrections | Resolve DA-01 through DA-09 plus DA-11, and clarify traffic-control semantics | Existing state, scope and evidence code | All applicable independent audit checks pass, with failures converted into mandatory regressions and stable cross-platform export results | Medium |
| 2. Profile and packaging repair | Reconcile every advertised profile with policy and ship consistent CLI/help/completion/install payloads | Stage 1 policy classification | Every advertised profile has a valid preview or an explicit availability explanation, with native payload tests | Small to medium |
| 3. Accurate inventory | Finish normalized asset/service observations, historical import and persistent assessor metadata | Validated evidence and subject identity | CIDR, DNS multi-answer, IPv4/IPv6, transport/state and cross-host association round trips | Medium |
| 4. Findings and review | Introduce conservative rule candidates, review decisions and technical finding templates | Stable observation schema and rule evidence definitions | Each rule passes positive, negative, ambiguous, malformed, contradictory and mismatched-subject cases, with approval gates tested | Large |
| 5. Retesting and reporting | Equivalent-evidence comparison, coverage summaries, executive/technical views and optional XLSX | Stable finding identity and review history | Host-down, missing-port, failed-scan and missing-check cases cannot become verified remediation | Medium to large |
| 6. Optional adapters | Add one optional tool at a time through a common contract | Stages 1 through 5 | Availability, argv, impact, scope, version, parser, timeout and contradiction tests for each adapter | Medium per adapter |
| 7. Operational enhancements | Local TUI, scheduling, privacy-safe sharing, trends and attestations | Stable CLI and accepted adapters | CLI parity, reauthorization, redaction, coverage-aware trends and artifact-binding tests | Medium to large |

Effort is a relative engineering judgment. It does not include a delivery-date commitment. The master plan remains the canonical checkbox backlog. New report recommendations should be linked there as they are accepted, implemented and tested.

The uncommitted P1 inventory module already has tests for exact states, evidence links, metadata persistence, imports and assessor-approved address aliases. It still needs its full integration and release review. Complete and review that increment before marking its acceptance criteria satisfied.

## Findings, false positives and retest design

Keep four durable layers for raw evidence, normalized observations, candidate findings and analyst-approved findings. Retain severity, confidence, verification status and business impact in separate fields. Keep unknown values explicit in every export.

Every candidate should contain the affected asset/service, check ID and version, exact raw artifact hash, evidence location, observed time, preconditions, contradictory observations, test limitations and remediation references. An analyst decision should append a review event containing the reviewer, timestamp, supporting evidence and decision rationale.

Use rule-specific evidence standards.

| Check family | Required evidence before a strong claim | Important drawbacks to guard against |
| --- | --- | --- |
| SMBv1 and signing | Negotiated dialect and the signing requirement for the correct endpoint | Port 445 exposure, enabled-versus-required ambiguity and conflicting dialect results |
| RDP NLA | A check that distinguishes required NLA from supported security mechanisms | CredSSP availability or an open RDP port being interpreted as enforcement status |
| TLS protocols and ciphers | Successful negotiation of the reported condition on the correct endpoint/SNI | Failed probes, different virtual hosts and parser labels being treated as handshake proof |
| TLS certificates | Separate checks for validity dates, hostname, chain trust and observation time | One trust failure being relabeled as every certificate issue |
| SSH algorithms | Supported algorithm negotiation or documented enumeration with endpoint identity | Banner-only CVE attribution and vendor patch/backport uncertainty |
| DNS recursion | An authorized recursion test with validated response semantics | Confusing authoritative answers, port exposure and recursive service behavior |
| Anonymous FTP | An explicitly authorized authentication attempt and a specific successful response | Banner inference or generic success markers |
| Management exposure | Exact observed service/port state and tested scope | Counting exposure alone as a confirmed vulnerability |

Retests need the same control/check identity, applicable asset identity, protocol/port and comparable execution conditions. Store old and new evidence plus an explicit comparability decision. Preserve outcomes for still present, potentially remediated, verified remediation, not retested, inconclusive and unable to assess. Asset address changes should use an assessor-reviewed identity mapping and retain the previous addresses and evidence.

## Measuring accuracy honestly

Publish metrics per supported rule and scanner/parser version. A single test pass rate cannot establish vulnerability detection accuracy.

1. Build a labeled corpus with positive, negative, ambiguous, timeout/partial, contradiction and wrong-host/port/protocol cases for every rule. Record fixture origin, sanitization, expected result and raw SHA-256.
2. Establish ground truth independently of the parser being tested. Use reviewed control configuration and protocol-level evidence in an expressly authorized isolated lab.
3. Use protocol-specific lab services for SMB dialect/signing, RDP NLA, TLS/SNI/certificates, SSH algorithms, DNS recursion and FTP authentication. Keep public and client targets outside development tests.
4. Keep a held-out corpus of tool versions and service implementations to measure generalization beyond the fixtures used to implement a rule.
5. Report true positives, false positives, true negatives, false negatives, inconclusive results, not-tested cases and affected-subject association errors. State the sample sizes and confidence intervals.
6. Report precision and recall for the defined decision policy. Publish abstention and coverage alongside them, including how many known positive cases produced inconclusive results.
7. Test candidate interpretation separately from analyst-confirmed totals. Explicitly test that negative and ambiguous fixtures cannot enter confirmed totals through automated paths.

The first release gate should require zero unjustified automatic confirmations in the defined negative/ambiguous test corpus, complete mandatory regression execution, successful artifact verification and passing subject-association checks. Product accuracy claims should state the measured rule set, dataset, versions, sample sizes and limitations. The master plan's prohibition on a universal zero-false-positive promise remains applicable.

## Optional integrations

All proposed tools remain separately installed and explicitly enabled. Each adapter needs a supported-version list, binary/version identity, scope validation, impact preview, bounded execution, raw evidence capture, parser compatibility tests and candidate-only default output. Missing adapters should leave core scanning usable.

| Integration | Benefit | Risks / drawbacks | Recommended order and acceptance gate |
| --- | --- | --- | --- |
| Nmap | Core network/service inventory and selected protocol checks | NSE behavior, incomplete XML, tool upgrades and timing semantics | Maintain first. Repair field semantics and profile policy, then validate supported real versions in a controlled lab |
| NetExec | Scoped SMB/RDP/AD observations | Human-readable output drift, authentication side effects, contradictory lines and tool-owned local state | Repair the existing adapter before expanding it. Require strict result association and documented authentication outcomes |
| testssl.sh | More detailed TLS protocol, cipher and certificate evidence | Repeated handshakes can increase load, SNI matters, and output compatibility needs explicit testing | Add after the adapter contract. Parse structured output, pin the tested release and preserve conflicting probes |
| ProjectDiscovery httpx | HTTP status, headers, titles and service metadata | Redirects, DNS changes, virtual-host/SNI handling, sensitive response data and target-expanding probes | Add a bounded metadata mode. Validate socket destinations, constrain requests and test off-scope redirect rejection |
| Nuclei | Reviewed template-specific candidate observations | Template changes, broad defaults, external callbacks, disruptive checks and uncertainty in match interpretation | Add later. Require pinned reviewed templates, explicit impact approval and analyst confirmation |
| Offline CVE/advisory data | Traceable references and potential applicability assessment | Banner ambiguity, vendor backports, stale data and unsupported applicability | Add as optional local imports with source/version/currency records. Correlations remain candidate observations |
| Optional XLSX library | Practical workbook exports for inventory, findings, coverage and retests | Formula injection, extra dependency maintenance and workbook-import XML risks | Use an optional tested library and round-trip schema/escaping tests. Keep core exports independent |
| Local notification/scheduler adapter | Explicit queued jobs and privacy-safe completion messages | Expired authorization, unintended repetition and exposure of client details | Add after authorization dates and scope versions are enforced at each scheduled execution |

The testssl.sh project documents TLS/SSL testing and JSON/CSV capabilities. Review its supported output schema and bundled/runtime dependencies for the selected release before implementation. Its website could not be retrieved by the research tool, so this recommendation uses the official repository. [testssl.sh project](https://github.com/testssl/testssl.sh)

ProjectDiscovery httpx documents JSONL output, rate/concurrency controls, allowed/denied addresses, redirect options, custom SNI and update-check controls. Its TLS-domain and CSP-domain probing options can expand target selection. The proposed adapter should disable expansion, redirect following and automatic update checks in its default local mode. Validate every destination and retain Host/SNI provenance. Collect only the response fields needed for the assessment. [httpx documentation](https://docs.projectdiscovery.io/opensource/httpx/usage)

Nuclei documents automatic template updates, optional code/headless/fuzzing modes and Interactsh support. A ScanRunner adapter should select explicit local templates, record their hashes, disable automatic updates and external interaction, cap requests and keep matches unverified until review. Template protocol and destination validation also need independent tests. [Nuclei documentation](https://docs.projectdiscovery.io/opensource/nuclei/running)

The CVE Program provides official CVE JSON data suitable for manually versioned local reference datasets. Preserve applicability uncertainty and vendor context with any correlation. FIRST's EPSS data can later provide a separately labeled prioritization signal for already identified CVEs, with an explicit data date and local snapshot identity. [CVE List data](https://github.com/CVEProject/cvelistV5), [FIRST EPSS](https://www.first.org/epss/)

openpyxl supports XLSX read/write workflows and documents XML security considerations. If selected, pin a tested version and treat workbook import as a separate input-validation feature. Export tests should inspect cell types and ensure hostile strings remain text. [openpyxl documentation](https://openpyxl.readthedocs.io/en/stable/)

## Reporting, usability and maintenance upgrades

Provide engagement-scoped technical inventory, candidate/confirmed findings, evidence references and coverage summaries in CSV, JSON, HTML and optional XLSX. Keep tested, unreachable, failed, skipped, inconclusive and not-tested counts visible. Severity summaries should use appropriately approved findings, with draft candidates labeled separately.

Add stable JSON schemas and schema versions. Test row counts, exact states, IPv4/IPv6, timestamps, host/port/protocol association, Unicode, HTML escaping and spreadsheet formulas. Add a privacy-safe export preview with a field allowlist, anonymized asset identifiers and explicit treatment of usernames, notes, tokens, response bodies and raw artifact paths.

Retain the CLI as the primary interface. Add consistent filtering by engagement, asset/IP/CIDR, hostname, owner/site, service, port, protocol, run and finding/retest state. An optional local TUI can reuse these operations once the CLI contracts are stable. Preserve non-interactive behavior and clear exit/status semantics for automation.

Improve durability with explicit schema migrations, transactional metadata updates, interruption/error recovery and verification of imported evidence. Separate immutable raw evidence from derived views. Storage cleanup should offer a manifest-based preview and require explicit authorization for deleting original evidence.

Publish a support matrix for Python, operating systems, Nmap/NetExec versions and optional adapters. Add controlled installation/completion tests and complete payload checks for companion modules. Kali-specific scanner behavior, network-share permissions, long paths and dual-stack hostname execution need explicit validation.

Expand quality checks with child-process line/branch coverage, mutations of the completion/approval gates, property-based parser inputs and resource-failure tests. Exercise concurrent writers, crash recovery, permission errors, disk exhaustion and corrupt caches. Retain sanitized fixture directories and child console logs on CI failure before cleanup so intermittent races can be investigated. Add deterministic synchronization points for writer-interleaving tests and repeated Windows stability runs. Track per-rule false-positive reports as new regression fixtures.

Longer-term upgrades can include declarative versioned rule packs, coverage-aware asset trends, reusable engagement/report templates and optional signed or attested manifests linking reports to evidence and reviewer decisions. Each should enter the master backlog with a clear user benefit and measurable acceptance criteria.

## Release checklist

- Resolve the reproduced high-priority interpretation and authorization findings.
- Pass the independent audit gate and the mandatory regression/packaging suite.
- Reconcile profile help and defaults with actual executable behavior.
- Verify imported and executed evidence origins, hashes and parser versions.
- Complete analyst approval and equivalent-evidence retest gates before final finding exports.
- Publish supported scanner versions and the measured accuracy/coverage limitations.
- Validate redaction, report schemas and exact affected-subject association.
- Keep optional integrations explicitly enabled, locally bounded and separately tested.
- Record remaining drawbacks and open blockers in the scorecard and master plan.

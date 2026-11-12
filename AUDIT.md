# ScanRunner baseline audit

Date: 2026-11-12. Source audit of checkout version 1.3.0. No scanner executed.

## Architecture and compatibility baseline

The application is a standard-library, single-file CLI (`scanrunner.py`); installation and shell completion live in `install.py`. There is no package manifest, database, migration system, or CI configuration in this checkout. Tests use unittest (`tests/test_scanrunner.py`, `tests/test_workflow.py`). No repository AGENTS.md was found.

CLI: mutually exclusive `-f/--file` and `-i/--ip`; raw Nmap arguments, `--profile/--template/--preset`, exclusions, `--yes`, `--resume`, `--skip-ping`, `-ok/--skip-no-ping`, `--scope-file`, retries, parallel workers, terminal tabs, output directory, metadata CSV, HTML export, split modes, focused help/completion, `--status`, and `--diff`. Preserve this interface unless a safety change is explicitly documented. Nmap output defaults to results; NXC defaults to the current directory. Output paths and JSON keys are existing compatibility contracts.

## Feature verification map

Verified here means present in source, not runtime acceptance verified.

| Reported feature | Source evidence | Verification limits |
| --- | --- | --- |
| Nmap orchestration/custom argv | parse_args, preprocess_argv, _build_nmap_command, run_nmap_scan, run_nmap_quiet | Existing CommandTests and end-to-end tests; not executed successfully here |
| NetExec | run_nxc, parse_nxc_output, nxc_table_columns | NxcParsingTests/NxcEndToEndTests; textual output is not a verified vulnerability |
| Profiles/templates | SCAN_PROFILES, print_template_catalog | Ten existing profiles; vuln uses broad NSE category; no impact authorization gate |
| Multi-host/parallel | main, ThreadPoolExecutor, run_nmap_quiet | ParallelEndToEndTests; no durable job claim |
| Terminal splitting | offer_terminal_tabs, _launch_tabs, _spawn_* | TerminalTabTests/TabEndToEndTests; native launch behavior unverified |
| Resume/skip/rescan/failures | previously_completed, get_file_status, main, OUTCOME_LOGS | SerialEndToEndTests; completion fingerprints absent |
| Scope file | load_scope, target_in_scope, _scope_networks | Scope tests exist; enforcement incomplete (below) |
| XML parsing | _hosts_from_xml, parse_nmap_hosts | Per-host IPv4/IPv6 handling; malformed XML falls back silently |
| CSV/JSON inventory | inventory_rows_for_target, write_inventory | Existing fields: target, host, hostname, owner, environment, port_service, version |
| HTML | render_html_report | Values escaped with html.escape; no coverage or approval model |
| Status/diffs | print_status, diff_open_ports, print_diff | ReviewCommandTests; missing ports misleadingly described as closed |
| Installer/completion/OS | install.py install_unix_launcher/install_windows_launcher/install_completion; RAW_MODE_SUPPORTED | Linux/macOS/Windows branches present; packaging/install behavior unverified |

Reviewed README.md, RELEASE_NOTES.md, ADDON-NOTES.md, scanner entry points, execution/parser/report/state helpers, installer and test sources. README/release notes describe capabilities, not acceptance evidence.

## Confirmed source-level defects and reproduction recipes

These recipes require runtime regression tests before fixes are accepted.

1. Scope fails open for empty lists: target_in_scope begins `if not scope or target in scope: return True`. A blank explicit scope file therefore authorizes any input. Missing scope also disables validation. Priority P0-03.
2. DNS scope validation checks one address: resolve_scan_target collects answers but returns only addresses[0]. A mixed authorized/unauthorized answer set can pass. Exact hostname membership bypasses resolution. Validation is separate from scanner execution and NXC can resolve again. Add mocked A/AAAA, changed answer, failed lookup and mixed-answer tests; pin approved destinations. P0-03.
3. Evidence overwritten on retries/rescans: _build_nmap_command always writes the same target .txt/.xml paths; run_nmap_quiet writes .error.log with w and deletes it on success. Tests explicitly simulate overwriting interrupted rescans. P0-05/09.
4. Completion can lack evidence: previously_completed trusts completed logs when reports are absent and uses report footer/time rather than command/tool/scope fingerprint. get_file_status does not require associated parseable XML. P0-06.
5. Unbounded subprocesses: run_nmap_quiet subprocess.run and run_nxc output iteration have no overall timeout; wrapper ping also lacks a process timeout. Review cancellation and descendant cleanup across platforms. P0-07.
6. Unsafe shared-state lock: _FileLock removes a lock after waiting regardless of whether its owner is alive. A slow writer can lose exclusivity; JSON/CSV files are rewritten in place. Log timestamps have only local second precision. P0-05/08.
7. False-positive retest wording: diff_open_ports computes set subtraction without equivalent coverage and print_diff calls removed entries `now closed`. Scanning a different port subset reproduces this misleading conclusion. Existing ReviewCommandTests even expects that phrase. Missing observation is not closure or remediation. P0 safety regression / P1-08.
8. Spreadsheet risk: write_inventory and run_nxc write scanner/user strings directly to CSV without formula neutralization. P0-10/P1-10.
9. Windows launch uses shell=True in _spawn_windows_terminal fallback. Audit quoting with malicious titles/paths; do not assume argument-array protection applies to that branch. P0-10.

## Risks and prioritized gaps

XML parsing uses ElementTree directly; entity-expansion/resource limits need negative fixtures, not an unsupported claim of external-entity exploitability. sanitize_filename only replaces colon/slash; prove target validation and path containment before trusting paths. Arbitrary scanner options, NSE scripts, NXC modules and credential requests require a scope/impact policy. Existing null-auth query adds empty credentials; do not broaden credential operations. Parsed NXC output may mix protocols or contradictory lines; no provenance or verification model currently exists.

Inventory intentionally includes only exact open states (does not convert open|filtered into open), but discards other port states and script evidence. Missing/failed/partial results need explicit coverage labels. There are no confirmed-finding totals or analyst approval gates to validate yet; do not introduce detectors before those exist.

## Tests and environment blockers

Attempted exact command: `python -B -m unittest discover -s tests -v`.
Result: exit 1 before discovery; Windows reports Python not found / Microsoft Store execution alias. No test passed or failed: the suite did not start. `py` is unavailable; python3 is also a WindowsApps alias; common Python/Conda install directories were not found. `wsl --list --quiet` reports WSL is not installed. No dependencies or system settings were changed.

The full suite must be reviewed before execution: workflow fixtures are POSIX shebang executables and may not launch on native Windows. RealNmapTests currently runs a localhost listener scan whenever Nmap is installed; make real scans separately opt-in and keep baseline fixture-only. TargetTests.test_resolution_timeout_or_success_contract already mocks socket.getaddrinfo. Workflow child DNS is now also blocked by the offline runtime harness. These are test-harness gaps, not grounds to skip required tests.

## Incremental migration and next tasks

1. P0-02: create synthetic fixture files and offline test selection; mock DNS and scanner launches. Cover normal/empty/truncated/broken XML, scripts, IPv4/IPv6/CIDR, mixed DNS, TCP/UDP ambiguity, down/filtered, timeout/nonzero process exits. Require positive/negative/ambiguous/contradictory associations before any finding rule.
2. P0-03: implement fail-closed explicit scope, exclusions and all-answer DNS validation with execution-time destination pinning and option restrictions. Document intentional safety incompatibilities.
3. P0-04: zero-network preview before binary checks, DNS, directory creation, or process launch; show unresolved names honestly rather than invent addresses.
4. P0-05/09: immutable run/attempt directories plus transactional SQLite state and evidence hashes; preserve legacy files as historical imports and retain legacy export compatibility views. Never rewrite originals during migration.
5. P0-06/07/08: validated outcomes, consequential-option fingerprints, bounded process lifecycle and transactional claims; crash/concurrency tests before enabling retries on the new store.
6. P0-10/11/12: negative security tests, CLI/install compatibility and offline CI. Do not advance to optional integrations while core safety is incomplete.

## Milestone status

P0-01 audit artifact prepared; acceptance remains pending runtime baseline and full source review of remaining paths. All implementation checkboxes remain unchecked. No application code changed; no live public/client/local scans performed; no earlier run evidence modified. Next action requires a usable Python runtime and approved workspace writes. No claim of zero false positives is made.


## Verified increment 1

The earlier environment-blocker and milestone paragraphs above record the initial audit state. The user approved per-user Python installation; winget installed Python 3.12.10. The interpreter is C:\Users\MadhavaRaoR\AppData\Local\Programs\Python\Python312\python.exe. No scanner was installed.

Baseline invocation: that interpreter with `-B -m unittest discover -s tests -v`, PYTHONUTF8=1. `baseline-tests.log`: 93 tests, 10 failures, 1 error, 1 skip; 81 passed. All failures/errors stemmed from unavailable POSIX fixture executable launch on Windows. This is retained baseline evidence, not a passing baseline.

P0-02 implementation: workflow child processes now load test-only offline_runtime/sitecustomize.py via a temporary test environment. Scanner executable lookup and launch use Python fixture scripts on Windows and POSIX; shell/GUI/other executable launches and child DNS are blocked. RealNmapTests requires explicit SCANRUNNER_TEST_REAL_NMAP=1 as well as Nmap. Synthetic fixtures cover scripts, IPv4/IPv6, CIDR, DNS answer sets, port ambiguity, down hosts, malformed/partial XML, NetExec ambiguity and process failures. Empty output is created directly in tests. No real scan was run. The localhost integration is intentionally excluded from offline acceptance, not silently counted as passed. POSIX execution of the repaired harness remains unverified on this Windows host.

False-positive guard: missing ports now display `no longer observed open`, with an explicit coverage limitation. JSON retains the legacy closed key and adds closed_interpretation plus coverage_comparability. This is a safety correction, not completion of equivalent-evidence retesting (P1-08/09 remain open). Existing data keys and filenames remain compatible; terminal wording intentionally changes. Regression tests cover differing coverage and missing hosts, exact-open versus open|filtered, malformed evidence, failed processes and absence of automatic confirmation. No finding rule was introduced; full future rule approval gates remain pending.

Exact final test command (PowerShell):
`$env:PYTHONUTF8='1'; & 'C:\Users\MadhavaRaoR\AppData\Local\Programs\Python\Python312\python.exe' -B -m unittest discover -s tests -v`

Result retained in regression-tests.log: 98 tests, 97 passed, 1 explicitly gated localhost integration skipped, no failures/errors. Intermediate offline-tests.log records 93 tests/92 pass/1 skip; fixture-tests.log records 97 tests/96 pass/1 skip. `git diff --check` passed. No client/public scans, original evidence changes, or commits. Packaging and native terminal integrations remain unverified. P0-01 remains open for completing exhaustive source review; P0-02 accepted for synthetic offline fixture coverage. Next: P0-03 execution-time all-answer scope validation and approved destination pinning; current production scope/state risks still apply.

## Verified increment 2

P0-01 baseline audit accepted after source review of CLI routing, serial/parallel execution, terminal launch/progress, resume, parsing, exports, NetExec, installation and existing tests. Baseline failures and subsequent fixture-only passing runs are retained above. The feature map references the implementation and tests for every reported existing feature.

P0-03 scope enforcement uses ScopeGuard for initial all-answer validation and execution-time revalidation/pinning before Nmap, ping and NetExec. Empty explicit scopes, failed DNS, changed answers, out-of-scope destinations, exclusion overlap, invalid target paths, extra target arguments, unreviewed NSE scripts, arbitrary NXC modules and credential operations without explicit opt-in are refused. Absent --scope-file uses the explicit requested target set as authorization. Mixed IPv4/IPv6 hostname answers require separate address targets because Nmap selects one address family per process. CIDRs overlapping exclusions are rejected conservatively. Listed hostname authorization accepts its initial complete answer set and rejects subsequent changes. Networks alone require every answer to fit the authorized networks.

P0-04 adds --dry-run/--json, producing JSON with exact planned argv, target, scope status, tool, profile, required privilege information, traffic impact, side effects and destinations. DNS-dependent destinations are explicitly deferred. Preview does not resolve DNS, check scanner binaries, create output directories or spawn processes. Tests assert these conditions for IPv4, IPv6 and hostname targets.

Compatibility changes are intentional safety restrictions. Arbitrary scanner argument passthrough is now limited to reviewed flags and scripts. Existing vuln/full-fast/web-enum definitions contain unreviewed actions and are refused during execution until replacement reviewed profiles land. Arbitrary NXC modules are refused. Credential operations require --allow-intrusive plus --authorization-note. --exclude entries intersecting a requested CIDR require the assessor to split that target into permitted subranges. Final client findings and retest verification gates remain pending.

Verification used the Python312 interpreter with `-B -m unittest discover -s tests -v`, PYTHONUTF8=1 and PYTHONDONTWRITEBYTECODE=1. verification-scope-final.log records 104 tests, 103 passed and 1 explicit real-Nmap opt-in skip. All processes and DNS in workflow tests used fixtures. Earlier verification-scope.log records expected failing old permissive assertions before migration. No real scanner ran. Next dependencies are P0-05/09 durable runs and immutable evidence, followed by completion fingerprints and subprocess lifecycle.

## Increment 3 durable state and execution

P0-05 through P0-11 are implemented. SQLite WAL transactions and busy handling record engagement scope snapshots, configuration fingerprints, unique run/job IDs, requested targets and DNS mappings, status events, timestamps, exit codes, parser success, capacity leases and artifact directories. Resume requires the latest equivalent job to have a validated process/XML result and intact evidence hashes. Legacy completion logs cannot satisfy the new gate. Existing text/XML paths remain report caches. Original legacy bytes are copied into the immutable attempt directory before each cache replacement. Every attempt and retry receives a new directory.

Raw stdout/stderr are captured as exact bytes. Commands, scanner versions, executable hashes, UTC timestamps, configuration and SHA-256 artifact manifests are preserved. --history and --verify-evidence review these records locally. Private state is stored in OUTPUT/.scanrunner. Unix permissions restrict it to the owner. Windows applies a protected inherited DACL for owner, SYSTEM and administrators using the documented SetFileSecurityW and SDDL APIs. Public report files remain in the selected output directory. Review the output directory's sharing permissions before deliberately sharing exports.

Managed capture bounds timeouts, retries and backoff. POSIX supervisors monitor worker lifetime and terminate their scanner process group if the worker dies. Windows starts a suspended scanner in a job object, then resumes it after containment, with descendants terminated on job close. Tests exercise exact bytes, timeout, cancellation, descendant cleanup and abrupt worker death with controlled Python processes. No real scanner is used for those tests. POSIX raw-key controls remain available for Space, Ctrl+X and Ctrl+C. Windows terminal launch falls back to background operation when Windows Terminal is unavailable, avoiding shell execution.

Optional global/per-subnet ceilings use transactional capacity decisions shared by workers and tabs in an output directory. Nmap rates default to an aggregate 100 PPS divided across four global slots. Worker queues have bounded outstanding futures. Duplicate claims are rejected, expired owners become Interrupted and retries create separate evidence. Large CIDRs spanning over 4096 accounting subnets require splitting. Scope/rate policies and resulting options are part of the fingerprint.

Security guards cover XML entity/DTD payloads and parser size, artifact traversal, reserved Windows filenames, CSV formulas, credential argv redaction and export secret patterns. NetExec raw output is preserved privately and its terminal view uses parsed/redacted fields. Hash verification flags missing or corrupted artifacts. The historical public JSON/CSV schemas and installer paths remain available. Safety changes include rechecking legacy reports through a new execution, moving manual mark-done to an acknowledged skip, conservative diff wording and restrictions on unreviewed options/scripts/modules. Raw evidence, source metadata and derived report caches are explicitly distinguishable.

Additional scope review removed http-title and http-headers from executable script selections because Nmap's HTTP library can follow redirects within a domain. Relevant primary documentation is https://nmap.org/nsedoc/lib/http.html and https://nmap.org/nsedoc/scripts/http-title.html. Existing web-oriented templates require the later reviewed profile update. No off-scope HTTP redirect behavior was enabled.

The standalone installer remains the deployment payload. Added installer-copy/completion-idempotence tests and a stdlib syntax/safety-lint/archive check. CI covers Windows, Linux and macOS with Python 3.10 and 3.12, fixture-only tests and CLI/installer help. P0-12 awaits actual CI execution. Local verification-p0-release.log recorded 116 tests, 115 passed and one explicit localhost-integration opt-in skip before the final export-redaction assertion. Final rerun follows before commit. Native terminal UI behavior and actual scanner execution remain outside fixture acceptance.

## CI compatibility correction

The first CI run passed all Python 3.12 jobs on Ubuntu, Windows and macOS. Python 3.10 exposed an existing argparse single-dash abbreviation difference where Nmap -n became -nxc despite allow_abbrev=False. preprocess_argv now removes -n before argparse and forwards it explicitly. The regression test asserts both wrapper-token isolation and scanner passthrough. Local verification-python-compat.log records 116 tests, 115 passed and the explicit localhost opt-in skip. Offline quality checks and git diff --check passed. The next CI run must pass before accepting P0-12.

## NetExec and asynchronous fixture corrections

Primary source review of https://github.com/Pennyw0rth/NetExec/blob/main/nxc/cli.py showed --version deliberately exits 1 and the default target thread pool is 256. Version detection now accepts exit 1 only with a valid observed version line and records that exit code. Scanner jobs constrain NetExec to one target thread, avoiding a hidden high-concurrency default. A negative version-output fixture rejects unrelated failures.

The second CI run passed Ubuntu/macOS on Python 3.10 and 3.12 but exposed a Windows test race. Background tabs log valid per-target completion before their final inventory transaction and run end. The fixture now waits for all durable child runs to end before checking row counts and cleaning up its temporary database. This preserves asynchronous tab behavior and checks the actual export completion condition.

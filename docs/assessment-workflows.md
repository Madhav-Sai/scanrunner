# Assessment workflows

ScanRunner 1.5 adds protocol evidence contracts, optional scanners and local assessment operations. Use `python scanrunner.py COMMAND --help` for each command. Authorization, scope, exclusions and evidence integrity apply before scanning. Findings require explicit analyst review before confirmation.

## Protocol controls

| Control | Evidence | Interpretation limits |
| --- | --- | --- |
| SMB signing and SMBv1 | Structured Nmap negotiation output with a sole supported endpoint | Ambiguous endpoint selection and conflicting dialect settings remain inconclusive |
| RDP NLA | Explicit accepted security layers or non-NLA rejection with `HYBRID_REQUIRED_BY_SERVER` | NLA support alone cannot establish that NLA is required |
| TLS protocols/ciphers | Structured successful cipher enumeration | The policy identifies selected legacy protocols and cipher patterns within enumerated results |
| Certificate validity | Certificate dates compared with the scan observation time | Chain trust and hostname matching remain separate checks |
| SSH algorithms | Explicit offered algorithm lists | Offers indicate configuration. Missing groups or unreviewed algorithms limit negative assessments |
| Anonymous FTP | Direct control-channel USER/PASS replies | A 230 reply supports success and a 530 reply supports rejection |
| DNS recursion | An owned canary answer plus matching nonrecursive control | Requires an explicitly authorized canary name and expected IPv4 answer |
| Management exposure | An observed open management-associated port | Exposure observations require assessment context |

```bash
python scanrunner.py probe ftp-anon --ip 127.0.0.1 --scope-file scope.txt --authorization-note OWNED_LAB --dry-run
python scanrunner.py probe dns-recursion --ip 127.0.0.1 --scope-file scope.txt --canary-name owned.example.invalid --expected-answer 203.0.113.9 --canary-authorized --authorization-note OWNED_LAB --dry-run
python scanrunner.py rules
```

Native probes record raw protocol exchanges and preserve their actual endpoint, including explicitly selected custom ports. The native FTP probe confines its traffic to the control channel. The stock DNS NSE recursion flag remains inconclusive until the controlled answer requirements are satisfied.

New profiles include `safe-baseline`, `ssh-audit`, `dns-audit`, `ad-discovery` and `tls-audit`. TLS cipher enumeration requires `--allow-intrusive --authorization-note AUTH_REF` because it repeatedly negotiates connections. The DNS and AD profiles perform service inventory. Protocol-control verification uses the corresponding explicitly selected check.

## Exports and private sharing

XLSX requires the optional package in `requirements-optional.txt`. Core scanning remains usable without it.

```bash
python -m pip install -r requirements-optional.txt
python scanrunner.py report --output results --format xlsx --destination results/assessment.xlsx
python scanrunner.py inventory --output results --format xlsx --destination results/inventory.xlsx
```

Technical reports include inventory, reviewed findings, coverage, run metadata and retests. Workbook text cells preserve their text type and hostile formula strings stay text. Fields without evidence display `Not determined` or `Not tested`. Earlier confirmed findings require renewed analyst review when the rule revision changes.

```bash
python scanrunner.py attest keygen --key results/.scanrunner/report.key
python scanrunner.py share --output results --key results/.scanrunner/report.key --preview
python scanrunner.py share --output results --key results/.scanrunner/report.key --destination results/shared.json
python scanrunner.py attest sign --output results --key results/.scanrunner/report.key --report results/assessment.xlsx --destination results/assessment-attestation.json
python scanrunner.py attest verify --output results --key results/.scanrunner/report.key --manifest results/assessment-attestation.json
```

Sharing uses keyed pseudonyms and an explicit allowlist of inventory state fields. It excludes free-text metadata, original addresses, hostnames and raw paths. HMAC attestations bind exported report hashes, preserved scan evidence, parser/rule identities and analyst approval records. Identity assurance depends on private key custody and the local review process. Keep keys and engagement evidence in protected local storage.

## Optional scanners

Install each tool separately, then inspect `plugin list`. Execution requires `--enable`, an authorization note, a literal IP URL, scope and an exact expected version. The adapter records the binary identity, raw output and parser identity. Imports preserve their unverified origin.

```bash
python scanrunner.py plugin list
python scanrunner.py plugin run --adapter httpx --target http://127.0.0.1:8080/ --scope-file scope.txt --expected-version 1.12.0 --enable --authorization-note OWNED_LAB --dry-run
python scanrunner.py plugin import --adapter httpx --target http://127.0.0.1:8080/ --scope-file scope.txt --expected-version 1.12.0 --artifact captured.jsonl
python scanrunner.py plugin observations --output results
```

The httpx adapter uses bounded metadata probes and a target IP allowlist. The testssl adapter selects protocol/cipher checks with DNS and external revocation queries disabled. Conflicting TLS records remain visible as inconclusive observations. Nuclei requires `--template`, `--template-sha256` and `--template-reviewed-by`. Supported templates use JSON syntax in a `.yaml` file, one to four GET/HEAD request blocks, literal endpoint-relative paths, and bounded status/word matchers. The adapter isolates configuration, disables updates, template downloads, redirects and external interactions. Matches retain `Needs Verification` status. Empty match output leaves execution coverage inconclusive.

Live integration validation uses pinned httpx 1.12.0, Nuclei 3.11.1 and testssl.sh 3.2.5 in the manually dispatched optional-tool Docker workflow. Runtime identities and actual failures are retained as workflow artifacts. Additional versions require compatibility verification. The core NetExec path also stores normalized observations with raw field/line provenance through `plugin observations`.

## Local assessment operations

```bash
python scanrunner.py tui --output results
python scanrunner.py tui --once --output results
python scanrunner.py trends --output results --group-by site
python scanrunner.py advisory import --output results --path downloaded-cve.json --source https://SOURCE_URL
python scanrunner.py advisory correlate --output results
python scanrunner.py template create --output results --engagement current --path assessment-template.json --view technical
python scanrunner.py template apply --output results --path assessment-template.json --name next-assessment --expires-at AUTHORIZATION_EXPIRY
python scanrunner.py template report --output results --engagement current --path assessment-template.json --format html --destination results/report.html
```

The terminal menu browses inventory, findings, queue/history, evidence and engagements, and delegates reviews and exports to the existing evidence gates. Trend reports preserve individual states, source, import status and coverage. Missing observations require equivalence review before a remediation conclusion.

Advisory support accepts manually downloaded CVE JSON 5 snapshots and records the declared source and snapshot hash. Exact supplied product/package and affected-version matches remain potential applicability observations. Version ranges, vendor identity, configuration, patch status and backports need analyst review.

Schedules require a registered engagement with current scope and an authorization expiry. A definition contains an `argv` list for the core scanner, including matching output/engagement, explicit scope, `--yes` and an authorization note. Input files and scope version are bound when queued and checked again immediately before execution. Each input is copied and verified for the scheduled invocation.

```bash
python scanrunner.py schedule add --output results --engagement current --definition scheduled-scan.json --at SCHEDULED_UTC_TIME
python scanrunner.py schedule list --output results --engagement current
python scanrunner.py schedule run-due --output results --engagement current
python scanrunner.py schedule run-due --output results --engagement current --execute
```

`run-due` previews queued identifiers by default. Execution occurs only with `--execute`, and the queue claim prevents duplicate execution. Completion notifications contain the job identifier and status. The application runs queued work when explicitly invoked, so an operating-system scheduler can call this command under the assessor's account.

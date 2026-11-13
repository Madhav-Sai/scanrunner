"""Task-oriented CLI help and a local-only beginner walkthrough."""
import argparse
import ipaddress
import json
import os
import re
import shlex
import sys
from pathlib import Path

GUIDES = {
    "discover": ("Use optional PingMe to check scoped host reachability before an assessment.", "Download PingMe 3.3.0 separately and prepare scope.txt containing authorized literal IPs/CIDRs.",
        ["discover --target 127.0.0.1 --scope-file scope.txt --pingme-script ../PingMe/pingme.py --authorization-note OWNED_LAB --dry-run", "discover --target 127.0.0.1 --scope-file scope.txt --pingme-script ../PingMe/pingme.py --authorization-note OWNED_LAB -o results", "plugin observations -o results"], "Review reachable, no-response and probe-error results. The output supplies a preview command for a later scan. No response does not prove offline."),
    "engagement": ("Save the authorized scope and owner for an assessment.", "Prepare scope.txt with the IPs or CIDRs you may assess.",
        ["engagement create --name lab --scope-file scope.txt -o results", "engagement show -o results"], "Use the same --engagement lab and -o results on later commands."),
    "inventory": ("See discovered hosts, ports and their exact observed states.", "Run a scan or import an existing Nmap XML file first.",
        ["inventory -o results", "inventory -o results --port 443", "inventory -o results --format csv --destination results/inventory.csv"], "Use report for a complete assessment summary and export."),
    "report": ("Create a readable assessment report with coverage and reviewed findings.", "Select the output folder containing your scan or import.",
        ["report -o results --format html --destination results/report.html", "report -o results --view executive --format html --destination results/summary.html", "report -o results --format xlsx --destination results/report.xlsx"], "Open the exported file. XLSX requires requirements-optional.txt."),
    "observations": ("Read evidence from the checks that actually ran.", "Choose a control profile, such as ssh-audit, or run an authorized native probe.",
        ["observations -o results"], "Copy an observation id into findings create when it needs analyst review."),
    "findings": ("Create, review and export evidence-linked assessment findings.", "Run observations first and copy the observation id you want to review.",
        ["findings create --observation OBSERVATION_ID -o results", "findings list -o results", "findings review --finding FINDING_ID --status 'Needs Verification' --reviewer YOUR_NAME --rationale REVIEW_REASON -o results", "findings history --finding FINDING_ID -o results", "findings export -o results --format html --destination results/findings.html"], "New findings need verification. Use 'scanrunner guide --task findings' for the review sequence."),
    "retest": ("Compare a finding with a later run of the same control.", "Repeat the original control using comparable scope, method and scanner version.",
        ["retest FINDING_ID --run NEW_RUN_ID -o results"], "Review comparability and evidence before explicitly approving remediation."),
    "import": ("Bring an existing Nmap XML scan into the inventory without scanning again.", "Prepare the original XML and a scope file covering its recorded hosts.",
        ["import saved-scan.xml --target 127.0.0.1 --scope-file scope.txt -o results"], "Use inventory to inspect imported hosts. Imported origin requires review."),
    "asset": ("Add your owner, site, tags or notes to an inventory asset.", "Copy asset_id from inventory and prepare a metadata JSON file.",
        ["asset ASSET_ID --metadata asset-details.json -o results"], "Metadata survives later observations of the same asset."),
    "probe": ("Run a specific authorized FTP or DNS control and save raw replies.", "Prepare scope.txt. Record the authorization note for the probe.",
        ["probe ftp-anon --ip 127.0.0.1 --scope-file scope.txt --authorization-note OWNED_LAB --dry-run", "probe ftp-anon --ip 127.0.0.1 --scope-file scope.txt --authorization-note OWNED_LAB -o results"], "Use observations to read the outcome. DNS also requires an owned canary and known answer."),
    "plugin": ("Use separately installed httpx, testssl.sh or reviewed Nuclei templates.", "Run plugin list to check availability, then select an exact tool version.",
        ["plugin list", "plugin run --adapter httpx --target http://127.0.0.1:8080/ --scope-file scope.txt --expected-version 1.12.0 --enable --authorization-note OWNED_LAB --dry-run", "plugin observations -o results"], "Preview first, then remove --dry-run to execute. Nuclei also requires an approved template hash and reviewer."),
    "rules": ("See supported checks, required evidence and interpretation limits.", "This command reads the installed rule catalog.",
        ["rules", "rules --check smb-protocols"], "Choose a scan profile or probe that gathers the required evidence."),
    "trends": ("Compare historical asset and service observations across runs.", "Use an assessment folder with saved history. Add site/subnet metadata to group assets.",
        ["trends -o results", "trends -o results --group-by site"], "Read coverage alongside changes. Approved retests establish remediation."),
    "share": ("Export inventory using pseudonyms and an allowlist of fields.", "Create a private local key with attest keygen after creating the assessment folder.",
        ["share -o results --key results/.scanrunner/report.key --preview", "share -o results --key results/.scanrunner/report.key --destination results/shared.json"], "Review the preview, then share the exported JSON according to your engagement policy."),
    "attest": ("Authenticate report files together with scan evidence and review records.", "Export the report inside results and retain the private key securely.",
        ["attest keygen --key results/.scanrunner/report.key", "attest sign -o results --key results/.scanrunner/report.key --report results/report.html --destination results/attestation.json", "attest verify -o results --key results/.scanrunner/report.key --manifest results/attestation.json"], "HMAC verification depends on private key custody and checks whether the bound files changed."),
    "schedule": ("Queue an authorized scan for a chosen time and run it explicitly.", "Register an engagement with an expiry and prepare a JSON argv definition.",
        ["schedule list -o results", "schedule run-due -o results", "schedule run-due -o results --execute", "schedule recover -o results --id JOB_ID"], "The preview lists due work. --execute runs it after scope, expiry and file checks."),
    "advisory": ("Import manually downloaded CVE JSON and inspect potential applicability.", "Download a CVE JSON 5 record from your selected authoritative source.",
        ["advisory import --path downloaded-cve.json --source https://SOURCE_URL -o results", "advisory list -o results", "advisory correlate -o results"], "Review vendor identity, backports, configuration and patch state for each candidate."),
    "template": ("Reuse engagement scope settings and report views.", "Create a template from an existing engagement. --profile selects scan profiles.",
        ["template create --engagement lab --path lab-template.json -o results", "template report --engagement lab --path lab-template.json --format html --destination results/report.html -o results"], "Applying a template to a new engagement requires a new authorization expiry."),
    "tui": ("Open a terminal menu for inventory, evidence, review and export.", "Choose the folder containing the assessment you want to work with.",
        ["tui -o results", "tui -o results --engagement lab", "tui --once -o results"], "The menu delegates reviews and exports to the same CLI evidence checks."),
    "benchmark": ("Measure rule outcomes against supplied ground-truth labels.", "Select a labeled dataset. The bundled example is a synthetic regression dataset.",
        ["benchmark tests/fixtures/detection-benchmark/dataset.json --destination results/benchmark.json"], "Read precision, recall, coverage and abstentions with their sample counts."),
}

MENU = """ScanRunner {version} - authorized network assessments

New here? Follow one assessment from preview to report
  scanrunner guide
  scanrunner --whats-new

Scan and check progress
  scanrunner discover --help                   Optional PingMe host discovery
  scanrunner -i IP --scope-file scope.txt --profile safe-baseline --dry-run
  scanrunner --list-templates                  Choose a scan profile
  scanrunner --status results                  See completion and failures
  scanrunner --history results                 See saved runs and run IDs

Read results and create a report
  scanrunner inventory --help                  Hosts, ports and filters
  scanrunner observations --help               Evidence from specific checks
  scanrunner findings --help                   Review candidate findings
  scanrunner report --help                     HTML, CSV, JSON and XLSX exports
  scanrunner retest --help                     Check a later remediation run
  scanrunner import --help                     Reuse existing Nmap XML
  scanrunner engagement --help                 Save authorization scope
  scanrunner asset --help                      Add owner, site and notes

Specific controls and optional tools
  scanrunner probe --help                      FTP and controlled DNS checks
  scanrunner plugin --help                     httpx, testssl.sh and Nuclei
  scanrunner rules --help                      Supported checks and limitations
  scanrunner benchmark --help                  Score a labeled dataset

Local workspace tools
  scanrunner tui --help                        Assessment menu
  scanrunner trends --help                     Historical asset observations
  scanrunner share --help                      Pseudonymous inventory export
  scanrunner attest --help                     Report/evidence integrity
  scanrunner schedule --help                   Explicit local scan queue
  scanrunner advisory --help                   Local CVE snapshots
  scanrunner template --help                   Reusable assessment settings

Focused help:
  scanrunner help COMMAND                      Purpose, prerequisites and examples
  scanrunner --nmap -h                         Nmap arguments and workflow
  scanrunner --template -h                     Scan profiles and exact arguments
  scanrunner -nxc -h                           NetExec authorization and queries
  scanrunner --split -h                        Split a target file
  scanrunner --reports -h                      Reporting and automation
  scanrunner --help-all                        Complete option reference
  scanrunner --version                        Installed version

Install Nmap for core scanning. Optional scanners are installed separately.
--dry-run previews a scan. Remove it when you are ready to execute within scope.
"""


OPTION_HINTS = {
    "--output": "Assessment folder containing saved scans and private evidence (default results)",
    "--engagement": "Saved assessment name (default default)",
    "--scope-file": "Text file containing authorized IPs/CIDRs, one entry per line",
    "--destination": "Path of the report or export file to create",
    "--format": "Export type. XLSX requires the optional workbook package",
    "--run": "Run ID from scanrunner --history results",
    "--history": "Include earlier observations as well as the latest ones",
    "--hostname": "Match an observed hostname",
    "--owner": "Assessor-supplied owner name",
    "--site": "Match the asset site stored in metadata",
    "--service": "Match an observed service name, such as ssh or https",
    "--port": "Service port number to select",
    "--transport": "Transport to select, such as tcp or udp",
    "--status": "Select a finding decision or execution state",
    "--view": "Technical includes details. Executive provides a summary",
    "--include-candidates": "Include unconfirmed candidates in a draft export",
    "--observation": "Observation ID copied from the observations command",
    "--finding": "Finding ID copied from findings list",
    "--reviewer": "Name of the analyst making this decision",
    "--rationale": "Explain the evidence and reason for your review decision",
    "--details": "JSON file containing your reviewed finding description, impact and remediation",
    "--approve-preconditions-and-impact": "Explicitly attest that you verified prerequisites and reviewed impact",
    "--trust-import-origin": "Explicitly approve the origin of imported evidence after verification",
    "--key": "Private local key file created with attest keygen",
    "--report": "Previously exported report to bind to this attestation (repeatable)",
    "--manifest": "Attestation JSON file to verify",
    "--preview": "Print the proposed sharing fields and pseudonyms before exporting",
    "--adapter": "Optional scanner integration to select",
    "--target": "Selected target URL for a plugin, or a literal target for import",
    "--ip": "Authorized literal IP of the service to test",
    "--expected-version": "Exact installed scanner version to verify before execution",
    "--enable": "Explicitly enable the selected optional scanner for this invocation",
    "--binary": "Path to the separately installed scanner executable",
    "--artifact": "Original existing scanner output to import",
    "--authorization-note": "Your authorization reference or note for this operation",
    "--template": "Local reviewed Nuclei template file in the supported JSON/YAML subset",
    "--template-sha256": "SHA-256 of the exact template bytes you reviewed",
    "--template-reviewed-by": "Analyst who reviewed the selected template",
    "--dry-run": "Print the proposed operation before sending network probes",
    "--canary-name": "Owned DNS name explicitly authorized for the recursion test",
    "--expected-answer": "Known IPv4 answer for your owned canary name",
    "--canary-authorized": "Attest that the canary query is authorized",
    "--definition": "JSON file containing the scheduled core scanner argv list",
    "--at": "Scheduled ISO timestamp including timezone, for example 2027-01-01T10:00:00Z",
    "--execute": "Run due queued jobs after validating current authorization",
    "--id": "Scheduled job ID copied from schedule list",
    "--path": "JSON snapshot or template path used by the selected action",
    "--source": "Declared HTTPS source of your manually downloaded CVE snapshot",
    "--expires-at": "Authorization expiry as an ISO timestamp including timezone",
    "--group-by": "Group historical observations by current site or subnet metadata",
    "--check": "Check ID copied from the rule catalog",
    "--once": "Print the terminal menu once for noninteractive use",
    "--metadata": "JSON file containing assessor-managed asset fields",
    "--add-address": "Analyst-approved IP alias for the same asset identity",
    "--name": "Name of the engagement to create",
}


class TaskParser(argparse.ArgumentParser):
    def add_argument(self, *flags, **options):
        if "help" not in options:
            for flag in flags:
                if flag in OPTION_HINTS:
                    options["help"] = OPTION_HINTS[flag]
                    break
        return super().add_argument(*flags, **options)


def parser(command):
    purpose, before, examples, after = GUIDES[command]
    epilog = "Before you start\n  " + before + "\n\nExamples\n" + "\n".join("  " + command_line(shlex.split(example)) for example in examples)
    epilog += "\n\nWhat to do next\n  " + after + "\n\nFor the beginner walkthrough, run: scanrunner guide"
    return TaskParser(prog="scanrunner " + command, description=purpose,
                                   epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)


def command_line(arguments):
    from_checkout = Path(sys.argv[0]).name == "scanrunner.py"
    program = [sys.executable, str(Path(sys.argv[0]).resolve())] if from_checkout else ["scanrunner"]
    if os.name != "nt":
        return shlex.join([*program, *arguments])
    prefix = "& " if from_checkout else ""
    return prefix + " ".join(value if re.fullmatch(r"[A-Za-z0-9_./:\\-]+", value)
                              else "'" + value.replace("'", "''") + "'" for value in [*program, *arguments])


def guide(argv):
    options = argparse.ArgumentParser(prog="scanrunner guide", description="Walk through a task using copyable commands. This guide only prints instructions.")
    options.add_argument("--task", choices=["first-scan", "reports", "findings", "optional-tools", "privacy", "schedule"], default="first-scan", help="Choose the job you want to learn")
    options.add_argument("--target", default="127.0.0.1", help="Your authorized IP. Default is your own loopback address")
    options.add_argument("--output", "-o", default="results", help="Folder to use in the examples")
    args = options.parse_args(argv)
    target = str(ipaddress.ip_address(args.target))
    print("ScanRunner beginner guide\n")
    print("Examples use your selected IP " + target + " and output folder " + args.output + ".")
    print("Run these commands in your terminal after preparing their inputs.\n")
    if args.task == "first-scan":
        print("1. Install Nmap and open a terminal in your ScanRunner installation.")
        print("2. Create scope.txt containing this authorized IP on its own line\n   " + target)
        common = ["-i", target, "--scope-file", "scope.txt", "--profile", "safe-baseline", "-o", args.output]
        print("3. Preview the targets, command and traffic limits\n   " + command_line([*common, "--dry-run"]))
        print("4. Run the baseline inventory scan\n   " + command_line(common))
        print("5. Check completion and discovered services\n   " + command_line(["--status", args.output]))
        print("   " + command_line(["inventory", "-o", args.output]))
        print("6. Export a readable report\n   " + command_line(["report", "-o", args.output, "--format", "html", "--destination", os.path.join(args.output, "report.html")]))
        print("   Open report.html in your browser. Review failed or inconclusive coverage.")
        print("7. Choose a control when you need more detail\n   scanrunner --list-templates\n   scanrunner probe --help")
        print("   For SSH algorithm evidence, preview --profile ssh-audit. TLS cipher enumeration also requires explicit authorization.")
        print("\nYour results\n  The output folder contains inventory and reports. Its .scanrunner folder holds private state and original evidence.")
    elif args.task == "findings":
        print("1. Gather a supported control observation using an appropriate profile or probe.")
        print("2. Read the evidence and copy its observation id\n   " + command_line(["observations", "-o", args.output]))
        print("3. Create a candidate and copy its finding id\n   " + command_line(["findings", "create", "--observation", "OBSERVATION_ID", "-o", args.output]))
        print("4. Inspect the candidate\n   " + command_line(["findings", "list", "-o", args.output]))
        print("5. Independently verify the condition, affected endpoint and practical impact. Write your reviewed description, impact, remediation and references in a details JSON file.")
        print("   Optional CVSS scoring requires cvss_vector (a CVSS 3.1 base vector) and cvss_justification. The score is checked from your selected metrics.")
        print("6. Read review options before making the explicit analyst decision\n   scanrunner findings --help")
        print("   " + command_line(["findings", "review", "--finding", "FINDING_ID", "--status", "Confirmed", "--reviewer", "YOUR_NAME", "--rationale", "REVIEW_REASON", "--details", "reviewed-details.json", "--approve-preconditions-and-impact", "-o", args.output]))
        print("   Confirmation requires --approve-preconditions-and-impact and a named reviewer. Imports also require --trust-import-origin.")
        print("7. Run the same control after remediation, then use retest with the new run ID\n   scanrunner retest --help")
    elif args.task == "schedule":
        print("1. Prepare scope.txt and choose the expiry of your actual scan authorization.")
        print("   Replace AUTHORIZATION_EXPIRY with an ISO timestamp including timezone.")
        print("   " + command_line(["engagement", "create", "--name", "lab", "--scope-file", "scope.txt", "--expires-at", "AUTHORIZATION_EXPIRY", "-o", args.output]))
        print("2. Save the following JSON as scheduled-scan.json. Replace YOUR_PERMISSION_REF with your actual authorization note.")
        definition = {"argv": ["-i", target, "--scope-file", os.path.abspath("scope.txt"), "--profile", "safe-baseline",
            "--output", os.path.abspath(args.output), "--engagement", "lab", "--yes", "--authorization-note", "YOUR_PERMISSION_REF"]}
        print(json.dumps(definition, indent=2))
        print("3. Choose SCHEDULED_UTC_TIME with a timezone, such as the format 2027-01-01T10:00:00Z.")
        print("   " + command_line(["schedule", "add", "--definition", "scheduled-scan.json", "--at", "SCHEDULED_UTC_TIME", "--engagement", "lab", "-o", args.output]))
        print("4. Preview the due jobs\n   " + command_line(["schedule", "run-due", "--engagement", "lab", "-o", args.output]))
        print("5. Execute due jobs when authorized\n   " + command_line(["schedule", "run-due", "--execute", "--engagement", "lab", "-o", args.output]))
        print("   Scope, expiry and input hashes are checked again. Use schedule list to inspect results.")
    else:
        tasks = {"reports": ["inventory", "report"], "optional-tools": ["discover", "plugin", "probe"], "privacy": ["attest", "share"], "schedule": ["engagement", "schedule"]}
        for command in tasks[args.task]:
            purpose, before, examples, after = GUIDES[command]
            print(purpose + "\n" + before)
            for example in examples:
                values = shlex.split(example)
                for index, value in enumerate(values):
                    if value == "results":
                        values[index] = args.output
                    elif value.startswith("results/"):
                        values[index] = os.path.join(args.output, value[len("results/"):])
                    elif "127.0.0.1" in value:
                        replacement = "[" + target + "]" if ":" in target and value.startswith(("http://", "https://")) else target
                        values[index] = value.replace("127.0.0.1", replacement)
                print("  " + command_line(values))
            print(after + "\n")
    print("\nNext tasks\n  scanrunner guide --task reports\n  scanrunner guide --task findings\n  scanrunner guide --task optional-tools\n  scanrunner guide --task privacy\n  scanrunner guide --task schedule")
    return 0


def whats_new(version):
    return f"""New in ScanRunner {version}

Optional host discovery
  Scoped PingMe 3.3.0 integration       scanrunner discover --help
  Reachable / no response / probe error, preserved evidence, manual scan handoff.

Understand and review results
  New protocol evidence contracts       scanrunner rules
  Clear candidate/retest fields         scanrunner findings --help
  Excel workbooks                      scanrunner report --help

Gather additional evidence
  Baseline, SSH, DNS, AD and TLS profiles   scanrunner --list-templates
  Controlled FTP/DNS probes                scanrunner probe --help
  Optional httpx/testssl/Nuclei adapters    scanrunner plugin --help

Manage your assessment locally
  Terminal assessment menu              scanrunner tui
  History and site/subnet comparisons    scanrunner trends --help
  Reusable assessment/report settings    scanrunner template --help
  Explicit scheduled scans               scanrunner schedule --help
  Manually imported CVE snapshots         scanrunner advisory --help
  Pseudonymous sharing                    scanrunner share --help
  Report/evidence attestations            scanrunner attest --help

Start with a worked example                scanrunner guide
Live scan output keeps terminal line alignment during keyboard controls.
TLS cipher enumeration requires explicit authorization. Revised rules require
renewed review of previously confirmed findings before final export.
"""

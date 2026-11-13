"""Local sharing, attestation, trends and reusable assessment operations."""
from scanrunner_lib.scanrunner_help import parser as command_parser
from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets

from scanrunner_lib import scanrunner_assessment as assessment
from scanrunner_lib import scanrunner_findings as findings


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_json(path, limit=8 * 1024 * 1024):
    path = Path(path)
    if path.stat().st_size > limit:
        raise ValueError("Input exceeds size limit")
    return json.loads(path.read_bytes())


def output_json(backend, value, destination=None):
    value = assessment.redact_records(backend, value)
    if destination:
        assessment.ensure_export_destination(destination)
        with backend.atomic_text(destination) as file:
            json.dump(value, file, indent=2)
    else:
        print(json.dumps(value, indent=2))


def key_bytes(path):
    raw = Path(path).read_bytes()
    if not 32 <= len(raw) <= 4096:
        raise ValueError("Use a private key file containing at least 32 bytes")
    return raw


def safe_share(records, key):
    def anonymous(value):
        return hmac.new(key, str(value).encode(), hashlib.sha256).hexdigest()[:24]
    shared = []
    for record in records:
        for service in record["services"] or [{"port": "Not tested", "transport": "Not tested", "state": "Not tested"}]:
            shared.append({"asset": anonymous(record["asset_id"]), "run": anonymous(record["run_id"]),
                           "addresses": [anonymous(item["address"]) for item in record["addresses"]],
                           "port": service["port"], "transport": service["transport"], "state": service["state"],
                           "execution_outcome": record["execution_outcome"]})
    return {"schema_version": 1, "fields": ["asset", "run", "addresses", "port", "transport", "state", "execution_outcome"],
            "inventory": shared, "limitations": "Pseudonymous inventory with an explicit field allowlist"}


def trend_report(directory, engagement, group_by):
    records = assessment.inventory(directory, engagement, latest=False)
    series = []
    for record in sorted(records, key=lambda item: (item["observed_at"], item["run_id"], item["asset_id"])):
        group = record["metadata"].get(group_by, "Not determined") if group_by else "All assets"
        series.append({"asset_id": record["asset_id"], "run_id": record["run_id"], "observed_at": record["observed_at"],
                       "group": group, "source_tool": record["source_tool"], "execution_outcome": record["execution_outcome"],
                       "confidence": "Unverified observation",
                       "imported": record["imported"], "port_states": [{"port": service["port"], "transport": service["transport"], "state": service["state"]}
                                                                  for service in record["services"]],
                       "open_services": sum(service["state"] == "open" for service in record["services"]),
                       "absence_interpretation": "Missing observations require coverage and control-equivalence review"})
    grouped = {}
    for row in series:
        group = row["group"] if isinstance(row["group"], str) else "Not determined"
        value = grouped.setdefault((group, row["run_id"]), {"assets": set(), "services": set(), "imported_assets": set(), "outcomes": Counter()})
        value["assets"].add(row["asset_id"])
        value["outcomes"][row["execution_outcome"]] += 1
        if row["imported"]:
            value["imported_assets"].add(row["asset_id"])
        value["services"].update((row["asset_id"], port["transport"], port["port"]) for port in row["port_states"] if port["state"] == "open")
    comparisons = [{"group": group, "run_id": run, "observed_assets": len(value["assets"]), "open_service_observations": len(value["services"]),
                    "imported_assets": len(value["imported_assets"]), "outcome_counts": dict(value["outcomes"]), "coverage_equivalence": "Not established"}
                   for (group, run), value in grouped.items()]
    return {"schema_version": 1, "engagement": engagement, "group_by": group_by, "observations": series, "group_runs": comparisons,
            "metadata_scope": "Current assessor metadata applied to historical observations",
            "coverage": dict(Counter(record["execution_outcome"] for record in records)),
            "limitations": "Observation history preserves source and coverage. Remediation requires approved comparable retests."}


def attestation_payload(backend, directory, engagement, reports):
    root = Path(directory).resolve()
    records = findings.list_findings(directory, engagement)
    with assessment.local_operation(backend, directory, {"tool": "local", "engagement": engagement}) as store:
        findings.FindingRepository(store, backend).validate_final_export(engagement, records)
        with store.connect() as database:
            jobs = database.execute("SELECT j.* FROM jobs j JOIN runs r ON r.id=j.run_id WHERE r.engagement=?", (engagement,)).fetchall()
            events = [dict(row) for row in database.execute("SELECT e.* FROM finding_events e JOIN findings f ON f.id=e.finding_id WHERE f.engagement=?", (engagement,))]
        files = []
        for job in jobs:
            if not store.verify_job(job):
                raise ValueError("Evidence integrity failed before attestation")
            manifest = read_json(Path(job["directory"]) / "manifest.json")
            for artifact in manifest["artifacts"]:
                path = (Path(job["directory"]) / artifact["name"]).resolve()
                if not path.is_relative_to(root):
                    raise ValueError("Evidence path exceeds the assessment directory")
                files.append({"path": str(path.relative_to(root)), "sha256": artifact["sha256"], "kind": "raw evidence"})
        for report in reports:
            path = Path(report).resolve()
            if not path.is_relative_to(root) or ".scanrunner" in path.relative_to(root).parts:
                raise ValueError("Reports must be exported under the assessment directory")
            files.append({"path": str(path.relative_to(root)), "sha256": backend.file_sha256(path), "kind": "report"})
        if not reports:
            raise ValueError("Select at least one exported report")
        return {"schema_version": 1, "algorithm": "HMAC-SHA256", "engagement": engagement, "created_at": backend.utc_now(),
                "rule_version": findings.RULE_VERSION, "parser_version": assessment.PARSER_VERSION,
                "implementation_sha256": {name: backend.file_sha256(path) for path in [Path(backend.__file__), *Path(__file__).parent.glob("*.py")] for name in [path.name]},
                "approval_events_sha256": hashlib.sha256(canonical(events)).hexdigest(),
                "approvals": [{"finding_id": row["id"], "reviewer": row.get("reviewer"), "reviewed_at": row.get("reviewed_at")} for row in records],
                "files": files, "limitations": "Shared-key integrity attestation. Identity assurance depends on key custody and local reviewer attestations."}


def verify_attestation(backend, document, key, directory):
    payload = document.get("payload")
    if not isinstance(payload, dict) or payload.get("algorithm") != "HMAC-SHA256" or payload.get("schema_version") != 1:
        raise ValueError("Unsupported attestation")
    signature = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    if not isinstance(document.get("signature"), str) or not hmac.compare_digest(signature, document["signature"]):
        raise ValueError("Attestation authentication failed")
    root = Path(directory).resolve()
    if not isinstance(payload.get("files"), list) or not payload["files"]:
        raise ValueError("Attestation has no bound files")
    for entry in payload["files"]:
        path = (root / entry["path"]).resolve()
        if not path.is_relative_to(root) or backend.file_sha256(path) != entry["sha256"]:
            raise ValueError("Attested file is missing, modified or outside the assessment directory")
    return {"verified": True, "files": len(payload["files"]), "engagement": payload["engagement"]}


def rules_catalog(backend):
    contracts = []
    for check, rule in findings.RULES.items():
        contracts.append({"check_id": check, **{key: sorted(value) if isinstance(value, set) else value for key, value in rule.items()},
                          "version": findings.RULE_VERSION, "default_status": "Needs Verification",
                          "prerequisites": rule.get("prerequisites", ["completed scan", "single associated open TCP SMB endpoint", "structured negotiation output"]),
                          "regressions": ["tests/test_findings.py", "tests/test_roadmap.py"]})
    return {"schema_version": 1, "pack_id": "scanrunner-protocol-controls", "version": findings.RULE_VERSION,
            "sha256": {name: backend.file_sha256(Path(__file__).with_name(name)) for name in ("scanrunner_findings.py", "scanrunner_rules.py")},
            "rules": contracts}


def cli(argv, backend):
    command = argv[0]
    if command in {"schedule", "advisory", "template", "tui"}:
        from scanrunner_lib import scanrunner_workspace
        return scanrunner_workspace.cli(argv, backend)
    parser = command_parser(command)
    parser.add_argument("--output", "-o", default="results")
    parser.add_argument("--engagement", default="default")
    parser.add_argument("--destination")
    if command == "rules":
        parser.add_argument("--check")
        args = parser.parse_args(argv[1:])
        value = rules_catalog(backend)
        if args.check:
            value["rules"] = [rule for rule in value["rules"] if rule["check_id"] == args.check]
            if not value["rules"]:
                raise ValueError("Unknown rule")
        output_json(backend, value, args.destination)
        return 0
    if command == "trends":
        parser.add_argument("--group-by", choices=["site", "subnet"])
        args = parser.parse_args(argv[1:])
        output_json(backend, trend_report(args.output, args.engagement, args.group_by), args.destination)
        return 0
    if command == "share":
        parser.add_argument("--key", required=True, help="Private local pseudonymization key file")
        parser.add_argument("--preview", action="store_true")
        args = parser.parse_args(argv[1:])
        if not args.preview and not args.destination:
            raise ValueError("Choose --preview or an export destination")
        result = safe_share(assessment.inventory(args.output, args.engagement), key_bytes(args.key))
        output_json(backend, result, None if args.preview else args.destination)
        return 0
    if command == "attest":
        parser.add_argument("action", choices=["keygen", "sign", "verify"])
        parser.add_argument("--key", required=True)
        parser.add_argument("--report", action="append", default=[])
        parser.add_argument("--manifest")
        args = parser.parse_args(argv[1:])
        if args.action == "keygen":
            descriptor = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(secrets.token_bytes(32))
            print(json.dumps({"created": True, "key_path": str(Path(args.key).resolve())}))
            return 0
        key = key_bytes(args.key)
        if args.action == "verify":
            output_json(backend, verify_attestation(backend, read_json(args.manifest), key, args.output))
            return 0
        if not args.destination or Path(args.destination).resolve() in {Path(args.key).resolve(), *[Path(path).resolve() for path in args.report]}:
            raise ValueError("Choose a distinct attestation output destination")
        payload = attestation_payload(backend, args.output, args.engagement, args.report)
        signature = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
        # The signature binds the exact bytes of the canonical payload. Applying
        # export redaction here would invalidate authentication.
        assessment.ensure_export_destination(args.destination)
        with backend.atomic_text(args.destination) as file:
            json.dump({"payload": payload, "signature": signature}, file, indent=2)
        return 0
    raise ValueError("Unsupported local operation")

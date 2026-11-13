"""Explicit local scheduling, advisory snapshots, templates and terminal menus."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid
from contextlib import redirect_stdout

import scanrunner_assessment as assessment
import scanrunner_findings as findings
from scanrunner_operations import canonical, output_json, read_json


def schedule_definition(backend, definition, directory, engagement):
    if not isinstance(definition, dict) or set(definition) != {"argv"} or not isinstance(definition["argv"], list):
        raise ValueError("Schedule definition must contain an argv list")
    argv = definition["argv"]
    if not argv or any(not isinstance(value, str) for value in argv) or argv[0] in {"plugin", "probe", "schedule"}:
        raise ValueError("Schedule only explicit core scanner arguments")
    previous = sys.argv
    try:
        sys.argv = ["scanrunner", *argv]
        args = backend.parse_args()
    finally:
        sys.argv = previous
    if args.dry_run or args.split is not None or args.split_size is not None or not args.scope_file:
        raise ValueError("Schedules require a scoped scan without split or preview flags")
    if Path(args.output).resolve() != Path(directory).resolve() or args.engagement != engagement:
        raise ValueError("Scheduled output and engagement must match their queue")
    if not args.yes or not args.authorization_note:
        raise ValueError("Scheduled scans require explicit noninteractive authorization")
    previous = sys.argv
    try:
        sys.argv = ["scanrunner", *argv, "--dry-run"]
        with redirect_stdout(io.StringIO()):
            backend.main()
    finally:
        sys.argv = previous
    policy = assessment.engagement_policy(directory, engagement)
    if not policy or not policy.get("expires_at") or assessment.parse_timestamp(policy["expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("Scheduling requires a current engagement with an explicit authorization expiry")
    files = {}
    for name in ("file", "scope_file", "exclude_file", "scope_snapshot"):
        value = getattr(args, name, None)
        if value:
            path = Path(value).resolve()
            files[str(path)] = backend.file_sha256(path)
    return {"argv": argv, "files": files, "scope_version": policy["scope_version"]}


def run_due(backend, store, execute):
    with store.connect() as database:
        rows = database.execute("SELECT * FROM schedules WHERE engagement=? AND status='Pending' AND due<=? ORDER BY due,id",
                                (store.config["engagement"], backend.utc_now())).fetchall()
    if not execute:
        return [{"id": row["id"], "due": row["due"], "status": row["status"]} for row in rows]
    results = []
    for row in rows:
        with store.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            if database.execute("UPDATE schedules SET status='Running' WHERE id=? AND status='Pending'", (row["id"],)).rowcount != 1:
                continue
        status, code, detail = "Failed", None, "Execution failed"
        directory = Path(store.directory) / ".scanrunner" / "schedules" / row["id"] / uuid.uuid4().hex
        directory.mkdir(parents=True, mode=0o700)
        try:
            saved = json.loads(row["data"])
            current = schedule_definition(backend, {"argv": saved["argv"]}, store.directory, store.config["engagement"])
            if current != saved:
                raise ValueError("Scheduled input files or authorization changed")
            # Snapshot each consequential file and verify the copied bytes before
            # launching the core CLI, which validates authorization again.
            replacements = {}
            for index, (name, digest) in enumerate(saved["files"].items()):
                copied = directory / (str(index) + "-input.txt")
                shutil.copyfile(name, copied)
                if backend.file_sha256(copied) != digest:
                    raise ValueError("Scheduled input changed while being copied")
                replacements[name] = str(copied)
            argv = []
            file_flags = {"-f", "--file", "--scope-file", "--exclude-file", "--scope-snapshot"}
            previous = None
            for value in saved["argv"]:
                flag, equal, argument = value.partition("=")
                if flag in file_flags and equal:
                    argv.append(flag + "=" + replacements[str(Path(argument).resolve())])
                elif previous in file_flags:
                    argv.append(replacements[str(Path(value).resolve())])
                else:
                    argv.append(value)
                previous = flag
            code, state = backend.capture_process([sys.executable, "-B", str(Path(__file__).with_name("scanrunner.py")), *argv], str(directory), timeout=3600)
            status = "Completed" if code == 0 and state == "Exited" else "Failed"
            detail = "Scheduled command completed" if status == "Completed" else "Scheduled command failed or was interrupted"
        except Exception as error:
            detail = type(error).__name__ + ": " + str(error)
        finally:
            evidence = {path.name: backend.file_sha256(path) for path in directory.iterdir() if path.is_file()}
            event = {"id": row["id"], "status": status, "exit_code": code, "ended_at": backend.utc_now(),
                     "detail": backend.redact_output_text(detail), "evidence": evidence,
                     "notification": {"job_id": row["id"], "status": status}}
            with store.connect() as database:
                database.execute("UPDATE schedules SET status=?,result=? WHERE id=?", (status, json.dumps(event), row["id"]))
            results.append(event)
    return results


def advisory_entries(data):
    if not isinstance(data, dict) or data.get("dataType") != "CVE_RECORD" or not str(data.get("dataVersion", "")).startswith("5."):
        raise ValueError("Advisory snapshots require CVE JSON 5 records")
    metadata = data.get("cveMetadata", {})
    identifier = metadata.get("cveId", "")
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier) or metadata.get("state") not in {"PUBLISHED", "REJECTED"}:
        raise ValueError("Invalid CVE record identity/state")
    return identifier, data.get("containers", {}).get("cna", {}).get("affected", [])


def correlate(backend, directory, engagement):
    records = assessment.inventory(directory, engagement)
    with assessment.read_database(directory) as database:
        snapshots = database.execute("SELECT * FROM advisory_snapshots").fetchall()
    results = []
    for snapshot in snapshots:
        path = Path(snapshot["path"])
        if backend.file_sha256(path) != snapshot["sha256"]:
            raise ValueError("Advisory snapshot integrity failed")
        data = read_json(path)
        identifier, affected = advisory_entries(data)
        if data["cveMetadata"]["state"] == "REJECTED":
            continue
        for record in records:
            for service in record["services"]:
                for product in affected:
                    product_name = product.get("product") or product.get("packageName")
                    if not product_name or not service.get("product") or str(service["product"]).casefold() != str(product_name).casefold():
                        continue
                    if any(version.get("status") == "affected" and version.get("version") == service.get("version")
                           for version in product.get("versions", [])):
                        results.append({"cve_id": identifier, "asset_id": record["asset_id"], "addresses": record["addresses"],
                                        "port": service["port"], "transport": service["transport"], "version": service.get("version"),
                                        "status": "Potential", "confidence": "Unverified", "source": snapshot["source"],
                                        "snapshot_sha256": snapshot["sha256"], "imported_at": snapshot["imported_at"],
                                        "limitations": "Exact supplied product/version match. Vendor identity, backports, patch state and applicability require analyst verification."})
    return {"schema_version": 1, "candidates": results, "limitations": "Only explicit exact affected-version entries are matched. Ranges and wildcard applicability require manual review."}


def terminal_menu(backend, directory, engagement, once=False):
    while True:
        print("ScanRunner assessment " + engagement)
        print("1 Inventory  2 Findings  3 Queue/history  4 Evidence  5 Review  6 Export  7 Engagements  0 Exit")
        if once:
            return 0
        choice = input("Choose action > ").strip()
        if choice == "0":
            return 0
        try:
            if choice == "1":
                output_json(backend, assessment.inventory(directory, engagement))
            elif choice == "2":
                output_json(backend, findings.list_findings(directory, engagement, True))
            elif choice == "3":
                output_json(backend, backend.review_run_history(directory))
            elif choice == "4":
                root = (Path(directory) / ".scanrunner" / "runs").resolve()
                selected = (root / input("Evidence path relative to runs directory > ").strip()).resolve()
                if not selected.is_relative_to(root) or not selected.is_file():
                    raise ValueError("Choose an existing evidence file inside this assessment")
                print(backend.redact_output_text(selected.read_bytes()[:65536].decode("utf-8", errors="replace")))
            elif choice == "5":
                identifier = input("Finding ID > ").strip()
                status = input("Review status > ").strip()
                reviewer = input("Reviewer > ").strip()
                rationale = input("Rationale > ").strip()
                details = input("Reviewed details JSON path > ").strip()
                argv = ["findings", "review", "--finding", identifier, "--status", status, "--reviewer", reviewer,
                        "--rationale", rationale, "--details", details, "--output", directory, "--engagement", engagement]
                if status == "Confirmed":
                    if input("Approve evidence prerequisites, impact and imported origin? Type APPROVE > ") != "APPROVE":
                        continue
                    argv.extend(["--approve-preconditions-and-impact", "--trust-import-origin"])
                findings.cli(argv, backend)
            elif choice == "6":
                destination = input("Export destination > ").strip()
                format_name = input("Format json/csv/html/xlsx > ").strip()
                assessment.cli(["report", "--output", directory, "--engagement", engagement, "--format", format_name,
                                "--destination", destination], backend)
            elif choice == "7":
                assessment.cli(["engagement", "show", "--output", directory], backend)
                engagement = input("Select engagement ID > ").strip() or engagement
        except (ValueError, OSError) as error:
            print(str(error))


def cli(argv, backend):
    command = argv[0]
    parser = argparse.ArgumentParser(prog="scanrunner " + command)
    parser.add_argument("--output", "-o", default="results")
    parser.add_argument("--engagement", default="default")
    if command == "tui":
        parser.add_argument("--once", action="store_true")
        args = parser.parse_args(argv[1:])
        return terminal_menu(backend, args.output, args.engagement, args.once)
    if command == "schedule":
        parser.add_argument("action", choices=["add", "list", "cancel", "run-due"])
        parser.add_argument("--definition")
        parser.add_argument("--at")
        parser.add_argument("--id")
        parser.add_argument("--execute", action="store_true")
        args = parser.parse_args(argv[1:])
        with assessment.local_operation(backend, args.output, {"tool": "local", "engagement": args.engagement}) as store:
            with store.connect() as database:
                database.execute("CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, engagement TEXT, due TEXT, status TEXT, data TEXT, result TEXT)")
            if args.action == "add":
                definition = schedule_definition(backend, read_json(args.definition), args.output, args.engagement)
                due = assessment.parse_timestamp(args.at).astimezone(timezone.utc).isoformat()
                identifier = uuid.uuid4().hex
                with store.connect() as database:
                    database.execute("INSERT INTO schedules VALUES (?, ?, ?, 'Pending', ?, NULL)", (identifier, args.engagement, due, json.dumps(definition)))
                output_json(backend, {"id": identifier, "due": due, "status": "Pending"})
            elif args.action == "run-due":
                output_json(backend, run_due(backend, store, args.execute))
            else:
                with store.connect() as database:
                    if args.action == "cancel":
                        if database.execute("UPDATE schedules SET status='Cancelled' WHERE id=? AND engagement=? AND status='Pending'", (args.id, args.engagement)).rowcount != 1:
                            raise ValueError("Pending scheduled job not found")
                    rows = [dict(row) for row in database.execute("SELECT id,due,status,result FROM schedules WHERE engagement=?", (args.engagement,))]
                output_json(backend, rows)
        return 0
    if command == "advisory":
        parser.add_argument("action", choices=["import", "list", "correlate"])
        parser.add_argument("--path")
        parser.add_argument("--source")
        args = parser.parse_args(argv[1:])
        with assessment.local_operation(backend, args.output, {"tool": "local", "engagement": args.engagement}) as store:
            with store.connect() as database:
                database.execute("CREATE TABLE IF NOT EXISTS advisory_snapshots (sha256 TEXT PRIMARY KEY, cve_id TEXT, path TEXT, source TEXT, imported_at TEXT)")
            if args.action == "import":
                if not args.source or not args.source.startswith("https://"):
                    raise ValueError("Record the declared HTTPS source URL for the manually downloaded snapshot")
                raw = Path(args.path).read_bytes()
                if len(raw) > 8 * 1024 * 1024:
                    raise ValueError("Advisory snapshot exceeds size limit")
                data = json.loads(raw)
                identifier, _ = advisory_entries(data)
                digest = hashlib.sha256(raw).hexdigest()
                directory = Path(args.output) / ".scanrunner" / "advisories"
                directory.mkdir(mode=0o700, exist_ok=True)
                destination = directory / (digest + ".json")
                try:
                    with destination.open("xb") as file:
                        file.write(raw)
                except FileExistsError:
                    if backend.file_sha256(destination) != digest:
                        raise ValueError("Existing snapshot integrity failed")
                with store.connect() as database:
                    database.execute("INSERT OR IGNORE INTO advisory_snapshots VALUES (?, ?, ?, ?, ?)",
                                     (digest, identifier, str(destination.resolve()), args.source, backend.utc_now()))
                output_json(backend, {"cve_id": identifier, "sha256": digest, "origin_verified": False})
            elif args.action == "correlate":
                output_json(backend, correlate(backend, args.output, args.engagement))
            else:
                with store.connect() as database:
                    output_json(backend, [dict(row) for row in database.execute("SELECT cve_id,sha256,source,imported_at FROM advisory_snapshots")])
        return 0
    if command == "template":
        parser.add_argument("action", choices=["create", "apply", "report"])
        parser.add_argument("--path", required=True)
        parser.add_argument("--name")
        parser.add_argument("--expires-at")
        parser.add_argument("--destination")
        parser.add_argument("--format", choices=["json", "csv", "html", "xlsx"], default="json")
        parser.add_argument("--view", choices=["technical", "executive"], default="technical")
        args = parser.parse_args(argv[1:])
        if args.action == "create":
            policy = assessment.engagement_policy(args.output, args.engagement)
            if not policy:
                raise ValueError("Select an existing engagement to template")
            output_json(backend, {"schema_version": 1, "scope": policy["scope"], "exclusions": policy.get("exclusions", []),
                                  "report": {"view": args.view, "include_candidates": False}}, args.path)
            return 0
        template = read_json(args.path)
        if (not isinstance(template, dict) or set(template) != {"schema_version", "scope", "exclusions", "report"}
                or template["schema_version"] != 1 or not isinstance(template["scope"], list) or not template["scope"]
                or not isinstance(template["exclusions"], list)
                or any(not isinstance(value, str) or not backend.ScopeGuard._valid_entry(value) for value in template["scope"] + template["exclusions"])
                or template["report"] not in ({"view": "technical", "include_candidates": False}, {"view": "executive", "include_candidates": False})):
            raise ValueError("Unsupported assessment template schema")
        if args.action == "report":
            if not args.destination:
                raise ValueError("Select a report destination")
            return assessment.cli(["report", "--output", args.output, "--engagement", args.engagement, "--view", template["report"]["view"],
                                   "--format", args.format, "--destination", args.destination], backend)
        if not args.name or not args.expires_at or assessment.parse_timestamp(args.expires_at) <= datetime.now(timezone.utc):
            raise ValueError("Applying a template requires a new engagement name and current authorization expiry")
        directory = Path(args.output).resolve() / ".scanrunner" / "template-inputs" / uuid.uuid4().hex
        directory.mkdir(parents=True, mode=0o700)
        scope = directory / "scope.txt"
        exclusions = directory / "exclude.txt"
        scope.write_text("\n".join(template["scope"]) + "\n", encoding="utf-8")
        exclusions.write_text("\n".join(template["exclusions"]) + "\n", encoding="utf-8")
        return assessment.cli(["engagement", "create", "--name", args.name, "--scope-file", str(scope), "--exclude-file", str(exclusions),
                               "--expires-at", args.expires_at, "--output", args.output], backend)
    raise ValueError("Unsupported workspace command")

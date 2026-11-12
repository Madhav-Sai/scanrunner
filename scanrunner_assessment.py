"""Offline normalized inventory and evidence-linked assessment records."""
import argparse
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import shutil
import sqlite3
import uuid
from collections import Counter

PARSER_VERSION = "1"
COMMANDS = {"engagement", "inventory", "asset", "import", "observations", "report", "findings", "retest", "benchmark"}


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp requires an explicit timezone")
    return parsed


def observed_time(root):
    try:
        return datetime.fromtimestamp(float(root.attrib["start"]), timezone.utc).isoformat()
    except (KeyError, ValueError, OverflowError, OSError):
        return "Not determined"


def normalize_nmap(backend, path, target, job, outcome="Imported"):
    root = backend.read_nmap_xml(path)
    raw_hash = backend.file_sha256(path)
    hosts = []
    for host_index, host in enumerate(root.findall("host"), 1):
        location = f"/nmaprun/host[{host_index}]"
        status = host.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        addresses = [{"address": str(ipaddress.ip_address(node.get("addr", ""))),
                      "family": node.get("addrtype"), "source": location + "/address"}
                     for node in host.findall("address") if node.get("addrtype") in {"ipv4", "ipv6"}]
        names = [{"name": node.get("name", ""), "source_type": node.get("type", "Not determined"),
                  "evidence_location": location + "/hostnames/hostname"}
                 for node in host.findall("hostnames/hostname")]
        guesses = [{"name": node.get("name", "Not determined"), "confidence": node.get("accuracy", "Not determined")}
                   for node in host.findall("os/osmatch")]
        inputs = [target] if isinstance(target, str) else target
        matches = [item for item in inputs if any(backend.target_in_scope(address["address"], [item]) for address in addresses)]
        record = {"target": matches[0] if len(matches) == 1 else (target if isinstance(target, str) else ", ".join(matches)),
                  "input_targets": matches or inputs, "addresses": addresses, "hostnames": names, "host_state": state,
                  "service_address": addresses[0]["address"] if len(addresses) == 1 else "Not determined",
                  "os_guesses": guesses, "services": [], "scripts": [], "run_id": job["run_id"],
                  "job_id": job["id"], "observed_at": observed_time(root), "execution_outcome": outcome,
                  "source_tool": root.get("scanner", "Not determined"), "tool_version": root.get("version", "Not determined"),
                  "scanner_arguments": root.get("args", "Not determined"),
                  "parser_version": PARSER_VERSION, "raw_sha256": raw_hash, "artifact": str(Path(path).resolve()),
                  "evidence_location": location, "imported": outcome == "Imported",
                  "scan_completion": root.find("runstats/finished").get("exit", "unknown")
                      if root.find("runstats/finished") is not None and host.get("timedout") != "true" else "unknown",
                  "limitations": "Imported evidence origin requires analyst review" if outcome == "Imported" else
                      ("Partial or failed scan evidence" if outcome != "COMPLETE" else "Time-bound tested scope")}
        for port_index, port in enumerate(host.findall("ports/port"), 1):
            port_location = location + f"/ports/port[{port_index}]"
            port_state = port.find("state")
            service = port.find("service")
            service_values = service.attrib if service is not None else {}
            number = int(port.get("portid", "-1"))
            if not 0 <= number <= 65535:
                raise ValueError("Invalid observed port number")
            if port.get("protocol") not in {"tcp", "udp", "sctp", "ip"}:
                raise ValueError("Unsupported observed transport")
            if port_state is not None and port_state.get("state") not in {
                    "open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown"}:
                raise ValueError("Unsupported observed service state")
            entry = {"port": number, "transport": port.get("protocol", "unknown"),
                     "state": port_state.get("state", "unknown") if port_state is not None else "unknown",
                     "service": service_values.get("name", "Not determined"),
                     "product": service_values.get("product", "Not determined"),
                     "version": service_values.get("version", "Not determined"),
                     "extra_info": service_values.get("extrainfo", ""),
                     "identification_method": service_values.get("method", "Not determined"),
                     "confidence": service_values.get("conf", "Not determined"), "evidence_location": port_location}
            record["services"].append(entry)
            for index, script in enumerate(port.findall("script"), 1):
                record["scripts"].append(script_observation(script, port_location + f"/script[{index}]", number, entry["transport"]))
        for index, script in enumerate(host.findall("hostscript/script"), 1):
            observation = script_observation(script, location + f"/hostscript/script[{index}]", None, None)
            if script.get("id") in {"smb-protocols", "smb2-security-mode"}:
                candidates = [service for service in record["services"] if service["transport"] == "tcp"
                              and service["port"] in {139, 445} and service["state"] == "open"]
                arguments = record["scanner_arguments"]
                netbios = next((service["state"] for service in record["services"]
                                if service["transport"] == "udp" and service["port"] == 137), "unknown")
                if (len(candidates) == 1 and arguments != "Not determined" and "--script-args" not in arguments
                        and "smbport" not in arguments.lower() and
                        (candidates[0]["port"] == 445 or netbios in {"unknown", "open", "open|filtered"})):
                    observation.update(port=candidates[0]["port"], transport="tcp",
                                       endpoint_association="Derived from sole eligible SMB endpoint and Nmap library selection",
                                       endpoint_evidence=candidates[0]["evidence_location"])
            record["scripts"].append(observation)
        hosts.append(record)
    return hosts


def script_observation(script, location, port, transport):
    output = script.get("output", "")
    fields = [{"key": element.get("key"), "value": element.text or ""} for element in script.iter("elem")]
    def structure(node):
        return {"tag": node.tag, "key": node.get("key"), "text": node.text or "",
                "children": [structure(child) for child in node]}
    return {"check_id": script.get("id", "Not determined"), "check_version": "Scanner implementation",
            "port": port, "transport": transport, "output": output, "fields": fields,
            "structured": structure(script),
            "endpoint_association": "Explicit XML port element" if port is not None else "Host-level endpoint not determined",
            "evidence_location": location, "confidence": "Unverified",
            "check_execution": "Inconclusive" if any(token in output.lower() for token in ("error", "timed out", "failed"))
                else "Output observed"}


class AssessmentRepository:
    def __init__(self, store, backend):
        self.store = store
        self.backend = backend
        with store.connect() as database:
            database.executescript("""
                CREATE TABLE IF NOT EXISTS engagement_metadata (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, engagement TEXT NOT NULL, metadata TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS asset_addresses (
                    engagement TEXT NOT NULL, address TEXT NOT NULL, asset_id TEXT NOT NULL,
                    PRIMARY KEY(engagement,address));
                CREATE TABLE IF NOT EXISTS asset_observations (
                    id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, run_id TEXT NOT NULL, job_id TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS security_observations (
                    id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, run_id TEXT NOT NULL, job_id TEXT NOT NULL, data TEXT NOT NULL);
            """)

    def ingest(self, records):
        engagement = self.store.config.get("engagement", "default")
        with self.store.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            for record in records:
                addresses = [item["address"] for item in record["addresses"]]
                candidates = {row[0] for address in addresses for row in database.execute(
                    "SELECT asset_id FROM asset_addresses WHERE engagement=? AND address=?", (engagement, address))}
                if len(candidates) > 1:
                    raise ValueError("Observed addresses belong to different assets; analyst identity review required")
                asset_id = next(iter(candidates)) if candidates else uuid.uuid4().hex
                database.execute("INSERT OR IGNORE INTO assets VALUES (?, ?, '{}')", (asset_id, engagement))
                for address in addresses:
                    database.execute("INSERT OR IGNORE INTO asset_addresses VALUES (?, ?, ?)", (engagement, address, asset_id))
                identity = hashlib.sha256((record["job_id"] + record["evidence_location"]).encode()).hexdigest()
                existing = database.execute("SELECT id FROM asset_observations WHERE id=?", (identity,)).fetchone()
                if existing:
                    continue
                record = {**record, "asset_id": asset_id, "engagement": engagement}
                database.execute("INSERT INTO asset_observations VALUES (?, ?, ?, ?, ?)",
                                 (identity, asset_id, record["run_id"], record["job_id"], json.dumps(record)))
                for script in record["scripts"]:
                    observation_id = hashlib.sha256((identity + script["evidence_location"]).encode()).hexdigest()
                    observation = {**script, "asset_id": asset_id, "addresses": addresses,
                                   "run_id": record["run_id"], "job_id": record["job_id"],
                                   "raw_sha256": record["raw_sha256"], "artifact": record["artifact"],
                                   "observed_at": record["observed_at"], "execution_outcome": record["execution_outcome"],
                                   "host_state": record["host_state"], "source_tool": record["source_tool"],
                                   "tool_version": record["tool_version"], "imported": record["imported"],
                                   "scan_completion": record["scan_completion"],
                                   "scanner_arguments": record["scanner_arguments"],
                                   "service_state": next((service["state"] for service in record["services"]
                                                          if service["port"] == script["port"] and service["transport"] == script["transport"]), "Not determined"),
                                   "parser_version": PARSER_VERSION, "verification_status": "Needs Verification"}
                    database.execute("INSERT INTO security_observations VALUES (?, ?, ?, ?, ?)",
                                     (observation_id, asset_id, record["run_id"], record["job_id"], json.dumps(observation)))


@contextmanager
def read_database(directory):
    path = Path(directory).resolve() / ".scanrunner" / "scanrunner.sqlite3"
    if not path.is_file():
        raise ValueError("No assessment database found")
    database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30)
    database.row_factory = sqlite3.Row
    try:
        yield database
    finally:
        database.close()


def engagement_policy(directory, name):
    if not (Path(directory) / ".scanrunner" / "scanrunner.sqlite3").is_file():
        return None
    with read_database(directory) as database:
        if not database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='engagement_metadata'").fetchone():
            return None
        row = database.execute("SELECT data FROM engagement_metadata WHERE id=?", (name,)).fetchone()
    return json.loads(row[0]) if row else None


def inventory(directory, engagement=None, run_id=None, latest=True):
    with read_database(directory) as database:
        try:
            rows = database.execute("SELECT o.data,a.metadata FROM asset_observations o JOIN assets a ON o.asset_id=a.id ORDER BY o.rowid DESC").fetchall()
        except sqlite3.OperationalError as error:
            raise ValueError("No normalized inventory exists; import Nmap XML or run a new assessment") from error
    records, seen = [], set()
    for row in rows:
        record = json.loads(row["data"])
        if engagement and record["engagement"] != engagement or run_id and record["run_id"] != run_id:
            continue
        if latest and record["asset_id"] in seen:
            continue
        seen.add(record["asset_id"])
        record["metadata"] = json.loads(row["metadata"])
        records.append(record)
    return records


def inventory_rows(records):
    rows = []
    for record in records:
        for address in [{"address": record["service_address"]}]:
            for service in record["services"] or [{"port": "Not tested", "transport": "Not tested", "state": "Not tested"}]:
                rows.append({"asset_id": record["asset_id"], "engagement": record["engagement"],
                             "input_target": record["target"], "address": address["address"],
                             "observed_addresses": [item["address"] for item in record["addresses"]],
                             "hostnames": ", ".join(item["name"] for item in record["hostnames"]) or "Not determined",
                             "host_state": record["host_state"], **service, "run_id": record["run_id"],
                             "observed_at": record["observed_at"], "execution_outcome": record["execution_outcome"],
                             "evidence": record["artifact"], "raw_sha256": record["raw_sha256"],
                             "metadata": record["metadata"]})
    return rows


def assessment_report(backend, directory, engagement, records, run_id=None, executive=False, include_candidates=False):
    import scanrunner_findings as findings
    all_findings = findings.list_findings(directory, engagement, True)
    asset_ids = {record["asset_id"] for record in records}
    all_findings = [finding for finding in all_findings if finding["asset_id"] in asset_ids]
    confirmed = [finding for finding in all_findings if finding["status"] == "Confirmed"]
    with local_operation(backend, directory, {"tool": "local", "engagement": engagement}) as store:
        findings.FindingRepository(store, backend).validate_final_export(engagement, confirmed)
        with store.connect() as database:
            targets = database.execute(
                "SELECT t.requested,t.outcome FROM run_targets t JOIN runs r ON r.id=t.run_id "
                "WHERE r.engagement=? AND (? IS NULL OR r.id=?) ORDER BY r.started,t.rowid",
                (engagement, run_id, run_id)).fetchall()
    latest_targets = {row["requested"]: row["outcome"] for row in targets}
    summary = {"engagement": engagement, "run_filter": run_id,
               "coverage_scope": "Engagement target entries under the run filter, independently of inventory filters",
               "requested_target_entries": len(latest_targets),
               "latest_target_outcomes": dict(Counter(latest_targets.values())),
               "target_attempt_outcomes": dict(Counter(row["outcome"] for row in targets)),
               "observed_assets": len(asset_ids),
               "open_service_observations": sum(service["state"] == "open" for record in records for service in record["services"]),
               "imported_asset_observations": sum(record["imported"] for record in records),
               "confirmed_findings": len(confirmed),
               "finding_status_counts": dict(Counter(finding["status"] for finding in all_findings)),
               "limitations": "Requested targets can be CIDRs or hostnames. Imported observations do not establish newly executed scan coverage. Failed, missing and inconclusive checks limit assessment coverage."}
    result = {"summary": summary}
    if not executive:
        result["inventory"] = records
        result["findings"] = all_findings if include_candidates else confirmed
    return result


def export_records(backend, records, destination, output_format):
    ensure_export_destination(destination)
    records = redact_records(backend, records)
    if output_format == "json":
        with backend.atomic_text(str(destination)) as file:
            json.dump(records, file, indent=2)
    elif output_format == "csv":
        fields = list(dict.fromkeys(key for row in records for key in row))
        with backend.atomic_text(str(destination), newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: backend.csv_safe(json.dumps(value) if isinstance(value, (dict, list)) else value)
                             for key, value in row.items()} for row in records)
    elif output_format == "html":
        fields = list(dict.fromkeys(key for row in records for key in row))
        page = '<!doctype html><meta charset="utf-8"><title>Assessment inventory</title>'
        page += '<p>Time-bound assessment. Coverage and execution outcomes limit interpretation.</p><table><tr>'
        page += "".join("<th>" + html.escape(key) + "</th>" for key in fields) + "</tr>"
        for row in records:
            page += "<tr>" + "".join("<td>" + html.escape(str(row.get(key, "Not determined"))) + "</td>" for key in fields) + "</tr>"
        with backend.atomic_text(str(destination)) as file:
            file.write(page + "</table>")
    else:
        raise ValueError("Unsupported export format")


def ensure_export_destination(destination):
    if ".scanrunner" in {part.lower() for part in Path(destination).resolve().parts}:
        raise ValueError("Exports cannot replace private assessment state or original evidence")


def redact_records(backend, value):
    if isinstance(value, dict):
        return {key: redact_records(backend, item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_records(backend, item) for item in value]
    return backend.redact_output_text(value) if isinstance(value, str) else value


@contextmanager
def local_operation(backend, output, config):
    store = backend.RunStore(output, config)
    try:
        yield store
    except BaseException:
        store.end("Local assessment operation failed")
        raise
    else:
        store.end("Local assessment operation completed")


def cli(argv, backend):
    if argv[0] in {"findings", "retest"}:
        import scanrunner_findings
        return scanrunner_findings.cli(argv, backend)
    if argv[0] == "benchmark":
        import scanrunner_benchmark
        return scanrunner_benchmark.cli(argv[1:], backend)
    parser = argparse.ArgumentParser(prog="scanrunner " + argv[0])
    parser.add_argument("--output", "-o", default="results", help="Assessment output directory")
    parser.add_argument("--engagement", default="default")
    command = argv[0]
    if command in {"inventory", "report"}:
        parser.add_argument("--run")
        parser.add_argument("--history", action="store_true")
        parser.add_argument("--format", choices=["json", "csv", "html"], default="json")
        parser.add_argument("--destination")
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--ip", help="Filter addresses by IP or CIDR without DNS")
        parser.add_argument("--hostname")
        parser.add_argument("--owner")
        parser.add_argument("--site")
        parser.add_argument("--service")
        parser.add_argument("--port", type=int)
        parser.add_argument("--transport")
        parser.add_argument("--status")
        if command == "report":
            parser.add_argument("--view", choices=["technical", "executive"], default="technical")
            parser.add_argument("--include-candidates", action="store_true")
        args = parser.parse_args(argv[1:])
        if args.format != "json" and not args.destination:
            parser.error("CSV and HTML exports require --destination")
        records = inventory(args.output, args.engagement, args.run, not args.history)
        if args.ip:
            network = ipaddress.ip_network(args.ip, strict=False)
            records = [record for record in records if any(ipaddress.ip_address(item["address"]) in network
                       for item in record["addresses"] if ipaddress.ip_address(item["address"]).version == network.version)]
        if args.hostname:
            records = [record for record in records if any(item["name"].lower() == args.hostname.lower() for item in record["hostnames"])]
        for field in ("owner", "site"):
            value = getattr(args, field)
            if value:
                records = [record for record in records if record["metadata"].get(field) == value]
        if args.status:
            records = [record for record in records if record["execution_outcome"] == args.status or record["host_state"] == args.status]
        if args.service or args.port is not None or args.transport:
            selected = []
            for record in records:
                services = [service for service in record["services"] if (not args.service or service["service"] == args.service)
                            and (args.port is None or service["port"] == args.port)
                            and (not args.transport or service["transport"] == args.transport)]
                if services:
                    selected.append({**record, "services": services})
            records = selected
        if command == "report":
            result = assessment_report(backend, args.output, args.engagement, records, args.run,
                                       args.view == "executive", args.include_candidates)
            if args.destination:
                ensure_export_destination(args.destination)
                if args.format == "json":
                    with backend.atomic_text(args.destination) as file:
                        json.dump(redact_records(backend, result), file, indent=2)
                else:
                    rows = [{"section": "summary", **result["summary"]}]
                    rows += [{"section": "inventory", **row} for row in inventory_rows(result.get("inventory", []))]
                    rows += [{"section": "finding", **row} for row in result.get("findings", [])]
                    export_records(backend, rows, args.destination, args.format)
            else:
                print(json.dumps(redact_records(backend, result), indent=2))
            return 0
        if args.destination:
            export_records(backend, inventory_rows(records) if args.format != "json" else records, args.destination, args.format)
        else:
            print(json.dumps(redact_records(backend, records), indent=2))
        return 0
    if command == "observations":
        args = parser.parse_args(argv[1:])
        with read_database(args.output) as database:
            rows = [{"id": row["id"], **json.loads(row["data"])} for row in database.execute(
                "SELECT o.id,o.data FROM security_observations o JOIN assets a ON o.asset_id=a.id WHERE a.engagement=?",
                (args.engagement,))]
        print(json.dumps(redact_records(backend, rows), indent=2))
        return 0
    if command == "import":
        parser.add_argument("path")
        parser.add_argument("--target", required=True, action="append")
        parser.add_argument("--scope-file", required=True)
        args = parser.parse_args(argv[1:])
        scope = backend.load_scope(args.scope_file)
        policy = engagement_policy(args.output, args.engagement)
        exclusions = policy.get("exclusions", []) if policy else []
        guard = backend.ScopeGuard(args.target, scope, exclusions,
                                   resolver=lambda *a, **k: ([], "Imports require literal authorized destinations"))
        if policy and any(not backend.target_in_scope(target, policy["scope"]) for target in args.target):
            raise ValueError("Imported target exceeds the registered engagement scope")
        root = backend.read_nmap_xml(args.path)
        for address in root.findall("host/address"):
            if address.get("addrtype") in {"ipv4", "ipv6"} and not backend.target_in_scope(address.get("addr"), guard.scope):
                raise ValueError("Imported XML contains an out-of-scope host")
        store = backend.RunStore(args.output, {"tool": "import", "engagement": args.engagement, "scope": scope})
        job = store.wait_claim(",".join(args.target))
        if job is None:
            store.end("Import already claimed")
            raise ValueError("Import target is already claimed by another worker")
        source = Path(job["directory"]) / "imported.xml"
        identity = {**job, "run_id": store.run_id}
        try:
            shutil.copyfile(args.path, source)
            copied_root = backend.read_nmap_xml(source)
            for address in copied_root.findall("host/address"):
                if address.get("addrtype") in {"ipv4", "ipv6"} and not backend.target_in_scope(address.get("addr"), args.target):
                    raise ValueError("Imported host does not match the requested target identity")
            records = normalize_nmap(backend, source, args.target, identity)
            AssessmentRepository(store, backend).ingest(records)
        except Exception:
            store.finish_job(job, "Import failed", None, False, ["import", str(Path(args.path).resolve())])
            store.end("Import failed")
            raise
        store.finish_job(job, "Imported", None, True, ["import", str(Path(args.path).resolve())])
        store.end("Imported; origin and execution trust require review")
        print(json.dumps({"run_id": store.run_id, "hosts": len(records), "imported": True}))
        return 0
    if command == "asset":
        parser.add_argument("id")
        parser.add_argument("--metadata", help="Assessor metadata JSON file")
        parser.add_argument("--add-address", help="Analyst-approved address alias for stable retest matching")
        args = parser.parse_args(argv[1:])
        if not args.metadata and not args.add_address:
            parser.error("provide --metadata or --add-address")
        metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8")) if args.metadata else {}
        allowed = {"owner", "site", "environment", "criticality", "tags", "notes", "subnet", "customer"}
        if not isinstance(metadata, dict) or not set(metadata) <= allowed:
            raise ValueError("Metadata contains unsupported fields")
        with local_operation(backend, args.output, {"tool": "local", "engagement": args.engagement}) as store:
            AssessmentRepository(store, backend)
            with store.connect() as database:
                row = database.execute("SELECT metadata FROM assets WHERE id=? AND engagement=?", (args.id, args.engagement)).fetchone()
                if row is None:
                    raise ValueError("Asset not found in this engagement")
                data = {**json.loads(row[0]), **metadata}
                if args.add_address:
                    address = str(ipaddress.ip_address(args.add_address))
                    existing = database.execute("SELECT asset_id FROM asset_addresses WHERE engagement=? AND address=?", (args.engagement, address)).fetchone()
                    if existing and existing[0] != args.id:
                        raise ValueError("Address already belongs to another asset")
                    database.execute("INSERT OR IGNORE INTO asset_addresses VALUES (?, ?, ?)", (args.engagement, address, args.id))
                database.execute("UPDATE assets SET metadata=? WHERE id=?", (json.dumps(data), args.id))
        print(json.dumps(redact_records(backend, {"asset_id": args.id, "metadata": data})))
        return 0
    if command == "engagement":
        parser.add_argument("action", choices=["create", "update", "show"])
        parser.add_argument("--name")
        parser.add_argument("--scope-file")
        parser.add_argument("--exclude-file")
        parser.add_argument("--expires-at", help="Explicit authorization expiry as an ISO 8601 timestamp with timezone")
        parser.add_argument("--owner", default="Not determined")
        args = parser.parse_args(argv[1:])
        if args.action == "show":
            with read_database(args.output) as database:
                rows = [json.loads(row[0]) for row in database.execute("SELECT data FROM engagement_metadata")]
            print(json.dumps(redact_records(backend, rows), indent=2))
            return 0
        if not args.name or not args.scope_file:
            parser.error("create requires --name and --scope-file")
        scope = backend.load_scope(args.scope_file)
        exclusions = backend.load_targets(args.exclude_file) if args.exclude_file else []
        if not scope or any(not backend.ScopeGuard._valid_entry(entry) for entry in scope + exclusions):
            raise ValueError("Engagement requires a valid explicit scope")
        with local_operation(backend, args.output, {"tool": "local", "engagement": args.name, "scope": scope}) as store:
            AssessmentRepository(store, backend)
            if args.expires_at:
                parse_timestamp(args.expires_at)
            policy = {"scope": scope, "exclusions": exclusions, "expires_at": args.expires_at}
            record = {"id": args.name, "owner": args.owner, **policy, "recorded_at": backend.utc_now(),
                      "scope_version": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()}
            with store.connect() as database:
                database.execute("CREATE TABLE IF NOT EXISTS engagement_versions (id TEXT, version TEXT, at_utc TEXT, data TEXT)")
                existing = database.execute("SELECT 1 FROM engagement_metadata WHERE id=?", (args.name,)).fetchone()
                if bool(existing) != (args.action == "update"):
                    raise ValueError("Engagement already exists" if existing else "Engagement does not exist")
                database.execute("INSERT OR REPLACE INTO engagement_metadata VALUES (?, ?)", (args.name, json.dumps(record)))
                database.execute("INSERT INTO engagement_versions VALUES (?, ?, ?, ?)",
                                 (args.name, record["scope_version"], backend.utc_now(), json.dumps(record)))
        print(json.dumps(redact_records(backend, record), indent=2))
        return 0
    raise ValueError("Unsupported assessment command")

"""Evidence-bound analyst decisions and conservative configuration checks."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import uuid
from urllib.parse import urlsplit

import scanrunner_assessment as assessment
import scanrunner_rules as protocol_rules

RULE_VERSION = "4"
SMB_DIALECTS = {
    "202": "2.0.2", "210": "2.1", "300": "3.0", "302": "3.0.2", "311": "3.1.1",
    "2.0.2": "2.0.2", "2.1": "2.1", "3.0": "3.0", "3.0.2": "3.0.2", "3.1.1": "3.1.1",
    "2:0:2": "2.0.2", "2:1:0": "2.1", "3:0:0": "3.0", "3:0:2": "3.0.2", "3:1:1": "3.1.1",
}
STATUSES = {"Not Tested", "Potential", "Needs Verification", "Confirmed", "False Positive",
            "Accepted Risk", "Inconclusive", "Remediated (Verified)"}
RULES = {
    "smb2-security-mode": {
        "id": "SR-SMB-SIGNING", "title": "SMB signing requirement requires review",
        "ports": {139, 445}, "reference": "https://nmap.org/nsedoc/scripts/smb2-security-mode.html"},
    "smb-protocols": {
        "id": "SR-SMBV1", "title": "SMBv1 negotiation requires review",
        "ports": {139, 445}, "reference": "https://nmap.org/nsedoc/scripts/smb-protocols.html"},
}
RULES.update(protocol_rules.RULES)


def evaluate(observation):
    """Return a candidate outcome, with no automatic analyst confirmation."""
    rule = RULES.get(observation.get("check_id"))
    result = {"outcome": "Inconclusive", "rule_version": RULE_VERSION,
              "rule_id": rule["id"] if rule else "Unsupported check",
              "reason": "Missing validated check prerequisites"}
    native = observation.get("source_tool") == "scanrunner-probe" and observation.get("check_id") in {"ftp-anon", "sr-dns-recursion"}
    if (not rule or observation.get("transport") != rule.get("transport", "tcp")
            or observation.get("port") not in rule["ports"] and not native
            or observation.get("source_tool") != "nmap" and not native
            or observation.get("check_id") == "sr-dns-recursion" and not native
            or len(observation.get("addresses", [])) != 1 or observation.get("host_state") != "up"
            or observation.get("service_state") != "open"
            or observation.get("execution_outcome") not in {"COMPLETE", "Imported"}
            or observation.get("scan_completion") != "success"
            or observation.get("check_execution") != "Output observed"):
        return result
    if observation["check_id"] in protocol_rules.RULES:
        outcome, reason = protocol_rules.assess(observation)
        return {**result, "outcome": outcome, "reason": reason}
    output = observation.get("output", "").strip()
    if re.search(r"\b(error|failed|timeout|timed out|inconclusive)\b", output, re.I):
        return result
    structured = observation.get("structured", {})
    if observation["check_id"] == "smb2-security-mode":
        dialects = [node for node in structured.get("children", []) if node.get("tag") == "table"]
        if any(node.get("key") not in SMB_DIALECTS for node in dialects):
            return {**result, "reason": "Unsupported SMB dialect evidence"}
        values = [child.get("text", "").strip() for node in dialects for child in node.get("children", [])
                  if child.get("tag") == "elem"]
        supported = {"Message signing enabled and required": False,
                     "Message signing enabled but not required": True, "Message signing disabled": True}
        if not values or any(value not in supported for value in values):
            return result
        if {value for value in supported if value in output} != set(values):
            return {**result, "reason": "Structured and displayed evidence disagree"}
        # Conflicting settings within the same dialect are not a reliable observation.
        for dialect in {SMB_DIALECTS[node["key"]] for node in dialects}:
            settings = {child.get("text", "").strip() for node in dialects if SMB_DIALECTS[node["key"]] == dialect
                        for child in node.get("children", []) if child.get("tag") == "elem"}
            if len(settings) != 1:
                return {**result, "reason": "Contradictory dialect evidence"}
        positive = any(supported[value] for value in values)
    else:
        tables = [node for node in structured.get("children", []) if node.get("key") == "dialects"]
        values = [node.get("text", "").strip() for table in tables for node in table.get("children", [])
                  if node.get("tag") == "elem"]
        if not values or any(value not in SMB_DIALECTS and not re.fullmatch(r"NT LM 0\.12 \(SMBv1\)(?: \[[^\]]+\])?", value)
                             for value in values):
            return result
        if any(value not in output for value in values) or (("SMBv1" in output) != any("SMBv1" in value for value in values)):
            return {**result, "reason": "Structured and displayed evidence disagree"}
        positive = any(value.startswith("NT LM 0.12 (SMBv1)") for value in values)
    return {**result, "outcome": "Potential" if positive else "Not observed",
            "reason": "Explicit supported negotiation output"}


class FindingRepository:
    def __init__(self, store, backend):
        self.store = store
        self.backend = backend
        assessment.AssessmentRepository(store, backend)
        with store.connect() as database:
            database.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY, engagement TEXT NOT NULL, asset_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS finding_events (
                    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, at_utc TEXT NOT NULL,
                    reviewer TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS retest_events (
                    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, at_utc TEXT NOT NULL, data TEXT NOT NULL);
            """)

    def observation(self, database, identifier, engagement):
        row = database.execute(
            "SELECT o.data FROM security_observations o JOIN assets a ON a.id=o.asset_id WHERE o.id=? AND a.engagement=?",
            (identifier, engagement)).fetchone()
        if row is None:
            raise ValueError("Observation not found in this engagement")
        observation = json.loads(row[0])
        path = Path(observation["artifact"]).resolve()
        root = Path(self.store.directory).resolve() / ".scanrunner" / "runs"
        if not path.is_relative_to(root) or self.backend.file_sha256(path) != observation["raw_sha256"]:
            raise ValueError("Source evidence is missing, changed, or outside the evidence store")
        job = database.execute("SELECT * FROM jobs WHERE id=?", (observation["job_id"],)).fetchone()
        if job is None or not self.store.verify_job(job):
            raise ValueError("Source job evidence integrity failed")
        records = assessment.normalize_artifact(self.backend, path, observation["addresses"],
                                            {"id": job["id"], "run_id": job["run_id"]}, job["outcome"])
        matches = [(record, script) for record in records for script in record["scripts"]
                   if script["evidence_location"] == observation["evidence_location"]]
        if len(matches) != 1:
            raise ValueError("Observation does not identify a unique raw evidence location")
        record, script = matches[0]
        if sum(item["check_id"] == script["check_id"] and item["port"] == script["port"] and
               item["transport"] == script["transport"] for host in records
               if any(address["address"] in observation["addresses"] for address in host["addresses"])
               for item in host["scripts"]) != 1:
            raise ValueError("Duplicate check evidence requires contradiction review")
        expected = {**script, "addresses": [item["address"] for item in record["addresses"]],
                    "host_state": record["host_state"], "source_tool": record["source_tool"],
                    "tool_version": record["tool_version"], "observed_at": record["observed_at"],
                    "scan_completion": record["scan_completion"], "execution_outcome": job["outcome"],
                    "scanner_arguments": record["scanner_arguments"],
                    "imported": record["imported"], "parser_version": record["parser_version"],
                    "service_state": next((service["state"] for service in record["services"]
                                           if service["port"] == script["port"] and service["transport"] == script["transport"]), "Not determined")}
        if observation.get("parser_version") == "1":
            expected.update(parser_version="1", check_version="Scanner implementation")
        if any(observation.get(field) != value for field, value in expected.items()):
            raise ValueError("Stored observation disagrees with preserved raw evidence")
        return observation

    def create(self, engagement, observation_id, title=None):
        with self.store.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            observation = self.observation(database, observation_id, engagement)
            evaluation = evaluate(observation)
            identity = {"asset": observation["asset_id"], "check": observation["check_id"],
                        "port": observation.get("port"), "transport": observation.get("transport"), "engagement": engagement}
            identifier = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            previous = database.execute("SELECT data FROM findings WHERE id=?", (identifier,)).fetchone()
            if previous:
                return json.loads(previous[0])
            rule = RULES.get(observation["check_id"], {})
            data = {"id": identifier, "engagement": engagement, "asset_id": observation["asset_id"],
                    "observation_id": observation_id, "status": "Needs Verification",
                    "title": title or rule.get("title", "Scanner observation requires review"),
                    "description": "Not determined", "impact": "Not determined", "remediation": "Not determined",
                    "severity": "Not determined", "references": [rule["reference"]] if rule else [],
                    "affected_addresses": observation["addresses"], "port": observation.get("port"),
                    "transport": observation.get("transport"), "check_id": observation["check_id"],
                    "endpoint_association": observation.get("endpoint_association", "Not determined"),
                    "endpoint_evidence": observation.get("endpoint_evidence", observation["evidence_location"]),
                    "confidence": "Not determined",
                    "cvss_vector": "Not determined", "cvss_score": "Not determined",
                    "affected_hostnames": [item["name"] for item in observation.get("hostnames", [])] or "Not determined",
                    "analyst_notes": "Not determined",
                    "test_conditions": observation.get("preconditions", "Not determined"),
                    "retest_status": "Not tested",
                    "evaluation": evaluation, "evidence": {"artifact": observation["artifact"],
                    "sha256": observation["raw_sha256"], "location": observation["evidence_location"]},
                    "baseline_run": observation["run_id"], "created_at": self.backend.utc_now(),
                    "observed_at": observation["observed_at"], "source_tool": observation["source_tool"],
                    "tool_version": observation["tool_version"], "parser_version": observation["parser_version"],
                    "limitations": "Automated observation requires analyst verification", "reviewer": None}
            database.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)",
                             (identifier, engagement, observation["asset_id"], observation_id, data["status"], json.dumps(data)))
            self.event(database, identifier, "System", {"action": "Created", "status": data["status"], "evaluation": evaluation})
        return data

    def validate_final_export(self, engagement, records):
        with self.store.connect() as database:
            for finding in records:
                if finding["status"] != "Confirmed":
                    continue
                observation = self.observation(database, finding["observation_id"], engagement)
                if evaluate(observation)["outcome"] != "Potential" or finding["evaluation"].get("rule_version") != RULE_VERSION:
                    raise ValueError("Confirmed finding requires renewed review under the current evidence rule")
                row = database.execute("SELECT data FROM finding_events WHERE finding_id=? ORDER BY rowid DESC LIMIT 1", (finding["id"],)).fetchone()
                decision = json.loads(row[0]) if row else {}
                if (decision.get("to") != "Confirmed" or not decision.get("preconditions_and_impact_approved")
                        or decision.get("evidence_sha256") != observation["raw_sha256"]
                        or decision.get("approved_finding_sha256") != hashlib.sha256(json.dumps(finding, sort_keys=True).encode()).hexdigest()
                        or observation.get("imported", True) and not decision.get("import_origin_approved")):
                    raise ValueError("Confirmed finding lacks a matching analyst approval event")

    def event(self, database, identifier, reviewer, data):
        database.execute("INSERT INTO finding_events VALUES (?, ?, ?, ?, ?)",
                         (uuid.uuid4().hex, identifier, self.backend.utc_now(), reviewer, json.dumps(data)))

    def get(self, database, identifier, engagement):
        row = database.execute("SELECT data FROM findings WHERE id=? AND engagement=?", (identifier, engagement)).fetchone()
        if row is None:
            raise ValueError("Finding not found in this engagement")
        return json.loads(row[0])

    def review(self, engagement, identifier, status, reviewer, rationale, details, attest=False, trust_import=False):
        if status not in STATUSES or not reviewer.strip() or not rationale.strip():
            raise ValueError("A supported status, reviewer identity and rationale are required")
        if status == "Remediated (Verified)":
            raise ValueError("Verified remediation requires a comparable retest and explicit approval")
        allowed = {"title", "description", "impact", "remediation", "severity", "confidence", "references", "notes", "analyst_notes"}
        if not isinstance(details, dict) or not set(details) <= allowed:
            raise ValueError("Unsupported finding fields")
        if any(not isinstance(value, str) or not value.strip() for field, value in details.items() if field != "references"):
            raise ValueError("Finding text fields must contain nonempty text")
        references = details.get("references", [])
        if not isinstance(references, list) or any(not isinstance(value, str) or urlsplit(value).scheme not in {"http", "https"}
                                                 or not urlsplit(value).netloc for value in references):
            raise ValueError("References must be a list of HTTP or HTTPS source URLs")
        if "severity" in details and details["severity"] not in {"Not determined", "Informational", "Low", "Medium", "High", "Critical"}:
            raise ValueError("Unsupported severity")
        if "confidence" in details and details["confidence"] not in {"Not determined", "Low", "Medium", "High"}:
            raise ValueError("Unsupported confidence")
        with self.store.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            finding = self.get(database, identifier, engagement)
            observation = self.observation(database, finding["observation_id"], engagement)
            finding.update(details)
            evaluation = evaluate(observation)
            if status == "Confirmed":
                if not attest or evaluation["outcome"] != "Potential":
                    raise ValueError("Confirmation requires positive, unambiguous evidence and explicit prerequisite/impact approval")
                if observation.get("imported", True) and not trust_import:
                    raise ValueError("Imported evidence origin requires explicit analyst trust approval")
                if observation.get("tool_version", "Not determined") == "Not determined" or observation.get("observed_at") == "Not determined":
                    raise ValueError("Confirmation requires scanner version and observation time provenance")
                if any(not isinstance(finding.get(field), str) or finding[field].strip() in {"", "Not determined"}
                       for field in ("description", "impact", "remediation")):
                    raise ValueError("Confirmation requires reviewed description, impact and remediation")
                if not finding.get("references"):
                    raise ValueError("Confirmation requires supporting references")
            previous_status = finding["status"]
            finding.update(status=status, reviewer=reviewer, reviewed_at=self.backend.utc_now(), evaluation=evaluation)
            self.event(database, identifier, reviewer, {"action": "Reviewed", "from": previous_status, "to": status,
                       "rationale": rationale, "details": details, "preconditions_and_impact_approved": attest,
                       "import_origin_approved": trust_import, "evidence_sha256": observation["raw_sha256"],
                       "approved_finding_sha256": hashlib.sha256(json.dumps(finding, sort_keys=True).encode()).hexdigest()})
            database.execute("UPDATE findings SET status=?,data=? WHERE id=?", (status, json.dumps(finding), identifier))
        return finding

    def retest(self, engagement, identifier, run_id, reviewer=None, rationale=None, approve=False, trust_import=False):
        with self.store.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            finding = self.get(database, identifier, engagement)
            baseline = self.observation(database, finding["observation_id"], engagement)
            rows = database.execute("SELECT id,data FROM security_observations WHERE asset_id=? AND run_id=?",
                                    (finding["asset_id"], run_id)).fetchall()
            candidates = [row for row in rows if all(json.loads(row["data"]).get(field) == baseline.get(field)
                          for field in ("check_id", "port", "transport"))]
            outcome, comparable, evidence = "Not Retested", False, None
            if candidates:
                if len(candidates) != 1:
                    outcome = "Inconclusive"
                else:
                    current = self.observation(database, candidates[0]["id"], engagement)
                    evidence = {"observation_id": candidates[0]["id"], "sha256": current["raw_sha256"],
                                "artifact": current["artifact"], "location": current["evidence_location"],
                                "observed_at": current["observed_at"], "tool_version": current["tool_version"],
                                "addresses": current["addresses"], "port": current["port"], "transport": current["transport"]}
                    same_method = all(current.get(field) == baseline.get(field) for field in ("source_tool", "tool_version", "parser_version"))
                    configurations = [json.loads(database.execute("SELECT config FROM runs WHERE id=?", (record["run_id"],)).fetchone()[0])
                                      for record in (baseline, current)]
                    same_method = same_method and all(configurations[0].get(field) == configurations[1].get(field)
                                                     for field in ("tool", "options", "scope", "authorization_note"))
                    fingerprints = [database.execute("SELECT fingerprint FROM jobs WHERE id=?", (record["job_id"],)).fetchone()[0]
                                    for record in (baseline, current)]
                    same_method = same_method and fingerprints[0] == fingerprints[1]
                    if current.get("imported") or baseline.get("imported"):
                        same_method = same_method and current.get("scanner_arguments") not in {None, "Not determined"} and current.get("scanner_arguments") == baseline.get("scanner_arguments")
                    try:
                        later = datetime.fromisoformat(current["observed_at"]) > datetime.fromisoformat(baseline["observed_at"])
                    except (ValueError, TypeError):
                        later = False
                    evaluation = evaluate(current)
                    comparable = (run_id != baseline["run_id"] and later and same_method and
                                  current.get("check_execution") == "Output observed" and evaluation["outcome"] != "Inconclusive")
                    if comparable:
                        outcome = "Still Present" if evaluation["outcome"] == "Potential" else "Potentially Remediated"
                    else:
                        outcome = "Unable to Assess" if current.get("host_state") != "up" else "Inconclusive"
            if approve:
                if outcome != "Potentially Remediated" or finding["status"] != "Confirmed" or not reviewer or not rationale:
                    raise ValueError("Verified remediation needs a confirmed baseline, comparable negative evidence, reviewer and rationale")
                if baseline.get("tool_version", "Not determined") == "Not determined":
                    raise ValueError("Scanner version must be known for verified remediation")
                if current.get("imported", True) and not trust_import:
                    raise ValueError("Retest import origin requires explicit analyst trust approval")
                outcome = "Remediated (Verified)"
                finding.update(status=outcome, retest_status=outcome, reviewer=reviewer, reviewed_at=self.backend.utc_now())
                self.event(database, identifier, reviewer, {"action": "Remediation approved", "run_id": run_id,
                           "rationale": rationale, "evidence": evidence})
            data = {"id": uuid.uuid4().hex, "finding_id": identifier, "baseline_run": baseline["run_id"],
                    "new_run": run_id, "outcome": outcome, "comparable": comparable, "new_evidence": evidence,
                    "reviewer": reviewer, "rationale": rationale, "baseline_sha256": baseline["raw_sha256"]}
            if approve:
                finding["latest_retest"] = data
                database.execute("UPDATE findings SET status=?,data=? WHERE id=?", (outcome, json.dumps(finding), identifier))
            database.execute("INSERT INTO retest_events VALUES (?, ?, ?, ?)",
                             (data["id"], identifier, self.backend.utc_now(), json.dumps(data)))
        return data


def finding_view(record):
    defaults = {"cvss_vector": "Not determined", "cvss_score": "Not determined", "affected_hostnames": "Not determined",
                "analyst_notes": record.get("notes", "Not determined"), "test_conditions": "Not determined", "retest_status": "Not tested"}
    return {**defaults, **record}


def list_findings(directory, engagement, include_candidates=False):
    with assessment.read_database(directory) as database:
        if not database.execute("SELECT 1 FROM sqlite_master WHERE name='findings'").fetchone():
            return []
        records = [json.loads(row[0]) for row in database.execute("SELECT data FROM findings WHERE engagement=?", (engagement,))]
    return records if include_candidates else [record for record in records if record["status"] == "Confirmed"]


def cli(argv, backend):
    parser = argparse.ArgumentParser(prog="scanrunner " + argv[0])
    parser.add_argument("--output", "-o", default="results")
    parser.add_argument("--engagement", default="default")
    parser.add_argument("--json", action="store_true")
    if argv[0] == "retest":
        parser.add_argument("finding")
        parser.add_argument("--run", required=True)
        parser.add_argument("--reviewer")
        parser.add_argument("--rationale")
        parser.add_argument("--approve", action="store_true")
        parser.add_argument("--trust-import-origin", action="store_true")
        args = parser.parse_args(argv[1:])
        action = "retest"
    else:
        parser.add_argument("action", choices=["create", "list", "review", "history", "export"])
        parser.add_argument("--observation")
        parser.add_argument("--finding")
        parser.add_argument("--title")
        parser.add_argument("--status", choices=sorted(STATUSES))
        parser.add_argument("--reviewer")
        parser.add_argument("--rationale")
        parser.add_argument("--details", help="JSON file containing reviewed finding fields")
        parser.add_argument("--approve-preconditions-and-impact", action="store_true")
        parser.add_argument("--trust-import-origin", action="store_true")
        parser.add_argument("--include-candidates", action="store_true")
        parser.add_argument("--format", choices=["json", "csv", "html", "xlsx"], default="json")
        parser.add_argument("--destination")
        args = parser.parse_args(argv[1:])
        action = args.action
    if action in {"list", "export"}:
        records = list_findings(args.output, args.engagement, args.include_candidates or action == "list")
        if args.status:
            records = [record for record in records if record["status"] == args.status]
        if action == "export":
            if not args.destination:
                parser.error("export requires --destination")
            store = backend.RunStore(args.output, {"tool": "local", "engagement": args.engagement})
            try:
                FindingRepository(store, backend).validate_final_export(args.engagement, records)
            finally:
                store.end("Final export evidence checked")
            assessment.export_records(backend, [finding_view(record) for record in records], args.destination, args.format)
            return 0
        print(json.dumps(assessment.redact_records(backend, [finding_view(record) for record in records]), indent=2))
        return 0
    if action == "create" and not args.observation:
        parser.error("create requires --observation")
    if action != "create" and not args.finding:
        parser.error("this operation requires --finding")
    if action == "review" and (not args.status or not args.reviewer or not args.rationale):
        parser.error("review requires --status, --reviewer and --rationale")
    store = backend.RunStore(args.output, {"tool": "local", "engagement": args.engagement})
    try:
        repository = FindingRepository(store, backend)
        if action == "create":
            result = repository.create(args.engagement, args.observation, args.title)
        elif action == "review":
            details = json.loads(Path(args.details).read_text(encoding="utf-8")) if args.details else {}
            result = repository.review(args.engagement, args.finding, args.status, args.reviewer, args.rationale,
                                       details, args.approve_preconditions_and_impact, args.trust_import_origin)
        elif action == "retest":
            result = repository.retest(args.engagement, args.finding, args.run, args.reviewer, args.rationale, args.approve, args.trust_import_origin)
        else:
            with store.connect() as database:
                repository.get(database, args.finding, args.engagement)
                result = {"decisions": [dict(row) for row in database.execute("SELECT * FROM finding_events WHERE finding_id=? ORDER BY rowid", (args.finding,))],
                          "retests": [json.loads(row[0]) for row in database.execute("SELECT data FROM retest_events WHERE finding_id=? ORDER BY rowid", (args.finding,))]}
    except Exception:
        store.end("Local assessment operation failed")
        raise
    store.end("Local assessment operation completed")
    print(json.dumps(assessment.redact_records(backend, result), indent=2))
    return 0

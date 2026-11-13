"""Explicit optional scanner adapters with version, scope and evidence contracts."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit

import scanrunner_assessment as assessment

ADAPTERS = {
    "httpx": {"binary": "httpx", "version_args": ["-version", "-duc"], "format": "jsonl", "impact": "HTTP metadata requests"},
    "testssl": {"binary": "testssl.sh", "version_args": ["--version"], "format": "json", "impact": "Repeated TLS negotiation"},
    "nuclei": {"binary": "nuclei", "version_args": ["-version", "-duc"], "format": "jsonl", "impact": "Reviewed bounded HTTP template requests"},
}


def endpoint(value):
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use an HTTP(S) URL with a literal IP and no credentials, query or fragment")
    address = str(ipaddress.ip_address(parsed.hostname))
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid endpoint port")
    return address, port, parsed.scheme


def reviewed_template(path, expected_hash):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("Reviewed template hash mismatch or size limit exceeded")
    # JSON is a strict YAML subset, so a .yaml file containing this format is
    # accepted by Nuclei while permitting a small auditable template grammar.
    template = json.loads(raw)
    if not isinstance(template, dict) or set(template) != {"id", "info", "http"} or not re.fullmatch(r"[a-z0-9-]{1,80}", template.get("id", "")):
        raise ValueError("Only reviewed declarative HTTP templates are supported")
    info = template["info"]
    if not isinstance(info, dict) or set(info) - {"name", "author", "severity", "description", "reference", "tags"}:
        raise ValueError("Unsupported template metadata")
    requests = template["http"]
    if not isinstance(requests, list) or not 1 <= len(requests) <= 4:
        raise ValueError("Templates need one to four bounded requests")
    for request in requests:
        if set(request) - {"method", "path", "matchers", "matchers-condition"} or request.get("method") not in {"GET", "HEAD"}:
            raise ValueError("Only GET/HEAD template requests are allowed")
        paths = request.get("path")
        if not isinstance(paths, list) or not 1 <= len(paths) <= 4:
            raise ValueError("A bounded explicit path list is required")
        for value in paths:
            if not isinstance(value, str) or not re.fullmatch(r"\{\{BaseURL\}\}/[A-Za-z0-9_./%-]*", value) or ".." in value or "%" in value:
                raise ValueError("Template paths must stay under the selected endpoint")
        if request.get("matchers-condition", "or") not in {"and", "or"}:
            raise ValueError("Unsupported matcher condition")
        matchers = request.get("matchers")
        if not isinstance(matchers, list) or not 1 <= len(matchers) <= 8:
            raise ValueError("Explicit bounded matchers are required")
        for matcher in matchers:
            kind = matcher.get("type")
            if kind == "status":
                if set(matcher) != {"type", "status"} or not isinstance(matcher["status"], list) or not matcher["status"] or any(type(value) is not int or not 100 <= value <= 599 for value in matcher["status"]):
                    raise ValueError("Invalid status matcher")
            elif kind == "word":
                if set(matcher) - {"type", "words", "part", "condition"} or matcher.get("part", "body") not in {"body", "header", "all"}:
                    raise ValueError("Unsupported word matcher")
                if matcher.get("condition", "or") not in {"and", "or"} or not isinstance(matcher.get("words"), list) or not matcher["words"]:
                    raise ValueError("Invalid word matcher")
                if any(not isinstance(word, str) or not word or len(word) > 1024 or "{{" in word for word in matcher["words"]):
                    raise ValueError("Word matcher must use bounded literal text")
            else:
                raise ValueError("Unsupported matcher type")
    return raw


def build_argv(tool, binary, target, directory, template=None):
    directory = Path(directory)
    config = str(directory / "config.yaml")
    address, _, _ = endpoint(target)
    if tool == "httpx":
        return [binary, "-u", target, "-json", "-silent", "-status-code", "-title", "-no-stdin", "-duc",
                "-config", config, "-allow", address, "-t", "1", "-rl", "1", "-timeout", "10", "-retries", "0", "-nfs"]
    if tool == "nuclei":
        if template is None:
            raise ValueError("Nuclei requires a reviewed template")
        return [binary, "-u", target, "-t", str(template), "-jsonl", "-silent", "-no-stdin", "-duc", "-ni", "-dr",
                "-config", config, "-c", "1", "-bs", "1", "-rl", "1", "-timeout", "10", "-retries", "0", "-nh"]
    return [binary, "--quiet", "--warnings", "off", "--color", "0", "--nodns", "none", "--ip", address,
            "--protocols", "--cipher-per-proto", "--jsonfile", str(directory / "tool-output.json"), target]


def isolated_environment(directory):
    environment = {key: value for key, value in os.environ.items() if key.upper() in
                   {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "LANG", "LC_ALL"}}
    home = Path(directory) / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "NUCLEI_CONFIG_DIR"):
        environment[name] = str(home)
    for name in ("PUBLIC", "GITHUB", "GITLAB", "AWS", "AZURE"):
        environment["DISABLE_NUCLEI_TEMPLATES_" + name + "_DOWNLOAD"] = "true"
    environment.update(PHONE_OUT="false", NODNS="none", PYTHONUTF8="1")
    return environment


def parse_output(tool, path, target):
    path = Path(path)
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Plugin output exceeds size limit")
    wanted = endpoint(target)
    content = path.read_text(encoding="utf-8")
    rows = json.loads(content) if tool == "testssl" else [json.loads(line) for line in content.splitlines() if line.strip()]
    if not isinstance(rows, list) or len(rows) > 100000:
        raise ValueError("Plugin output needs a bounded record array")
    results = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError("Invalid plugin record")
        if tool == "testssl":
            if row.get("severity") == "FATAL":
                raise ValueError("TLS scanner reported a fatal execution diagnostic")
            if row.get("id") == "cmdline_ip-target" and row.get("severity") == "WARN" and row.get("ip") == "/":
                # testssl 3.2.5 emits this startup diagnostic before assigning its
                # endpoint. It remains in the raw artifact, outside control facts.
                continue
            encoded_subject = row.get("ip", "")
            if not isinstance(encoded_subject, str):
                raise ValueError("Invalid TLS endpoint")
            parts = encoded_subject.split("/")
            subject = str(ipaddress.ip_address(parts[-1].strip("[]")))
            if len(parts) > 2 or len(parts) == 2 and str(ipaddress.ip_address(parts[0].strip("[]"))) != wanted[0]:
                raise ValueError("TLS target name disagrees with the explicitly selected IP")
            if subject != wanted[0] or int(row.get("port", -1)) != wanted[1] or not isinstance(row.get("id"), str) or not isinstance(row.get("finding"), str):
                raise ValueError("TLS result subject or schema mismatch")
            data = {key: row.get(key) for key in ("id", "finding", "severity")}
            check = row["id"]
        else:
            url = row.get("url") if tool == "httpx" else row.get("matched-at")
            if not isinstance(url, str) or endpoint(url) != wanted:
                raise ValueError("Plugin output contains an unassociated endpoint")
            if tool == "httpx":
                returned_ip = row.get("host") or row.get("ip")
                if returned_ip is not None and str(ipaddress.ip_address(returned_ip)) != wanted[0]:
                    raise ValueError("HTTP response address disagrees with the selected target")
                if type(row.get("status_code")) is not int or not 100 <= row["status_code"] <= 599:
                    raise ValueError("Missing valid HTTP response status")
                data = {key: row.get(key) for key in ("status_code", "title", "webserver", "content_type")}
                check = "http-metadata"
            else:
                if not isinstance(row.get("template-id"), str) or not row["template-id"]:
                    raise ValueError("Nuclei match lacks template identity")
                check = row["template-id"]
                data = {"template_id": check, "matcher_name": row.get("matcher-name", "Not determined")}
        results.append({"check_id": check, "address": wanted[0], "port": wanted[1], "transport": "tcp",
                        "data": data, "evidence_location": (f"/records/{index}" if tool == "testssl" else f"/lines/{index}"),
                        "outcome": "Observed" if tool == "httpx" else "Needs Verification", "verification_status": "Needs Verification"})
    grouped = {}
    for result in results:
        grouped.setdefault(result["check_id"], set()).add(json.dumps(result["data"], sort_keys=True))
    if tool == "testssl":
        for result in results:
            if len(grouped[result["check_id"]]) > 1:
                result["outcome"] = "Inconclusive"
    return results


def persist(store, job, records, artifact, tool, version, imported=False):
    digest = hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
    with store.connect() as database:
        database.execute("CREATE TABLE IF NOT EXISTS plugin_observations (id TEXT PRIMARY KEY, engagement TEXT, run_id TEXT, data TEXT)")
        for record in records:
            identifier = hashlib.sha256((job["id"] + record["evidence_location"] + record["check_id"]).encode()).hexdigest()
            data = {**record, "id": identifier, "source_tool": tool, "tool_version": version, "parser_version": "1",
                    "run_id": store.run_id, "job_id": job["id"], "artifact": str(Path(artifact).resolve()),
                    "raw_sha256": digest, "observed_at": store.config.get("capture_started_at", "Not determined"),
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "imported": imported, "confidence": "Unverified"}
            database.execute("INSERT INTO plugin_observations VALUES (?, ?, ?, ?)",
                             (identifier, store.config.get("engagement", "default"), store.run_id, json.dumps(data)))


def persist_nxc(store, job, rows, protocol):
    artifact = Path(job["directory"]) / "stdout.bin"
    lines = artifact.read_text(encoding="utf-8", errors="replace").splitlines()
    records = []
    for row in rows:
        address = row.get("target", "")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        if not str(row.get("port", "")).isdigit():
            continue
        matching = [index for index, line in enumerate(lines, 1) if re.search(r"(?<![\w.])" + re.escape(address) + r"(?![\w.])", line)]
        for field in ("os", "hostname", "smbv1", "smb_signing", "null_auth", "rdp_nla"):
            value = row.get(field)
            if not value:
                continue
            records.append({"check_id": "nxc-" + protocol + "-" + field, "address": address, "port": int(row["port"]), "transport": "tcp",
                "data": {field: value}, "evidence_location": "/lines/" + ",".join(map(str, matching)) + "/" + field,
                "outcome": "Inconclusive" if "inconclusive" in str(value).lower() or not matching else "Observed",
                "verification_status": "Needs Verification"})
    persist(store, job, records, artifact, "nxc", store.config.get("tool_version", "Not determined"))


def cli(argv, backend):
    parser = argparse.ArgumentParser(prog="scanrunner plugin")
    parser.add_argument("action", choices=["list", "run", "import", "observations"])
    parser.add_argument("--adapter", choices=ADAPTERS)
    parser.add_argument("--target")
    parser.add_argument("--scope-file")
    parser.add_argument("--output", "-o", default="results")
    parser.add_argument("--engagement", default="default")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--authorization-note")
    parser.add_argument("--expected-version")
    parser.add_argument("--binary")
    parser.add_argument("--artifact")
    parser.add_argument("--template")
    parser.add_argument("--template-sha256")
    parser.add_argument("--template-reviewed-by")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.action == "list":
        print(json.dumps({name: {**spec, "path": shutil.which(spec["binary"])} for name, spec in ADAPTERS.items()}, indent=2))
        return 0
    if args.action == "observations":
        with assessment.read_database(args.output) as database:
            exists = database.execute("SELECT 1 FROM sqlite_master WHERE name='plugin_observations'").fetchone()
            rows = [json.loads(row[0]) for row in database.execute("SELECT data FROM plugin_observations WHERE engagement=?", (args.engagement,))] if exists else []
        if rows:
            verified = {job["id"] for job in backend.review_run_history(args.output)["jobs"] if job["evidence_integrity"] == "Verified"}
            root = (Path(args.output) / ".scanrunner" / "runs").resolve()
            for row in rows:
                path = Path(row["artifact"]).resolve()
                if not path.is_relative_to(root) or row["job_id"] not in verified or backend.file_sha256(path) != row["raw_sha256"]:
                    raise ValueError("Plugin observation evidence is missing, modified or outside the assessment store")
        print(json.dumps(assessment.redact_records(backend, rows), indent=2))
        return 0
    if not args.adapter or not args.target or not args.scope_file or not args.expected_version:
        raise ValueError("Adapter, target URL, scope and expected tool version are required")
    address, _, _ = endpoint(args.target)
    policy = assessment.engagement_policy(args.output, args.engagement)
    guard = backend.ScopeGuard([address], backend.load_scope(args.scope_file), policy.get("exclusions", []) if policy else [])
    if policy and (not backend.target_in_scope(address, policy["scope"]) or policy.get("expires_at")
                   and assessment.parse_timestamp(policy["expires_at"]) <= datetime.now(timezone.utc)):
        raise ValueError("Plugin target exceeds current engagement authorization")
    template_bytes = None
    if args.adapter == "nuclei":
        if not args.template or not args.template_sha256 or not args.template_reviewed_by:
            raise ValueError("Nuclei requires an exact reviewed template hash and reviewer")
        template_bytes = reviewed_template(args.template, args.template_sha256)
    if args.action == "run" and (not args.enable or not args.authorization_note or not args.authorization_note.strip()):
        raise ValueError("Plugin execution requires explicit enablement and authorization note")
    spec = ADAPTERS[args.adapter]
    binary = args.binary or shutil.which(spec["binary"]) or spec["binary"]
    if args.dry_run:
        print(json.dumps({"adapter": args.adapter, "impact": spec["impact"], "expected_version": args.expected_version,
                          "argv": build_argv(args.adapter, binary, args.target, "FRESH_RUN_DIRECTORY", "REVIEWED_TEMPLATE.yaml" if template_bytes else None)}, indent=2))
        return 0
    if args.action == "run" and not Path(binary).is_file():
        raise ValueError("Optional scanner is unavailable, install it separately")
    config = {"tool": "plugin", "adapter": args.adapter, "tool_version": args.expected_version, "target_url": args.target,
              "capture_started_at": backend.utc_now() if args.action == "run" else "Not determined",
              "engagement": args.engagement, "scope": guard.scope, "template_sha256": args.template_sha256,
              "template_reviewed_by": args.template_reviewed_by, "authorization_note": backend.redact_output_text(args.authorization_note or "Imported evidence")}
    with assessment.local_operation(backend, args.output, config) as store:
        job = store.wait_claim(address)
        if job is None:
            raise ValueError("Plugin target already claimed")
        directory = Path(job["directory"])
        artifact = directory / ("tool-output.json" if args.adapter == "testssl" else "stdout.bin")
        code, state, status, command = None, "Interrupted", "Interrupted", ["import", args.adapter]
        try:
            if args.action == "import":
                if not args.artifact:
                    raise ValueError("Import requires an existing raw artifact")
                shutil.copyfile(args.artifact, artifact)
                if artifact.name != "stdout.bin":
                    (directory / "stdout.bin").write_bytes(b"")
                (directory / "stderr.bin").write_bytes(b"")
                code, state = 0, "Exited"
            else:
                environment = isolated_environment(directory)
                (directory / "config.yaml").write_text("{}\n", encoding="utf-8")
                identity = backend.file_sha256(binary)
                result = subprocess.run([binary, *spec["version_args"]], capture_output=True, timeout=10, env=environment)
                version_bytes = result.stdout + result.stderr
                (directory / "version.bin").write_bytes(version_bytes)
                if result.returncode != 0 or not re.search(r"(?<![\d.])v?" + re.escape(args.expected_version) + r"(?![\d.])", version_bytes.decode("utf-8", errors="replace")):
                    raise ValueError("Scanner version does not match the explicitly selected version")
                template_path = directory / "reviewed-template.yaml"
                if template_bytes:
                    template_path.write_bytes(template_bytes)
                command = build_argv(args.adapter, binary, args.target, directory, template_path if template_bytes else None)
                guard.destinations(address)
                if backend.file_sha256(binary) != identity:
                    raise ValueError("Scanner binary changed before execution")
                (directory / "binary-identity.json").write_text(json.dumps({"path": str(Path(binary).resolve()), "sha256": identity}), encoding="utf-8")
                code, state = backend.capture_process(command, str(directory), timeout=300, environment=environment)
                if backend.file_sha256(binary) != identity:
                    raise ValueError("Scanner binary changed during execution")
            records = parse_output(args.adapter, artifact, args.target)
            if args.adapter == "nuclei" and records:
                template_id = json.loads(template_bytes)["id"]
                if any(record["check_id"] != template_id for record in records):
                    raise ValueError("Nuclei output does not match the reviewed template")
            status = "Imported" if args.action == "import" else "Observed" if code == 0 and state == "Exited" and records else "INCONCLUSIVE"
            records = [{**record, "execution_outcome": status,
                        "outcome": "Inconclusive" if status == "INCONCLUSIVE" else record["outcome"]} for record in records]
            persist(store, job, records, artifact, args.adapter, args.expected_version, args.action == "import")
        except Exception:
            status = "FAILED"
            raise
        finally:
            store.finish_job(job, status, code, status in {"Observed", "Imported"}, command)
        print(json.dumps({"run_id": store.run_id, "outcome": status, "observations": len(records)}))
        return 0 if status in {"Observed", "Imported"} else 1

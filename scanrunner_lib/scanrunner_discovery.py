"""Explicitly scoped, optional PingMe reachability discovery."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

from scanrunner_lib import scanrunner_assessment as assessment
from scanrunner_lib import scanrunner_plugins as plugins
from scanrunner_lib.scanrunner_help import parser as command_parser, command_line

SUPPORTED_VERSION = "3.3.0"
LIMIT = 256


def expand_targets(values):
    """Expand bounded literal addresses/CIDRs without DNS or discovery pivots."""
    addresses = set()
    for value in values:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses > LIMIT:
            raise ValueError(f"Discovery is limited to {LIMIT} addresses; split the target list")
        for address in network.hosts():
            if address.is_unspecified or address.is_multicast or address == ipaddress.ip_address("255.255.255.255"):
                raise ValueError("Discovery requires unicast addresses")
            addresses.add(str(address))
        if len(addresses) > LIMIT:
            raise ValueError(f"Discovery is limited to {LIMIT} addresses")
    if not addresses:
        raise ValueError("Supply --target IP/CIDR or --file containing literal IPs/CIDRs")
    return sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))


def parse_results(directory, addresses, tcp_ports):
    """Require one associated, internally consistent result per selected address."""
    seen, parsed = set(), []
    for filename, status in (("alive.json", "REACHABLE"), ("no-response.json", "NO RESPONSE"), ("errors.json", "PROBE ERROR")):
        path = Path(directory) / filename
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("PingMe report exceeds size limit")
        rows = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(rows, list) or len(rows) > LIMIT:
            raise ValueError("Unsupported PingMe result schema")
        records = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError("Unsupported PingMe result row")
            address = str(ipaddress.ip_address(row.get("ip", "")))
            if address not in addresses or address in seen:
                raise ValueError("PingMe output has an unexpected or duplicate address")
            seen.add(address)
            if row.get("status") != status or type(row.get("alive")) is not bool or row["alive"] != (status == "REACHABLE"):
                raise ValueError("Contradictory PingMe reachability result")
            ports = row.get("tcp_open", [])
            if not isinstance(ports, list) or any(type(port) is not int or port not in tcp_ports for port in ports):
                raise ValueError("PingMe reported a TCP port outside the selected probes")
            if type(row.get("icmp_alive")) is not bool or (status == "REACHABLE" and not (row["icmp_alive"] or ports)
                    or status == "NO RESPONSE" and (row["icmp_alive"] or ports)):
                raise ValueError("PingMe reachability lacks consistent ICMP/TCP evidence")
            record = {"check_id": "pingme-reachability", "check_version": "1", "address": address,
                      "port": None, "transport": "icmp/tcp" if tcp_ports else "icmp",
                      "outcome": status, "status": "Needs Verification", "evidence_location": f"{filename}:$[{index}]",
                      "facts": {key: row.get(key) for key in ("icmp_alive", "tcp_open", "ttl", "rtt_avg", "loss_pct", "probe_error")},
                      "limitations": "Time-bound reachability only. No response does not prove offline; TCP acceptance may be a proxy. No service or OS identification is established."}
            records.append(record)
        parsed.append((path, records))
    if seen != set(addresses):
        raise ValueError("PingMe output is incomplete; missing targets remain unassessed")
    return parsed


def build_argv(script, directory, ports):
    directory = Path(directory)
    argv = [sys.executable, "-I", "-B", str(script), "--no-config", "--no-history", "--no-dns", "--no-arp",
            "--file", str(directory / "targets.txt"), "--ping-tool", "ping", "--threads", "4", "--rate", "10",
            "--count", "3", "--min-replies", "2", "--retry", "0", "--timeout", "1", "--tcp-timeout", "1",
            "--out-format", "json", "--alive-out", str(directory / "alive.json"),
            "--dead-out", str(directory / "no-response.json"), "--error-out", str(directory / "errors.json"),
            "--hostnames-out", str(directory / "hostnames.json"), "--color", "never", "--quiet", "--no-banner"]
    if ports:
        argv += ["--tcp-ports", ",".join(map(str, ports))]
    return argv


def cli(argv, backend):
    parser = command_parser("discover")
    parser.add_argument("--target", "-i", action="append", default=[], help="Authorized literal IP/CIDR; repeat for multiple targets")
    parser.add_argument("--file", "-f", help="Target file containing literal IPs/CIDRs, one per line")
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--pingme-script", required=True, help="Path to your separately installed PingMe 3.3.0 pingme.py")
    parser.add_argument("--authorization-note", required=True)
    parser.add_argument("--tcp-ports", default="", help="Optional comma-separated TCP connect ports; at most 16 (default ICMP only)")
    parser.add_argument("--output", "-o", default="results")
    parser.add_argument("--engagement", default="default")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable discovery summary and next preview command")
    args = parser.parse_args(argv)
    values = args.target + (backend.load_scope(args.file) if args.file else [])
    addresses = expand_targets(values)
    ports = sorted({int(port) for port in args.tcp_ports.split(",") if port})
    if len(ports) > 16 or any(not 1 <= port <= 65535 for port in ports) or not args.authorization_note.strip():
        raise ValueError("Select at most 16 valid TCP ports and supply an authorization note")
    policy = assessment.engagement_policy(args.output, args.engagement)
    if policy and policy.get("expires_at") and assessment.parse_timestamp(policy["expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("Engagement authorization expired")
    scope = backend.load_scope(args.scope_file)
    if not scope:
        raise ValueError("Discovery requires a nonempty explicit scope file")
    # Literal scope/exclusions keep previews and PingMe execution free of DNS lookups.
    for value in [*scope, *(policy.get("exclusions", []) if policy else []), *(policy.get("scope", []) if policy else [])]:
        ipaddress.ip_network(value, strict=False)
    guard = backend.ScopeGuard(addresses, scope, policy.get("exclusions", []) if policy else [])
    for address in addresses:
        guard.destinations(address)
        if policy and not backend.target_in_scope(address, policy["scope"]):
            raise ValueError("Discovery target exceeds engagement authorization")
    script = Path(args.pingme_script).expanduser().resolve()
    impact = "Up to 5 ICMP attempts per address, 4 workers, ICMP rate 10/s; optional TCP connect probes have a separate rate. No DNS, ARP, notifications, watch mode or scan chaining."
    if args.dry_run:
        print(json.dumps({"tool": "PingMe", "supported_version": SUPPORTED_VERSION, "addresses": addresses,
                          "tcp_ports": ports, "impact": impact, "output": str(Path(args.output).resolve()),
                          "argv": build_argv(script, Path(args.output).resolve() / "FRESH_JOB_DIRECTORY", ports)}, indent=2))
        return 0
    if not script.is_file():
        raise ValueError("PingMe is optional; install its repository separately and supply --pingme-script PATH/pingme.py")
    identity = backend.file_sha256(script)
    config = {"tool": "pingme", "tool_version": SUPPORTED_VERSION, "script_sha256": identity, "targets": addresses,
              "engagement": args.engagement, "scope": guard.scope, "exclusions": guard.exclusions,
              "script_path": str(script), "tcp_ports": ports, "timeout": 600,
              "capture_started_at": backend.utc_now(), "authorization_note": backend.redact_output_text(args.authorization_note)}
    with assessment.local_operation(backend, args.output, config) as store:
        job = store.wait_claim("pingme-" + hashlib.sha256(json.dumps(addresses).encode()).hexdigest()[:16])
        if job is None:
            raise ValueError("Discovery job already claimed or cancelled")
        directory = Path(job["directory"]).resolve()
        environment = plugins.isolated_environment(directory)
        environment["PINGME_DATA_DIR"] = str(directory / "home" / "pingme-data")
        command, code, state, status = [], None, "Interrupted", "Interrupted"
        records = []
        try:
            version = subprocess.run([sys.executable, "-I", "-B", str(script), "--no-config", "--version"],
                                     capture_output=True, timeout=10, env=environment)
            (directory / "version.bin").write_bytes(version.stdout + version.stderr)
            if version.returncode != 0 or not re.fullmatch(r"pingme 3\.3\.0 \(reliable-cross-platform\)", version.stdout.decode("utf-8").strip(), re.IGNORECASE):
                raise ValueError("Supported PingMe version is 3.3.0; installed version did not match")
            (directory / "targets.txt").write_text("\n".join(addresses) + "\n", encoding="utf-8")
            for address in addresses:
                guard.destinations(address)
            if policy and policy.get("expires_at") and assessment.parse_timestamp(policy["expires_at"]) <= datetime.now(timezone.utc):
                raise ValueError("Engagement authorization expired before execution")
            if backend.file_sha256(script) != identity:
                raise ValueError("PingMe script changed before execution")
            command = build_argv(script, directory, ports)
            if not args.json:
                print(f"Running PingMe {SUPPORTED_VERSION}: {len(addresses)} scoped address(es), ICMP"
                      + (" plus TCP " + ",".join(map(str, ports)) if ports else " only")
                      + ". Deadline: 600 seconds.", flush=True)
            code, state = backend.capture_process(command, str(directory), timeout=600, environment=environment)
            if backend.file_sha256(script) != identity:
                raise ValueError("PingMe script changed during execution")
            if state != "Exited" or code not in {0, 1, 4}:
                raise ValueError("PingMe failed or was interrupted; inspect preserved stderr and partial evidence")
            parsed = parse_results(directory, addresses, ports)
            records = [record for _, rows in parsed for record in rows]
            expected_code = 4 if any(row["outcome"] == "PROBE ERROR" for row in records) else 1 if any(row["outcome"] == "NO RESPONSE" for row in records) else 0
            if code != expected_code:
                raise ValueError("PingMe exit code contradicts its result files")
            status = "INCONCLUSIVE" if code == 4 else "Observed"
            for path, rows in parsed:
                plugins.persist(store, job, [{**row, "execution_outcome": status} for row in rows], path, "pingme", SUPPORTED_VERSION)
            (directory / "reachable.txt").write_text("".join(row["address"] + "\n" for row in records if row["outcome"] == "REACHABLE"), encoding="utf-8")
        except BaseException:
            status = "FAILED"
            raise
        finally:
            store.finish_job(job, status, code, status == "Observed", command)
        result = {"run_id": store.run_id, "outcome": status, "counts": {label: sum(row["outcome"] == label for row in records)
                  for label in ("REACHABLE", "NO RESPONSE", "PROBE ERROR")}, "reachable_file": str(directory / "reachable.txt"),
                  "limitations": "No response is not proof of offline. Review all original targets for coverage.",
                  "next_preview": command_line(["-f", str(directory / "reachable.txt"), "--scope-file", str(Path(args.scope_file).resolve()),
                                                "--engagement", args.engagement, "--profile", "safe-baseline", "--skip-ping", "-o", args.output, "--dry-run"])}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("PingMe discovery results")
            for record in records:
                print(f"  {record['address']:<40} {record['outcome']}")
            print("\n" + result["limitations"] + "\nReachable list: " + result["reachable_file"])
            if result["counts"]["REACHABLE"]:
                print("Preview a later scan of reachable hosts only:\n  " + result["next_preview"])
            print("Evidence: scanrunner plugin observations -o " + args.output)
        return 1 if status == "INCONCLUSIVE" else 0

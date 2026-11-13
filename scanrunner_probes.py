"""Explicit scoped FTP authentication and controlled DNS recursion probes."""
from scanrunner_help import parser as command_parser
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import struct
import time

import scanrunner_assessment as assessment


def dns_name(packet, offset, seen=None):
    seen = set() if seen is None else seen
    labels = []
    end = None
    while True:
        if offset in seen or len(seen) > 128 or offset >= len(packet):
            raise ValueError("Invalid compressed DNS name")
        seen.add(offset)
        size = packet[offset]
        offset += 1
        if size & 0xC0 == 0xC0:
            if offset >= len(packet):
                raise ValueError("Truncated DNS pointer")
            pointer = ((size & 63) << 8) | packet[offset]
            label, _ = dns_name(packet, pointer, seen)
            labels.append(label)
            end = offset + 1
            break
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            raise ValueError("Invalid DNS label")
        labels.append(packet[offset:offset + size].decode("ascii").lower())
        offset += size
    return ".".join(labels), end if end is not None else offset


def dns_question(name, recursive):
    labels = name.rstrip(".").lower().split(".")
    if len(name) > 253 or any(not label or len(label) > 63 or not all(character.isalnum() or character == "-" for character in label) for label in labels):
        raise ValueError("Invalid canary DNS name")
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return struct.pack("!HHHHHH", secrets.randbelow(65536), 256 if recursive else 0, 1, 0, 0, 0) + encoded + struct.pack("!HH", 1, 1)


def dns_response(request, response):
    if len(request) < 17 or len(response) < 12 or response[:2] != request[:2]:
        raise ValueError("Unassociated DNS response")
    _, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", response)
    if not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or questions != 1 or answers > 128:
        raise ValueError("Invalid or truncated DNS response")
    if flags & 0x0100 != struct.unpack_from("!H", request, 2)[0] & 0x0100:
        raise ValueError("DNS response does not echo the requested recursion flag")
    name, offset = dns_name(response, 12)
    requested_name, requested_end = dns_name(request, 12)
    if name != requested_name or response[offset:offset + 4] != request[requested_end:requested_end + 4]:
        raise ValueError("DNS question mismatch")
    offset += 4
    addresses = []
    for _ in range(answers):
        owner, offset = dns_name(response, offset)
        if offset + 10 > len(response):
            raise ValueError("Truncated DNS resource record")
        kind, family, _, length = struct.unpack_from("!HHIH", response, offset)
        offset += 10
        if offset + length > len(response):
            raise ValueError("Truncated DNS answer")
        if kind == family == 1 and length == 4 and owner == name:
            addresses.append(str(ipaddress.ip_address(response[offset:offset + length])))
        offset += length
    return {"rcode": flags & 15, "ra": bool(flags & 128), "aa": bool(flags & 1024), "answers": addresses}


def interpret(proof):
    exchanges = proof["exchanges"]
    if proof["check_id"] == "ftp-anon":
        replies = []
        commands = []
        for exchange in exchanges:
            command = bytes.fromhex(exchange["request_hex"])
            response = bytes.fromhex(exchange["response_hex"])
            lines = response.splitlines()
            if not lines or len(lines[0]) < 4 or not lines[0][:3].isdigit() or not lines[-1].startswith(lines[0][:3] + b" "):
                raise ValueError("Malformed FTP response")
            replies.append(int(lines[0][:3]))
            commands.append(command)
        valid = commands in ([b"", b"USER anonymous\r\n"], [b"", b"USER anonymous\r\n", b"PASS scanrunner@example.invalid\r\n"])
        if not valid or replies[0] != 220 or len(replies) == 3 and replies[1] != 331:
            raise ValueError("Invalid anonymous authentication transcript")
        if replies[-1] == 230:
            return "Anonymous FTP login allowed (FTP code 230)"
        if replies[-1] == 530:
            return "Anonymous FTP login rejected (FTP code 530)"
        return "Anonymous FTP authentication outcome inconclusive"
    if len(exchanges) != 2:
        raise ValueError("DNS requires nonrecursive and recursive controls")
    packets = [(bytes.fromhex(item["request_hex"]), bytes.fromhex(item["response_hex"])) for item in exchanges]
    if any(len(request) < 17 or len(response) < 12 for request, response in packets):
        raise ValueError("Missing DNS wire header")
    if (struct.unpack_from("!H", packets[0][0], 2)[0] != 0 or struct.unpack_from("!H", packets[1][0], 2)[0] != 256
            or packets[0][0][12:] != packets[1][0][12:]):
        raise ValueError("DNS controls do not match")
    control, recursive = [dns_response(*item) for item in packets]
    expected = str(ipaddress.IPv4Address(proof["expected_answer"]))
    if control["rcode"] == recursive["rcode"] == 5:
        return "Controlled recursion rejected (DNS REFUSED)"
    if (not control["answers"] and recursive["ra"] and not recursive["aa"] and recursive["rcode"] == 0
            and expected in recursive["answers"]):
        return "Controlled recursion verified with matching canary answer and nonrecursive control"
    return "Controlled DNS recursion outcome inconclusive"


def normalize(backend, path, target, job, outcome="COMPLETE"):
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Probe artifact exceeds size limit")
    proof = json.loads(path.read_bytes())
    required = {"schema_version", "address", "port", "check_id", "observed_at", "exchanges"}
    if not isinstance(proof, dict) or not required <= proof.keys() or not isinstance(proof["exchanges"], list) or not 1 <= len(proof["exchanges"]) <= 3:
        raise ValueError("Invalid probe evidence schema")
    if (type(proof["schema_version"]) is not int or any(not isinstance(proof[key], str) for key in ("address", "check_id", "observed_at"))
            or proof["check_id"] == "sr-dns-recursion" and not isinstance(proof.get("expected_answer"), str)):
        raise ValueError("Invalid probe identity or timestamp")
    if any(not isinstance(item, dict) or set(item) != {"request_hex", "response_hex"}
           or any(not isinstance(value, str) or len(value) > 131072 for value in item.values()) for item in proof["exchanges"]):
        raise ValueError("Invalid protocol transcript")
    address = str(ipaddress.ip_address(proof["address"]))
    targets = [target] if isinstance(target, str) else target
    if not backend.target_in_scope(address, targets) or proof.get("schema_version") != 1 or proof["check_id"] not in {"ftp-anon", "sr-dns-recursion"}:
        raise ValueError("Probe subject or schema mismatch")
    port = proof["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid probe port")
    assessment.parse_timestamp(proof["observed_at"])
    output = interpret(proof)
    transport = "tcp" if proof["check_id"] == "ftp-anon" else "udp"
    script = {"check_id": proof["check_id"], "check_version": "1", "port": port, "transport": transport,
              "output": output, "fields": [], "structured": {}, "evidence_location": "/exchanges",
              "endpoint_association": "Direct socket peer", "confidence": "Unverified", "check_execution": "Output observed"}
    return [{"target": address, "input_targets": targets, "addresses": [{"address": address, "family": "ipv4" if ":" not in address else "ipv6", "source": "/address"}],
             "hostnames": [], "host_state": "up", "service_address": address, "os_guesses": [],
             "services": [{"port": port, "transport": transport, "state": "open", "service": "ftp" if transport == "tcp" else "domain", "evidence_location": "/exchanges"}],
             "scripts": [script], "run_id": job["run_id"], "job_id": job["id"], "observed_at": proof["observed_at"],
             "execution_outcome": outcome, "source_tool": "scanrunner-probe", "tool_version": "1", "scanner_arguments": "Direct controlled protocol probe",
             "parser_version": assessment.PARSER_VERSION, "raw_sha256": backend.file_sha256(path), "artifact": str(path.resolve()),
             "evidence_location": "/", "imported": outcome == "Imported", "scan_completion": "success", "limitations": "A single explicitly authorized protocol control"}]


def ftp_exchange(address, port, exchanges):
    with socket.create_connection((address, port), timeout=5) as connection:
        buffer = bytearray()
        deadline = time.monotonic() + 12
        def receive(command):
            if command:
                connection.sendall(command)
            lines = []
            code = None
            while time.monotonic() < deadline:
                if b"\n" not in buffer:
                    chunk = connection.recv(4096)
                    if not chunk or len(buffer) + sum(map(len, lines)) + len(chunk) > 65536:
                        raise ValueError("FTP response closed or exceeds limit")
                    buffer.extend(chunk)
                    continue
                line, _, rest = buffer.partition(b"\n")
                buffer[:] = rest
                line = bytes(line) + b"\n"
                lines.append(line)
                code = code or line[:3]
                if line.startswith(code + b" "):
                    response = b"".join(lines)
                    exchanges.append({"request_hex": command.hex(), "response_hex": response.hex()})
                    return int(code)
            raise TimeoutError("FTP response deadline exceeded")
        if receive(b"") != 220:
            raise ValueError("FTP service did not send a ready banner")
        if receive(b"USER anonymous\r\n") == 331:
            receive(b"PASS scanrunner@example.invalid\r\n")


def cli(argv, backend):
    parser = command_parser("probe")
    parser.add_argument("kind", choices=["ftp-anon", "dns-recursion"])
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--output", "-o", default="results")
    parser.add_argument("--engagement", default="default")
    parser.add_argument("--authorization-note", required=True)
    parser.add_argument("--canary-name")
    parser.add_argument("--expected-answer")
    parser.add_argument("--canary-authorized", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    address = str(ipaddress.ip_address(args.ip))
    port = args.port or (21 if args.kind == "ftp-anon" else 53)
    if not 1 <= port <= 65535 or not args.authorization_note.strip():
        raise ValueError("Valid port and authorization note are required")
    policy = assessment.engagement_policy(args.output, args.engagement)
    if policy and policy.get("expires_at") and assessment.parse_timestamp(policy["expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("Engagement authorization expired")
    guard = backend.ScopeGuard([address], backend.load_scope(args.scope_file), policy.get("exclusions", []) if policy else [])
    guard.destinations(address)
    if policy and not backend.target_in_scope(address, policy["scope"]):
        raise ValueError("Probe exceeds engagement scope")
    if args.kind == "dns-recursion":
        if not args.canary_authorized or not args.canary_name or not args.expected_answer:
            raise ValueError("DNS recursion requires an authorized owned canary name and known IPv4 answer")
        ipaddress.IPv4Address(args.expected_answer)
        dns_question(args.canary_name, True)
    if args.dry_run:
        print(json.dumps({"address": address, "port": port, "check": args.kind, "impact": "anonymous authentication" if port == 21 else "controlled DNS query", "scope": guard.scope}))
        return 0
    config = {"tool": "probe", "tool_version": "1", "engagement": args.engagement, "scope": guard.scope,
              "probe_sha256": backend.file_sha256(__file__),
              "authorization_note": backend.redact_output_text(args.authorization_note), "check": args.kind,
              "port": port, "canary_name": args.canary_name, "expected_answer": args.expected_answer}
    with assessment.local_operation(backend, args.output, config) as store:
        job = store.wait_claim(address)
        if job is None:
            raise ValueError("Probe target already claimed")
        proof = {"schema_version": 1, "address": address, "port": port, "check_id": "ftp-anon" if args.kind == "ftp-anon" else "sr-dns-recursion",
                 "observed_at": backend.utc_now(), "expected_answer": args.expected_answer, "exchanges": []}
        status, valid = "FAILED", False
        path = Path(job["directory"]) / "probe.json"
        try:
            guard.destinations(address)
            if args.kind == "ftp-anon":
                ftp_exchange(address, port, proof["exchanges"])
            else:
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                for recursive in (False, True):
                    request = dns_question(args.canary_name, recursive)
                    with socket.socket(family, socket.SOCK_DGRAM) as connection:
                        connection.settimeout(5)
                        connection.connect((address, port))
                        connection.send(request)
                        response = connection.recv(4096)
                    proof["exchanges"].append({"request_hex": request.hex(), "response_hex": response.hex()})
            path.write_text(json.dumps(proof, indent=2), encoding="utf-8")
            records = normalize(backend, path, address, {**job, "run_id": store.run_id}, "COMPLETE")
            assessment.AssessmentRepository(store, backend).ingest(records)
            from scanrunner_findings import evaluate
            candidate = {**records[0]["scripts"][0], "addresses": [address], "host_state": "up", "service_state": "open",
                         "source_tool": "scanrunner-probe", "execution_outcome": "COMPLETE", "scan_completion": "success"}
            valid = evaluate(candidate)["outcome"] != "Inconclusive"
            status = "COMPLETE" if valid else "INCONCLUSIVE"
        finally:
            if not path.exists():
                path.write_text(json.dumps(proof, indent=2), encoding="utf-8")
            (path.parent / "stdout.bin").write_bytes(path.read_bytes())
            (path.parent / "stderr.bin").write_bytes(b"")
            status, valid = store.finish_job(job, status, 0 if valid else 1, valid, ["probe", args.kind, address, str(port)])
        print(json.dumps({"run_id": store.run_id, "outcome": status, "artifact": str(path)}))
        return 0 if status == "COMPLETE" else 1

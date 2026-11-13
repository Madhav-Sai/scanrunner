"""Exercise installed optional scanners and native probes against owned services."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

OUTPUT = Path("/evidence")
TARGET = "172.29.78.10"


def main():
    OUTPUT.mkdir(exist_ok=True)
    scope = OUTPUT / "scope.txt"
    scope.write_text(TARGET + "\n")
    shutil.copyfile("/opt/tool-identities.json", OUTPUT / "tool-identities.json")
    template = OUTPUT / "reviewed-template.yaml"
    template.write_text(json.dumps({"id": "owned-lab-status", "info": {"name": "Owned HTTP marker", "author": "ScanRunner controlled lab", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"], "matchers": [{"type": "word", "words": ["Owned ScanRunner Lab"]}]}]}))
    commands = []
    for tool, version, scheme, port in (("httpx", "1.12.0", "http", 8080), ("nuclei", "3.11.1", "http", 8080), ("testssl", "3.2.5", "https", 8443)):
        command = ["plugin", "run", "--adapter", tool, "--target", f"{scheme}://{TARGET}:{port}/", "--scope-file", str(scope),
                   "--output", str(OUTPUT / tool), "--enable", "--authorization-note", "Owned isolated Docker lab", "--expected-version", version]
        if tool == "nuclei":
            command += ["--template", str(template), "--template-sha256", hashlib.sha256(template.read_bytes()).hexdigest(),
                        "--template-reviewed-by", "Controlled lab literal HTTP marker"]
        commands.append((tool, command, None))
    for kind, port, expected in (("ftp-anon", 21, "Potential"), ("ftp-anon", 2121, "Not observed"),
                                 ("dns-recursion", 53, "Potential"), ("dns-recursion", 5353, "Not observed")):
        name = kind + "-" + str(port)
        command = ["probe", kind, "--ip", TARGET, "--port", str(port), "--scope-file", str(scope), "--output", str(OUTPUT / name),
                   "--authorization-note", "Owned isolated Docker lab"]
        if kind == "dns-recursion":
            command += ["--canary-name", "owned.example.invalid", "--expected-answer", "203.0.113.9", "--canary-authorized"]
        commands.append((name, command, expected))
    results = []
    for name, command, expected in commands:
        print("RUNNING " + name, flush=True)
        execution = subprocess.run([sys.executable, "-B", "scanrunner.py", *command], capture_output=True, timeout=360)
        (OUTPUT / (name + "-stdout.bin")).write_bytes(execution.stdout)
        (OUTPUT / (name + "-stderr.bin")).write_bytes(execution.stderr)
        output_directory = str(OUTPUT / name)
        review = ["observations"] if expected is not None else ["plugin", "observations"]
        observed = subprocess.run([sys.executable, "-B", "scanrunner.py", *review, "--output", output_directory], capture_output=True, timeout=30)
        integrity = subprocess.run([sys.executable, "-B", "scanrunner.py", "--verify-evidence", output_directory, "--json"], capture_output=True, timeout=30)
        (OUTPUT / (name + "-observations.json")).write_bytes(observed.stdout)
        (OUTPUT / (name + "-integrity.json")).write_bytes(integrity.stdout)
        rows = json.loads(observed.stdout) if observed.returncode == 0 else []
        matched = bool(rows) and all(row.get("verification_status") == "Needs Verification" for row in rows)
        if expected is not None:
            matched = matched and len(rows) == 1 and rows[0]["evaluation"]["outcome"] == expected
        elif name == "httpx":
            matched = matched and all(row["data"]["status_code"] == 200 for row in rows)
        elif name == "nuclei":
            matched = matched and all(row["check_id"] == "owned-lab-status" for row in rows)
        else:
            protocols = {row["check_id"]: row["data"]["finding"] for row in rows}
            matched = matched and protocols.get("TLS1") == "not offered" and protocols.get("TLS1_1") == "not offered" and protocols.get("TLS1_2") == "offered"
        results.append({"case": name, "exit_code": execution.returncode, "argv": command, "expected_outcome": expected,
                        "observations_exit_code": observed.returncode, "integrity_exit_code": integrity.returncode, "ground_truth_match": matched})
        (OUTPUT / "executions.json").write_text(json.dumps(results, indent=2))
        print(f"FINISHED {name} exit={execution.returncode}", flush=True)
    return int(any(result["exit_code"] != 0 or result["observations_exit_code"] != 0 or result["integrity_exit_code"] != 0
                   or not result["ground_truth_match"] for result in results))


if __name__ == "__main__":
    raise SystemExit(main())

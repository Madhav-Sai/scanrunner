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
        commands.append((tool, command))
    for kind, port, expected in (("ftp-anon", 21, "Potential"), ("ftp-anon", 2121, "Not observed"),
                                 ("dns-recursion", 53, "Potential"), ("dns-recursion", 5353, "Not observed")):
        name = kind + "-" + str(port)
        command = ["probe", kind, "--ip", TARGET, "--port", str(port), "--scope-file", str(scope), "--output", str(OUTPUT / name),
                   "--authorization-note", "Owned isolated Docker lab"]
        if kind == "dns-recursion":
            command += ["--canary-name", "owned.example.invalid", "--expected-answer", "203.0.113.9", "--canary-authorized"]
        commands.append((name, command))
    results = []
    for name, command in commands:
        print("RUNNING " + name, flush=True)
        execution = subprocess.run([sys.executable, "-B", "scanrunner.py", *command], capture_output=True, timeout=360)
        (OUTPUT / (name + "-stdout.bin")).write_bytes(execution.stdout)
        (OUTPUT / (name + "-stderr.bin")).write_bytes(execution.stderr)
        results.append({"case": name, "exit_code": execution.returncode, "argv": command})
        (OUTPUT / "executions.json").write_text(json.dumps(results, indent=2))
        print(f"FINISHED {name} exit={execution.returncode}", flush=True)
    return int(any(result["exit_code"] != 0 for result in results))


if __name__ == "__main__":
    raise SystemExit(main())

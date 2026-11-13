"""Measure the production CLI and rules against four isolated Samba policies."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from negotiate import probe

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scanrunner as backend
from scanrunner_benchmark import benchmark
from scanrunner_findings import evaluate

PROFILES = [
    ("nt1-optional", "172.29.77.10", True, False),
    ("nt1-required", "172.29.77.11", True, True),
    ("smb2-optional", "172.29.77.12", False, False),
    ("smb2-required", "172.29.77.13", False, True),
]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    output = Path("/evidence")
    if (output / "dataset.json").exists() or (output / "executions.json").exists():
        raise FileExistsError("Choose a fresh evidence directory for each lab run")
    scope = output / "scope.txt"
    scope.write_text("\n".join(address for _, address, _, _ in PROFILES) + "\n", encoding="utf-8")
    scanner_version = subprocess.check_output(["nmap", "--version"], text=True)
    (output / "nmap-version.txt").write_text(scanner_version, encoding="utf-8")
    (output / "runner-packages.txt").write_text(subprocess.check_output(["dpkg-query", "-W"], text=True), encoding="utf-8")
    scripts = [Path("/usr/share/nmap") / name for name in
               ("scripts/smb-protocols.nse", "scripts/smb2-security-mode.nse", "nselib/smb.lua", "nselib/smb2.lua")]
    (output / "nmap-script-hashes.json").write_text(json.dumps({str(path): digest(path) for path in scripts}, indent=2), encoding="utf-8")
    cases, runs = [], []
    for profile, address, smbv1, signing in PROFILES:
        print(f"VERIFYING {profile} {address}", flush=True)
        server_directory = output / "server-proofs" / profile
        server = json.loads((server_directory / "server.json").read_text(encoding="utf-8"))
        if digest(server_directory / "smb.conf") != server["config_sha256"]:
            raise RuntimeError("Server configuration proof changed")
        verification = probe(address)
        proof = {"profile": profile, "address": address, "port": 445, "server": server,
                 "verification": verification, "verified_at": datetime.now(timezone.utc).isoformat(),
                 "method": "Effective Samba configuration plus independent SMB1 and SMB2 wire negotiation"}
        proof_path = output / (profile + "-ground-truth.json")
        proof_path.write_text(json.dumps(proof, indent=2), encoding="utf-8")
        if verification.get("error"):
            raise RuntimeError("Independent SMB2 negotiation could not establish ground truth")
        if (server["configured_smbv1"] != smbv1 or server["configured_signing_required"] != signing
                or verification["smbv1_accepted"] != smbv1 or verification["smb2"]["signing_required"] != signing):
            raise RuntimeError(f"Independent verification disagrees with policy for {profile}")
        print(f"VERIFIED {profile} SMBv1={smbv1} signing_required={signing}", flush=True)
        destination = output / "scans" / profile
        argv = [sys.executable, "-B", "scanrunner.py", "-i", address, "--yes", "--skip-ping", "-n", "-sT", "-Pn",
                "--disable-arp-ping", "--unprivileged", "-p", "445", "--script", "smb-protocols,smb2-security-mode",
                "--host-timeout", "60s", "--process-timeout", "90", "--scan-rate", "16", "--global-concurrency", "1",
                "--subnet-concurrency", "1", "--scope-file", str(scope), "--allow-intrusive", "--authorization-note",
                "Owned isolated Docker lab", "--no-color", "-o", str(destination)]
        execution = subprocess.run(argv, capture_output=True, timeout=120)
        print(f"SCANNED {profile} exit={execution.returncode}", flush=True)
        (output / (profile + "-cli-stdout.bin")).write_bytes(execution.stdout)
        (output / (profile + "-cli-stderr.bin")).write_bytes(execution.stderr)
        integrity = subprocess.run([sys.executable, "-B", "scanrunner.py", "--verify-evidence", str(destination), "--json"],
                                   capture_output=True, timeout=30)
        observations = subprocess.run([sys.executable, "-B", "scanrunner.py", "observations", "--output", str(destination)],
                                      capture_output=True, timeout=30)
        (output / (profile + "-integrity-stdout.bin")).write_bytes(integrity.stdout)
        (output / (profile + "-integrity-stderr.bin")).write_bytes(integrity.stderr)
        (output / (profile + "-observations-stdout.bin")).write_bytes(observations.stdout)
        (output / (profile + "-observations-stderr.bin")).write_bytes(observations.stderr)
        stored = json.loads(observations.stdout) if observations.returncode == 0 else []
        expected = {"smb-protocols": "Potential" if smbv1 else "Not observed",
                    "smb2-security-mode": "Not observed" if signing else "Potential"}
        matched = (len(stored) == 2 and {item["check_id"] for item in stored} == set(expected)
                   and all(item["addresses"] == [address] and item["port"] == 445 and item["transport"] == "tcp"
                           and item["verification_status"] == "Needs Verification"
                           and evaluate(item)["outcome"] == expected[item["check_id"]] for item in stored))
        print(f"PERSISTED {profile} observations_match={matched} integrity_exit={integrity.returncode}", flush=True)
        runs.append({"profile": profile, "argv": argv, "exit_code": execution.returncode,
                     "integrity_exit_code": integrity.returncode, "observations_exit_code": observations.returncode,
                     "stored_observations_match": matched})
        (output / "executions.json").write_text(json.dumps(runs, indent=2), encoding="utf-8")
        artifacts = list((destination / ".scanrunner" / "runs").glob("*/*/nmap.xml"))
        if len(artifacts) == 1:
            artifact = artifacts[0]
        else:
            # Preserve real failed execution bytes as unparseable evidence. The
            # benchmark retains both labeled cases as abstentions.
            artifact = output / (profile + "-cli-stderr.bin")
        for check, positive in [("smb-protocols", smbv1), ("smb2-security-mode", not signing)]:
            cases.append({"id": profile + "-" + check, "artifact": str(artifact.relative_to(output)),
                          "sha256": digest(artifact), "address": address, "port": 445, "transport": "tcp", "check_id": check,
                          "expected": "positive" if positive else "negative", "ground_truth": {
                          "reviewer": "Controlled lab configuration and independent wire verifier",
                          "method": proof["method"], "verified_at": proof["verified_at"],
                          "artifact": proof_path.name, "sha256": digest(proof_path)}})
    dataset = output / "dataset.json"
    dataset.write_text(json.dumps({"schema_version": 1, "dataset_kind": "controlled-lab", "cases": cases}, indent=2), encoding="utf-8")
    result = benchmark(dataset, backend, output / "benchmark.json")
    (output / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    environment = {**os.environ, "SCANRUNNER_TEST_REAL_NMAP": "1"}
    local_test = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_workflow.py",
                                 "-k", "RealNmapTests", "-v"], capture_output=True, env=environment, timeout=210)
    (output / "localhost-test-stdout.bin").write_bytes(local_test.stdout)
    (output / "localhost-test-stderr.bin").write_bytes(local_test.stderr)
    failed = any(run["exit_code"] != 0 or run["integrity_exit_code"] != 0 or run["observations_exit_code"] != 0
                 or not run["stored_observations_match"] for run in runs) or local_test.returncode != 0
    failed = failed or any(score["false_positive"] or score["false_negative"] or score["abstained_positive"]
                           or score["abstained_negative"] for score in result["per_check"].values())
    return int(failed)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        Path("/evidence/lab-error.json").write_text(json.dumps({"error": type(error).__name__, "detail": str(error)}, indent=2), encoding="utf-8")
        raise

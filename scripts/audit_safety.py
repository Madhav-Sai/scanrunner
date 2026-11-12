"""Independent offline safety probes. Exit nonzero when an expected guard fails.

These checks assess specific behavior, not real-world vulnerability accuracy.
Scanner launches and DNS are mocked. Only a controlled local Python timeout runs.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock


def audit(repository):
    sys.path.insert(0, str(repository))
    source = repository / "scanrunner.py"
    spec = importlib.util.spec_from_file_location("audited_scanrunner", source)
    backend = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = backend
    spec.loader.exec_module(backend)
    findings = []

    def probe(name, function):
        captured = io.StringIO()
        try:
            with mock.patch("sys.stdout", captured), mock.patch("sys.stderr", captured):
                detail = function()
            findings.append({"check": name, "passed": True, "detail": detail or "Expected guard held"})
        except Exception as error:
            findings.append({"check": name, "passed": False, "detail": str(error)})

    def require(value, message):
        if not value:
            raise AssertionError(message)

    def denied(function):
        try:
            function()
        except ValueError:
            return
        raise AssertionError("Input was accepted")

    def xml_result(xml, text="# Nmap done -- 1 IP address (1 host up) scanned\n", target="192.0.2.1", code=0):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nmap.txt"
            report.write_text(text)
            report.with_suffix(".xml").write_text(xml)
            with mock.patch.object(backend, "ACTIVE_SCOPE", backend.ScopeGuard([target], None)):
                return backend.validate_nmap_evidence(str(report), target, code)

    normal_xml = '<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port portid="22" protocol="tcp"><state state="open"/></port></ports></host><runstats><finished exit="success"/><hosts up="1" total="1"/></runstats></nmaprun>'

    probe("empty_scope_denied", lambda: denied(lambda: backend.ScopeGuard(["192.0.2.1"], [])))
    probe("mixed_dns_denied", lambda: denied(lambda: backend.ScopeGuard(["fixture.invalid"], ["192.0.2.0/24"],
          resolver=lambda *a, **k: (["192.0.2.1", "198.51.100.1"], "synthetic"))))

    def rebinding():
        resolver = mock.Mock(return_value=(["192.0.2.1"], "synthetic"))
        guard = backend.ScopeGuard(["fixture.invalid"], ["fixture.invalid"], resolver=resolver)
        resolver.return_value = (["198.51.100.1"], "changed")
        denied(lambda: guard.destinations("fixture.invalid"))
    probe("changed_dns_denied", rebinding)
    probe("extra_targets_denied", lambda: denied(lambda: backend.validate_scan_options(["192.0.2.2"])))
    probe("unreviewed_nse_denied", lambda: denied(lambda: backend.validate_scan_options(["--script", "vuln"])))
    probe("credential_operations_require_opt_in", lambda: denied(lambda: backend.validate_scan_options(["-u", "fixture"], True)))

    def no_dry_run_effects():
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            with mock.patch("sys.argv", ["scanrunner", "-i", "fixture.invalid", "--dry-run", "--json", "-o", str(output)]), \
                    mock.patch.object(backend.subprocess, "Popen") as popen, \
                    mock.patch.object(backend.subprocess, "run") as run, \
                    mock.patch.object(backend.socket, "getaddrinfo") as dns:
                backend.main()
            require(not popen.called and not run.called and not dns.called and not output.exists(), "Preview performed side effects")
    probe("dry_run_has_zero_network_processes_or_writes", no_dry_run_effects)

    def entities():
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "payload.xml"
            path.write_text('<!DOCTYPE nmaprun [<!ENTITY e "expanded">]><nmaprun>&e;</nmaprun>')
            denied(lambda: backend.read_nmap_xml(path))
    probe("xml_entity_payload_denied", entities)

    def ambiguous_udp():
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nmap.xml"
            path.write_text(normal_xml.replace('protocol="tcp"', 'protocol="udp"').replace('state="open"', 'state="open|filtered"'))
            require(not backend._hosts_from_xml(path)[0]["ports"], "Ambiguous UDP state became an open port")
    probe("ambiguous_udp_not_promoted_to_open", ambiguous_udp)
    probe("nonzero_exit_not_complete", lambda: require(xml_result(normal_xml, code=1)[1] is False, "Nonzero exit completed"))
    probe("mismatched_host_not_complete", lambda: require(xml_result(normal_xml.replace("192.0.2.1", "198.51.100.1"))[1] is False, "Unassociated host completed"))
    probe("timeout_xml_not_complete", lambda: require(xml_result(normal_xml.replace("<host>", '<host timedout="true">'))[1] is False, "Timed-out host completed"))

    def malformed_port():
        result = xml_result(normal_xml.replace('portid="22"', 'portid="not-a-port"'))
        require(result[1] is False, f"Malformed port was accepted as {result}")
    probe("malformed_port_cannot_complete", malformed_port)

    def contradictory_counts():
        result = xml_result(normal_xml.replace('hosts up="1"', 'hosts up="0"'),
                            text="# Nmap done -- 1 IP address (0 hosts up) scanned\n")
        require(result[1] is False, f"Contradictory up-host/counter evidence was accepted as {result}")
    probe("contradictory_down_xml_cannot_validate", contradictory_counts)

    def nxc_empty():
        with tempfile.TemporaryDirectory() as temporary:
            store = backend.RunStore(temporary, {"tool": "nxc"})
            def capture(command, directory, timeout, live):
                (Path(directory) / "stdout.bin").write_bytes(b"")
                (Path(directory) / "stderr.bin").write_bytes(b"")
                return 0, "Exited"
            with mock.patch.object(backend, "ACTIVE_STORE", store), mock.patch.object(backend, "ACTIVE_SCOPE", None), \
                    mock.patch.object(backend, "capture_process", side_effect=capture):
                backend.run_nxc("fixture-nxc", "smb", "192.0.2.1", ["192.0.2.1"], [], [], temporary)
            with store.connect() as database:
                row = database.execute("SELECT outcome,parser_ok FROM jobs").fetchone()
            require(not (row["outcome"] == "COMPLETE" and row["parser_ok"]), "Empty NetExec stdout became COMPLETE with parser_ok=1")
    probe("empty_netexec_not_marked_complete", nxc_empty)

    def nxc_scope():
        rows = backend.parse_nxc_output("SMB 198.51.100.1 445 OUTSIDE [*] (signing:False)", ["192.0.2.1"])
        require(not any(row["target"] == "198.51.100.1" for row in rows), "Unrequested out-of-scope host entered normal result rows")
    probe("netexec_unsolicited_hosts_excluded", nxc_scope)

    def nxc_contradiction():
        rows = backend.parse_nxc_output("SMB 192.0.2.1 445 FIXTURE [*] (signing:True)\nSMB 192.0.2.1 445 FIXTURE [*] (signing:False)", ["192.0.2.1"])
        require(rows[0]["smb_signing"] not in {"True", "False"}, "Contradiction was silently resolved to " + rows[0]["smb_signing"])
    probe("netexec_contradiction_is_inconclusive", nxc_contradiction)

    def nxc_auth():
        rows = backend.parse_nxc_output("SMB 192.0.2.1 445 FIXTURE [+] Enumeration finished", ["192.0.2.1"], null_auth_attempt=True)
        require(rows[0]["null_auth"] != "Success", "Unrelated success marker became successful anonymous authentication")
    probe("netexec_generic_success_not_authentication_proof", nxc_auth)

    def nxc_protocol():
        rows = backend.parse_nxc_output("SMB 192.0.2.1 445 FIXTURE [*] (signing:False)\nRDP 192.0.2.1 3389 FIXTURE [*] (NLA:False)", ["192.0.2.1"])
        require(not any(row["port"] == "3389" and row["smb_signing"] == "False" for row in rows), "SMB signing evidence became associated with RDP port 3389")
    probe("netexec_protocol_evidence_not_cross_associated", nxc_protocol)
    probe("anonymous_session_nse_requires_explicit_opt_in", lambda: denied(lambda:
          backend.validate_scan_options(["--script", "smb-os-discovery"], allow_intrusive=False)))

    def minimal_manifest():
        with tempfile.TemporaryDirectory() as temporary:
            store = backend.RunStore(temporary, {"tool": "nmap"})
            job = store.claim("192.0.2.1")
            store.finish_job(job, "COMPLETE", 0, True, ["nmap"])
            require(not store.completed("192.0.2.1"), "State API accepted completion without any scan artifacts")
    probe("completion_api_requires_scan_artifacts", minimal_manifest)

    def hashes():
        with tempfile.TemporaryDirectory() as temporary:
            store = backend.RunStore(temporary)
            job = store.claim("192.0.2.1")
            artifact = Path(job["directory"]) / "stdout.bin"
            artifact.write_bytes(b"synthetic")
            (Path(job["directory"]) / "stderr.bin").write_bytes(b"")
            store.finish_job(job, "COMPLETE", 0, True, [])
            require(store.completed("192.0.2.1"), "Valid generic capture failed before tampering")
            artifact.write_bytes(b"tampered")
            require(not store.completed("192.0.2.1"), "Tampered bytes passed resume")
    probe("corrupt_artifact_blocks_resume", hashes)

    def profiles():
        rejected = []
        for name, options in backend.SCAN_PROFILES.items():
            try:
                backend.validate_scan_options(options)
            except ValueError:
                rejected.append(name)
        require(not rejected, "Advertised profiles rejected by execution policy: " + ", ".join(rejected))
    probe("advertised_profiles_match_execution_policy", profiles)

    def duplicate_claims():
        with tempfile.TemporaryDirectory() as temporary:
            first = backend.RunStore(temporary)
            second = backend.RunStore(temporary)
            require(first.claim("192.0.2.1") is not None and second.claim("192.0.2.1") is None, "Duplicate ownership was granted")
    probe("duplicate_job_ownership_denied", duplicate_claims)
    probe("csv_formula_neutralized", lambda: require(backend.csv_safe("=1+1").startswith("'"), "CSV formula left active"))
    probe("secret_pattern_redacted", lambda: require("fixture-secret" not in backend.redact_output_text("password=fixture-secret"), "Secret pattern remained"))
    return {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "probe_count": len(findings), "passed": sum(item["passed"] for item in findings),
            "failed": sum(not item["passed"] for item in findings), "probes": findings,
            "interpretation": "Targeted guard checks only. This is not a vulnerability detection accuracy estimate."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.repo.resolve())
    if args.output:
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["failed"] else 0)

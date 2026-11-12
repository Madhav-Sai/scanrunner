"""Synthetic rule, evidence integrity, analyst approval and retest regressions."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import scanrunner_assessment as assessment
import scanrunner_findings as findings
import scanrunner_benchmark as benchmark

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("findings_backend", ROOT / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sr
spec.loader.exec_module(sr)


def write_scan(path, positive=True, start=1700000000, check="smb2-security-mode", port=445, state="open", finished="success", hostscript=False):
    root = ET.Element("nmaprun", scanner="nmap", version="7.95", start=str(start), args="synthetic controlled fixture")
    host = ET.SubElement(root, "host")
    ET.SubElement(host, "status", state="up")
    ET.SubElement(host, "address", addr="192.0.2.10", addrtype="ipv4")
    ports = ET.SubElement(host, "ports")
    endpoint = ET.SubElement(ports, "port", protocol="tcp", portid=str(port))
    ET.SubElement(endpoint, "state", state=state)
    script = ET.SubElement(endpoint, "script", id=check)
    if check == "smb2-security-mode":
        value = "Message signing enabled but not required" if positive else "Message signing enabled and required"
        script.set("output", "3.1.1: " + value)
        table = ET.SubElement(script, "table", key="3.1.1")
        ET.SubElement(table, "elem").text = value
    else:
        value = "NT LM 0.12 (SMBv1)" if positive else "3.1.1"
        script.set("output", "dialects: " + value)
        table = ET.SubElement(script, "table", key="dialects")
        ET.SubElement(table, "elem").text = value
    statistics = ET.SubElement(root, "runstats")
    ET.SubElement(statistics, "finished", exit=finished)
    ET.SubElement(statistics, "hosts", up="1", down="0", total="1")
    if hostscript:
        endpoint.remove(script)
        ET.SubElement(host, "hostscript").append(script)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class FindingWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.scope = self.root / "scope.txt"
        self.scope.write_text("192.0.2.0/24\n")

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, *args):
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            assessment.cli([*args, "--output", str(self.output)], sr)
        return json.loads(captured.getvalue()) if captured.getvalue() else None

    def imported(self, positive=True, start=1700000000, **kwargs):
        path = self.root / ("scan-" + str(start) + ".xml")
        write_scan(path, positive, start, **kwargs)
        result = self.command("import", str(path), "--scope-file", str(self.scope), "--target", "192.0.2.10")
        observations = self.command("observations")
        observation = next(row for row in observations if row["run_id"] == result["run_id"])
        return result, observation

    def details(self):
        path = self.root / "details.json"
        path.write_text(json.dumps({"description": "Synthetic reviewed configuration", "impact": "Synthetic policy impact",
                                   "remediation": "Require signing under the approved policy", "severity": "Medium"}))
        return str(path)

    def confirm(self, identifier):
        return self.command("findings", "review", "--finding", identifier, "--status", "Confirmed", "--reviewer", "Synthetic Analyst",
                            "--rationale", "Synthetic fixture reviewed", "--details", self.details(),
                            "--approve-preconditions-and-impact", "--trust-import-origin")

    def test_rule_matrix_for_both_supported_checks(self):
        for check in findings.RULES:
            for positive in (True, False):
                _, observation = self.imported(positive, 1700000000 + len(check) + int(positive), check=check)
                self.assertEqual(findings.evaluate(observation)["outcome"], "Potential" if positive else "Not observed")
                for field, invalid in [("addresses", ["192.0.2.10", "198.51.100.1"]), ("port", 3389), ("transport", "udp"),
                                       ("host_state", "down"), ("service_state", "filtered"), ("execution_outcome", "TIMEOUT"),
                                       ("check_execution", "Inconclusive"), ("scan_completion", "error")]:
                    with self.subTest(check=check, field=field):
                        self.assertEqual(findings.evaluate({**observation, field: invalid})["outcome"], "Inconclusive")
                self.assertEqual(findings.evaluate({**observation, "structured": {}})["outcome"], "Inconclusive")

    def test_contradictions_are_inconclusive(self):
        _, observation = self.imported()
        contradictory = copy.deepcopy(observation)
        contradictory["structured"]["children"][0]["children"].append(
            {"tag": "elem", "key": None, "text": "Message signing enabled and required", "children": []})
        contradictory["output"] += " Message signing enabled and required"
        self.assertEqual(findings.evaluate(contradictory)["outcome"], "Inconclusive")
        self.assertEqual(findings.evaluate({**observation, "output": "Message signing enabled and required"})["outcome"], "Inconclusive")

    def test_real_hostscript_layout_has_explicit_derivation_and_ambiguous_ports_abstain(self):
        _, observation = self.imported(hostscript=True)
        self.assertEqual(observation["port"], 445)
        self.assertIn("Derived", observation["endpoint_association"])
        self.assertEqual(findings.evaluate(observation)["outcome"], "Potential")
        source = self.root / "ambiguous-hostscript.xml"
        write_scan(source, hostscript=True)
        root = ET.parse(source).getroot()
        endpoint = ET.SubElement(root.find("host/ports"), "port", portid="139", protocol="tcp")
        ET.SubElement(endpoint, "state", state="open")
        ET.ElementTree(root).write(source, encoding="utf-8")
        result = self.command("import", str(source), "--scope-file", str(self.scope), "--target", "192.0.2.10")
        ambiguous = next(row for row in self.command("observations") if row["run_id"] == result["run_id"])
        self.assertIsNone(ambiguous["port"])
        self.assertEqual(findings.evaluate(ambiguous)["outcome"], "Inconclusive")

    def test_nmap_execution_entry_point_ingests_realistic_hostscript_layout(self):
        source = self.root / "scanner-fixture.xml"
        write_scan(source, hostscript=True)
        store = sr.RunStore(str(self.output), {"tool": "nmap", "tool_version": "7.95"})
        def capture(command, directory, timeout, live):
            directory = Path(directory)
            (directory / "stdout.bin").write_bytes(b"synthetic scanner output")
            (directory / "stderr.bin").write_bytes(b"")
            (directory / "nmap.xml").write_bytes(source.read_bytes())
            (directory / "nmap.txt").write_text("# Nmap done -- 1 IP address (1 host up) scanned\n")
            return 0, "Exited"
        with mock.patch.object(sr, "ACTIVE_STORE", store), mock.patch.object(sr, "ACTIVE_SCOPE", sr.ScopeGuard(["192.0.2.10"], None)), \
                mock.patch.object(sr, "ACTIVE_CONFIG", {}), mock.patch.object(sr, "capture_process", side_effect=capture):
            status, _ = sr.execute_nmap("192.0.2.10", str(self.output / "192.0.2.10.txt"), [])
        store.end("Synthetic execution integration completed")
        self.assertEqual(status, "COMPLETE")
        self.assertTrue(store.completed("192.0.2.10"))
        observation = self.command("observations")[0]
        self.assertFalse(observation["imported"])
        self.assertEqual(findings.evaluate(observation)["outcome"], "Potential")

    def test_confirmation_requires_explicit_analyst_approval_and_complete_fields(self):
        _, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        self.assertEqual(finding["status"], "Needs Verification")
        self.assertEqual(finding["observed_at"], "2023-11-14T22:13:20+00:00")
        self.assertEqual(finding["tool_version"], "7.95")
        base = ["findings", "review", "--finding", finding["id"], "--status", "Confirmed", "--reviewer", "Synthetic Analyst", "--rationale", "Reviewed"]
        for extra in [[], ["--approve-preconditions-and-impact"], ["--approve-preconditions-and-impact", "--trust-import-origin"]]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.command(*base, *extra)
        confirmed = self.confirm(finding["id"])
        self.assertEqual(confirmed["status"], "Confirmed")
        history = self.command("findings", "history", "--finding", finding["id"])
        self.assertEqual(len(history["decisions"]), 2)
        repeated = self.command("findings", "create", "--observation", observation["id"])
        self.assertEqual(repeated["status"], "Confirmed")

    def test_negative_and_ambiguous_results_cannot_be_confirmed(self):
        for positive, kwargs in [(False, {}), (True, {"state": "open|filtered"}), (True, {"finished": "error"}), (True, {"port": 3389})]:
            _, observation = self.imported(positive, 1700000000 + len(kwargs), **kwargs)
            finding = self.command("findings", "create", "--observation", observation["id"])
            with self.assertRaises(ValueError):
                self.confirm(finding["id"])

    def test_review_status_transitions_preserve_decision_history(self):
        _, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        statuses = ["Not Tested", "Potential", "Inconclusive", "False Positive", "Accepted Risk", "Needs Verification"]
        for status in statuses:
            reviewed = self.command("findings", "review", "--finding", finding["id"], "--status", status,
                                    "--reviewer", "Synthetic Analyst", "--rationale", "Synthetic decision")
            self.assertEqual(reviewed["status"], status)
        history = self.command("findings", "history", "--finding", finding["id"])
        self.assertEqual(len(history["decisions"]), len(statuses) + 1)

    def test_tampered_evidence_and_tampered_normalized_data_are_rejected(self):
        _, observation = self.imported()
        store = sr.RunStore(str(self.output), {"tool": "local"})
        with store.connect() as database:
            changed = {**observation, "port": 3389}
            database.execute("UPDATE security_observations SET data=? WHERE id=?", (json.dumps(changed), observation["id"]))
        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.command("findings", "create", "--observation", observation["id"])
        with store.connect() as database:
            database.execute("UPDATE security_observations SET data=? WHERE id=?", (json.dumps({k: v for k, v in observation.items() if k != "id"}), observation["id"]))
        Path(observation["artifact"]).write_text("changed")
        with self.assertRaises(ValueError):
            self.command("findings", "create", "--observation", observation["id"])
        store.end("Synthetic test completed")

    def test_retest_requires_comparable_negative_evidence_and_review(self):
        baseline, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        self.confirm(finding["id"])
        same = self.command("retest", finding["id"], "--run", baseline["run_id"])
        self.assertEqual(same["outcome"], "Inconclusive")
        absent = self.command("retest", finding["id"], "--run", "missing-run")
        self.assertEqual(absent["outcome"], "Not Retested")
        current, _ = self.imported(False, 1700001000)
        candidate = self.command("retest", finding["id"], "--run", current["run_id"])
        self.assertEqual(candidate["outcome"], "Potentially Remediated")
        self.assertEqual(self.command("findings", "list")[0]["status"], "Confirmed")
        verified = self.command("retest", finding["id"], "--run", current["run_id"], "--approve", "--reviewer", "Synthetic Analyst",
                                "--rationale", "Comparable synthetic negative reviewed", "--trust-import-origin")
        self.assertEqual(verified["outcome"], "Remediated (Verified)")
        self.assertEqual(verified["new_evidence"]["addresses"], ["192.0.2.10"])
        self.assertEqual(self.command("findings", "list")[0]["latest_retest"]["new_run"], current["run_id"])
        history = self.command("findings", "history", "--finding", finding["id"])
        self.assertEqual(len(history["retests"]), 4)

    def test_failed_filtered_or_different_method_retest_cannot_verify_remediation(self):
        _, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        self.confirm(finding["id"])
        for index, kwargs in enumerate([{"state": "filtered"}, {"finished": "error"}, {"port": 139}]):
            current, _ = self.imported(False, 1700001000 + index, **kwargs)
            result = self.command("retest", finding["id"], "--run", current["run_id"])
            self.assertNotIn(result["outcome"], {"Remediated (Verified)", "Potentially Remediated"})
            with self.assertRaises(ValueError):
                self.command("retest", finding["id"], "--run", current["run_id"], "--approve", "--reviewer", "Synthetic Analyst", "--rationale", "Review")

    def test_final_export_excludes_unapproved_candidates(self):
        _, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        destination = self.root / "final.json"
        self.command("findings", "export", "--destination", str(destination))
        self.assertEqual(json.loads(destination.read_text()), [])
        self.confirm(finding["id"])
        self.command("findings", "export", "--destination", str(destination))
        self.assertEqual(len(json.loads(destination.read_text())), 1)
        result = subprocess.run([sys.executable, str(ROOT / "scanrunner.py"), "findings", "list", "-o", str(self.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[0]["status"], "Confirmed")
        previous = destination.read_bytes()
        Path(observation["artifact"]).write_text("corrupt")
        with self.assertRaises(ValueError):
            self.command("findings", "export", "--destination", str(destination))
        self.assertEqual(destination.read_bytes(), previous)

    def test_executive_report_counts_candidates_separately_and_imports_are_visible(self):
        _, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        report = self.command("report", "--view", "executive")
        self.assertEqual(report["summary"]["confirmed_findings"], 0)
        self.assertEqual(report["summary"]["finding_status_counts"]["Needs Verification"], 1)
        self.assertEqual(report["summary"]["imported_asset_observations"], 1)
        self.assertEqual(report["summary"]["requested_target_entries"], 0)
        self.confirm(finding["id"])
        technical = self.command("report")
        self.assertEqual(technical["summary"]["confirmed_findings"], 1)
        self.assertEqual(technical["findings"][0]["id"], finding["id"])
        for format_name in ("json", "csv", "html"):
            destination = self.root / ("report." + format_name)
            self.command("report", "--destination", str(destination), "--format", format_name)
            self.assertTrue(destination.is_file())

    def test_changed_approved_record_requires_new_review_before_export(self):
        _, observation = self.imported()
        finding = self.command("findings", "create", "--observation", observation["id"])
        approved = self.confirm(finding["id"])
        store = sr.RunStore(str(self.output), {"tool": "local"})
        with store.connect() as database:
            database.execute("UPDATE findings SET data=? WHERE id=?", (json.dumps({**approved, "impact": "Unreviewed modification"}), finding["id"]))
        store.end("Synthetic test completed")
        with self.assertRaisesRegex(ValueError, "approval event"):
            self.command("findings", "export", "--destination", str(self.root / "unsafe.json"))

    def test_duplicate_completion_and_port_evidence_is_rejected(self):
        source = self.root / "duplicate.xml"
        write_scan(source)
        root = ET.parse(source).getroot()
        ports = root.find("host/ports")
        ports.append(copy.deepcopy(ports[0]))
        ET.ElementTree(root).write(source, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            sr.read_nmap_xml(source)
        write_scan(source)
        root = ET.parse(source).getroot()
        root.append(copy.deepcopy(root.find("runstats")))
        ET.ElementTree(root).write(source, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            sr.read_nmap_xml(source)

    def test_benchmark_keeps_abstentions_and_rejects_duplicate_cases(self):
        cases = []
        for index, (positive, state) in enumerate([(True, "open"), (False, "open"), (True, "filtered")]):
            source = self.root / f"case-{index}.xml"
            write_scan(source, positive, state=state)
            cases.append({"id": str(index), "artifact": source.name, "sha256": sr.file_sha256(source),
                          "address": "192.0.2.10", "port": 445, "transport": "tcp", "check_id": "smb2-security-mode",
                          "expected": "positive" if positive else "negative", "ground_truth": {
                          "reviewer": "Synthetic fixture author", "method": "Synthetic label", "verified_at": "2026-11-12T00:00:00+00:00"}})
        manifest = self.root / "dataset.json"
        data = {"schema_version": 1, "dataset_kind": "synthetic", "cases": cases}
        manifest.write_text(json.dumps(data))
        result = benchmark.benchmark(manifest, sr)
        score = result["per_check"]["smb2-security-mode"]
        self.assertEqual((score["true_positive"], score["true_negative"], score["abstained_positive"]), (1, 1, 1))
        self.assertEqual(score["operational_recall"]["value"], 0.5)
        self.assertEqual(score["coverage"]["value"], 2 / 3)
        with self.assertRaisesRegex(ValueError, "cannot replace"):
            benchmark.benchmark(manifest, sr, manifest)
        data["cases"].append({**cases[0], "id": "duplicate"})
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "inflate"):
            benchmark.benchmark(manifest, sr)

"""Privacy, local scheduling and attestation end-to-end regressions."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import scanrunner_assessment as assessment
import scanrunner_findings as findings
import scanrunner_operations as operations
import scanrunner_workspace as workspace
from test_roadmap import backend


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / "out"
        self.scope = self.root / "scope.txt"
        self.scope.write_text("192.0.2.0/24\n2001:db8::/64\n")
        self.expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        with mock.patch("sys.stdout", io.StringIO()):
            assessment.cli(["engagement", "create", "--name", "default", "--scope-file", str(self.scope),
                            "--expires-at", self.expiry, "--output", str(self.directory)], backend)
            assessment.cli(["import", str(Path(__file__).parent / "fixtures/nmap-mixed.xml"), "--scope-file", str(self.scope),
                            "--target", "192.0.2.0/24", "--target", "2001:db8::/64", "--output", str(self.directory)], backend)

    def tearDown(self):
        self.temporary.cleanup()

    def test_safe_sharing_excludes_free_text_addresses_paths_and_credentials(self):
        records = assessment.inventory(self.directory, "default")
        records[0]["metadata"].update(owner="Private User", notes="password=fixture-secret")
        first = operations.safe_share(records, b"a" * 32)
        text = json.dumps(first)
        for secret in ("Private User", "fixture-secret", "192.0.2.", "2001:db8", ".scanrunner", str(self.root)):
            self.assertNotIn(secret, text)
        self.assertEqual(first, operations.safe_share(records, b"a" * 32))
        self.assertNotEqual(first, operations.safe_share(records, b"b" * 32))
        self.assertTrue(all(set(row) == set(first["fields"]) for row in first["inventory"]))

    def test_signed_manifest_detects_report_and_signature_tampering(self):
        report = self.directory / "report.json"
        with mock.patch("sys.stdout", io.StringIO()):
            assessment.cli(["report", "--output", str(self.directory), "--destination", str(report)], backend)
        payload = operations.attestation_payload(backend, self.directory, "default", [report])
        key = b"private-fixture-key" * 3
        document = {"payload": payload, "signature": hmac.new(key, operations.canonical(payload), hashlib.sha256).hexdigest()}
        self.assertTrue(operations.verify_attestation(backend, document, key, self.directory)["verified"])
        altered = copy.deepcopy(document)
        altered["payload"]["engagement"] = "modified"
        with mock.patch.object(backend, "file_sha256") as read, self.assertRaisesRegex(ValueError, "authentication"):
            operations.verify_attestation(backend, altered, key, self.directory)
        read.assert_not_called()
        report.write_text("changed")
        with self.assertRaisesRegex(ValueError, "modified"):
            operations.verify_attestation(backend, document, key, self.directory)

    def test_schedule_preview_does_not_execute_and_changed_inputs_fail_closed(self):
        definition = self.root / "job.json"
        argv = ["-i", "192.0.2.10", "--scope-file", str(self.scope), "--output", str(self.directory),
                "--engagement", "default", "--yes", "--authorization-note", "Owned fixture"]
        definition.write_text(json.dumps({"argv": argv}))
        with mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["schedule", "add", "--definition", str(definition), "--at", "2000-01-01T00:00:00Z",
                           "--output", str(self.directory)], backend)
        with mock.patch.object(backend, "capture_process") as execute, mock.patch("sys.stdout", io.StringIO()) as output:
            workspace.cli(["schedule", "run-due", "--output", str(self.directory)], backend)
        execute.assert_not_called()
        self.assertEqual(len(json.loads(output.getvalue())), 1)
        self.scope.write_text("198.51.100.0/24\n")
        with mock.patch.object(backend, "capture_process") as execute, mock.patch("sys.stdout", io.StringIO()) as output:
            workspace.cli(["schedule", "run-due", "--execute", "--output", str(self.directory)], backend)
        execute.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())[0]["status"], "Failed")

    def test_schedule_claim_is_single_execution_and_notifications_exclude_client_data(self):
        definition = self.root / "job.json"
        definition.write_text(json.dumps({"argv": ["-i", "192.0.2.10", "--scope-file", str(self.scope), "--output", str(self.directory),
            "--engagement", "default", "--yes", "--authorization-note", "Owned fixture"]}))
        with mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["schedule", "add", "--definition", str(definition), "--at", "2000-01-01T00:00:00Z", "--output", str(self.directory)], backend)
        def capture(command, directory, timeout):
            self.assertNotIn(str(self.scope), command)
            for name in ("stdout.bin", "stderr.bin"):
                (Path(directory) / name).write_bytes(b"")
            return 0, "Exited"
        with mock.patch.object(backend, "capture_process", side_effect=capture) as execute, mock.patch("sys.stdout", io.StringIO()) as output:
            workspace.cli(["schedule", "run-due", "--execute", "--output", str(self.directory)], backend)
            result = json.loads(output.getvalue())
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(set(result[0]["notification"]), {"job_id", "status"})
        with mock.patch.object(backend, "capture_process") as execute, mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["schedule", "run-due", "--execute", "--output", str(self.directory)], backend)
        execute.assert_not_called()

    def test_template_round_trip_and_report_layout(self):
        template = self.root / "template.json"
        with mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["template", "create", "--path", str(template), "--view", "executive", "--output", str(self.directory)], backend)
            workspace.cli(["template", "apply", "--path", str(template), "--name", "reused", "--expires-at", self.expiry, "--output", str(self.directory)], backend)
        self.assertEqual(assessment.engagement_policy(self.directory, "reused")["scope"], assessment.engagement_policy(self.directory, "default")["scope"])
        report = self.root / "executive.json"
        with mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["template", "report", "--path", str(template), "--destination", str(report), "--output", str(self.directory)], backend)
        self.assertIn("summary", json.loads(report.read_bytes()))
        self.assertNotIn("inventory", json.loads(report.read_bytes()))

    def test_scheduler_recovery_preserves_history_and_refuses_active_owner(self):
        import os
        import socket
        definition = self.root / "job.json"
        definition.write_text(json.dumps({"argv": ["-i", "192.0.2.10", "--scope-file", str(self.scope), "--output", str(self.directory),
            "--engagement", "default", "--yes", "--authorization-note", "Owned fixture"]}))
        with mock.patch("sys.stdout", io.StringIO()) as output:
            workspace.cli(["schedule", "add", "--definition", str(definition), "--at", "2000-01-01T00:00:00Z", "--output", str(self.directory)], backend)
        identifier = json.loads(output.getvalue())["id"]
        store = backend.RunStore(str(self.directory), {"tool": "local"})
        with store.connect() as database:
            database.execute("UPDATE schedules SET status='Running',result=? WHERE id=?", (json.dumps({"owner_pid": os.getpid(), "owner_host": socket.gethostname()}), identifier))
        with mock.patch("sys.stdout", io.StringIO()), self.assertRaisesRegex(ValueError, "still running"):
            workspace.cli(["schedule", "recover", "--id", identifier, "--output", str(self.directory)], backend)
        with mock.patch.object(workspace, "process_alive", return_value=False), mock.patch("sys.stdout", io.StringIO()) as output:
            workspace.cli(["schedule", "recover", "--id", identifier, "--output", str(self.directory)], backend)
        self.assertEqual(json.loads(output.getvalue())["status"], "Pending")
        with store.connect() as database:
            self.assertTrue(database.execute("SELECT 1 FROM schedule_events WHERE schedule_id=?", (identifier,)).fetchone())
        store.end("Test completed")

    def test_trend_history_preserves_ambiguous_states_and_coverage(self):
        result = operations.trend_report(self.directory, "default", "site")
        self.assertTrue(result["observations"])
        self.assertTrue(any(port["state"] == "open|filtered" for row in result["observations"] for port in row["port_states"]))
        self.assertTrue(all(row["imported"] for row in result["observations"]))
        self.assertTrue(result["group_runs"])
        self.assertEqual(sum(row["observed_assets"] for row in result["group_runs"]), len(result["observations"]))
        self.assertNotIn("Remediated", json.dumps(result))

    def test_advisory_snapshot_is_manual_immutable_and_banner_match_stays_potential(self):
        # Minimal affected-version fields from the published CVE JSON record at
        # CVEProject/cvelistV5/cves/2024/3xxx/CVE-2024-3094.json.
        snapshot = self.root / "cve.json"
        snapshot.write_text(json.dumps({"dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {"cveId": "CVE-2024-3094", "state": "PUBLISHED"},
            "containers": {"cna": {"affected": [{"packageName": "xz", "versions": [{"version": "5.6.0", "status": "affected"}, {"version": "5.6.1", "status": "affected"}]}]}}}))
        with mock.patch.object(backend.subprocess, "Popen") as process, mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["advisory", "import", "--path", str(snapshot), "--source", "https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/3xxx/CVE-2024-3094.json", "--output", str(self.directory)], backend)
        process.assert_not_called()
        records = assessment.inventory(self.directory, "default")
        next(record for record in records if record["services"])["services"][0].update(product="xz", version="5.6.0")
        with mock.patch.object(assessment, "inventory", return_value=records):
            result = workspace.correlate(backend, self.directory, "default")
        self.assertEqual(result["candidates"][0]["status"], "Potential")
        self.assertIn("backports", result["candidates"][0]["limitations"])
        with assessment.read_database(self.directory) as database:
            path = Path(database.execute("SELECT path FROM advisory_snapshots").fetchone()[0])
        path.write_text("tampered")
        with self.assertRaisesRegex(ValueError, "integrity"):
            workspace.correlate(backend, self.directory, "default")

    def test_tui_noninteractive_and_rule_pack_have_no_network_effects(self):
        with mock.patch.object(backend.subprocess, "Popen") as process, mock.patch("builtins.input") as read, mock.patch("sys.stdout", io.StringIO()):
            workspace.cli(["tui", "--once", "--output", str(self.directory)], backend)
        process.assert_not_called()
        read.assert_not_called()
        catalog = operations.rules_catalog(backend)
        self.assertEqual(len({rule["id"] for rule in catalog["rules"]}), len(catalog["rules"]))
        self.assertTrue(all(rule["prerequisites"] and rule["regressions"] for rule in catalog["rules"]))

import csv
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scanrunner_lib import scanrunner_assessment as assessment

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("assessment_backend", ROOT / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)
FIXTURE = ROOT / "tests" / "fixtures" / "nmap-mixed.xml"


class NormalizedAssessmentTests(unittest.TestCase):
    def test_iso_utc_z_timestamp_works_on_supported_python_versions(self):
        self.assertEqual(assessment.parse_timestamp("2026-11-12T00:00:00Z").isoformat(), "2026-11-12T00:00:00+00:00")
        with self.assertRaises(ValueError):
            assessment.parse_timestamp("2026-11-12T00:00:00")
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "out"
        self.scope = self.directory / "scope.txt"
        self.scope.write_text("192.0.2.0/24\n2001:db8::/64\n")

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, *argv):
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            result = assessment.cli([*argv, "--output", str(self.output)], sr)
        self.assertEqual(result, 0)
        return json.loads(output.getvalue()) if output.getvalue() else None

    def import_fixture(self, path=FIXTURE):
        return self.command("import", str(path), "--scope-file", str(self.scope),
                            "--target", "192.0.2.0/24", "--target", "2001:db8::/64")

    def test_import_preserves_hosts_protocol_states_and_evidence_without_scanning(self):
        with mock.patch.object(sr.subprocess, "Popen") as launch, \
                mock.patch.object(sr.socket, "getaddrinfo") as dns:
            imported = self.import_fixture()
        launch.assert_not_called()
        dns.assert_not_called()
        self.assertTrue(imported["imported"])
        records = self.command("inventory")
        self.assertEqual(len(records), 3)
        host = next(record for record in records if record["service_address"] == "192.0.2.10")
        self.assertEqual({(port["port"], port["transport"], port["state"]) for port in host["services"]},
                         {(445, "tcp", "open"), (22, "tcp", "closed"), (3389, "tcp", "filtered"), (161, "udp", "open|filtered")})
        self.assertEqual(host["target"], "192.0.2.0/24")
        self.assertEqual(host["observed_at"], "Not determined")
        self.assertEqual(host["execution_outcome"], "Imported")
        self.assertEqual(sr.file_sha256(host["artifact"]), host["raw_sha256"])
        observations = self.command("observations")
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(observation["verification_status"] == "Needs Verification" for observation in observations))
        self.assertTrue(all("/script[" in observation["evidence_location"] for observation in observations))
        history = sr.review_run_history(str(self.output))
        self.assertTrue(all(job["evidence_integrity"] == "Verified" for job in history["jobs"]))

    def test_metadata_survives_import_and_all_export_formats_preserve_associations(self):
        self.import_fixture()
        original = self.command("inventory")
        host = next(record for record in original if record["service_address"] == "192.0.2.10")
        metadata = self.directory / "metadata.json"
        metadata.write_text(json.dumps({"owner": "assessor", "notes": "<script>alert(1)</script>"}))
        self.command("asset", host["asset_id"], "--metadata", str(metadata))
        self.import_fixture()
        records = self.command("inventory", "--owner", "assessor")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["asset_id"], host["asset_id"])
        self.assertEqual(records[0]["metadata"]["owner"], "assessor")
        rows = assessment.inventory_rows(self.command("inventory"))
        for format_name in ("json", "csv", "html"):
            destination = self.directory / ("inventory." + format_name)
            assessment.export_records(sr, rows, destination, format_name)
            if format_name == "json":
                self.assertEqual(json.loads(destination.read_text()), rows)
            elif format_name == "csv":
                with destination.open(newline="", encoding="utf-8") as file:
                    exported = list(csv.DictReader(file))
                self.assertEqual(len(exported), 6)
                self.assertTrue(any(row["address"] == "192.0.2.10" and row["state"] == "open|filtered" for row in exported))
            else:
                self.assertNotIn("<script>alert", destination.read_text())
                self.assertIn("&lt;script&gt;", destination.read_text())

    def test_multiple_addresses_do_not_duplicate_untested_service_endpoints(self):
        source = self.directory / "multiple-addresses.xml"
        text = FIXTURE.read_text().replace('<address addr="192.0.2.10" addrtype="ipv4"/>',
                '<address addr="192.0.2.10" addrtype="ipv4"/><address addr="2001:db8::99" addrtype="ipv6"/>')
        source.write_text(text)
        self.import_fixture(source)
        records = self.command("inventory")
        host = next(record for record in records if len(record["addresses"]) == 2)
        self.assertEqual(host["service_address"], "Not determined")
        rows = assessment.inventory_rows([host])
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["address"] == "Not determined" for row in rows))

    def test_out_of_scope_import_is_rejected_before_storage(self):
        self.scope.write_text("192.0.2.0/24\n")
        with self.assertRaises(ValueError):
            self.import_fixture()
        self.assertFalse(self.output.exists())

    def test_analyst_address_alias_preserves_asset_identity_across_retest(self):
        self.import_fixture()
        host = next(record for record in self.command("inventory") if record["service_address"] == "192.0.2.10")
        self.command("asset", host["asset_id"], "--add-address", "192.0.2.20")
        source = self.directory / "readdressed.xml"
        source.write_text(FIXTURE.read_text().replace("192.0.2.10", "192.0.2.20"))
        self.import_fixture(source)
        retest = next(record for record in self.command("inventory") if record["service_address"] == "192.0.2.20")
        self.assertEqual(host["asset_id"], retest["asset_id"])

    def test_registered_engagement_scope_cannot_be_widened_on_import(self):
        self.scope.write_text("192.0.2.0/24\n")
        self.command("engagement", "create", "--name", "default", "--scope-file", str(self.scope))
        wider = self.directory / "wider.txt"
        wider.write_text("192.0.2.0/24\n2001:db8::/64\n")
        with self.assertRaisesRegex(ValueError, "registered engagement scope"):
            self.command("import", str(FIXTURE), "--scope-file", str(wider), "--target", "2001:db8::/64")

    def test_exports_redact_nested_secrets_and_preserve_raw_bytes(self):
        source = self.directory / "secret.xml"
        source.write_text(FIXTURE.read_text().replace("message_signing: disabled", "password=fixture-secret"))
        original = source.read_bytes()
        self.import_fixture(source)
        observations = self.command("observations")
        self.assertNotIn("fixture-secret", json.dumps(observations))
        for format_name in ("json", "csv", "html"):
            destination = self.directory / ("safe." + format_name)
            assessment.export_records(sr, [{"nested": {"value": "password=fixture-secret"}}], destination, format_name)
            self.assertNotIn("fixture-secret", destination.read_text())
        self.assertEqual(source.read_bytes(), original)
        evidence = next(record["artifact"] for record in self.command("inventory"))
        retained = Path(evidence).read_bytes()
        with self.assertRaisesRegex(ValueError, "original evidence"):
            assessment.export_records(sr, [], evidence, "json")
        self.assertEqual(Path(evidence).read_bytes(), retained)

    def test_malformed_import_cannot_create_observations(self):
        for replacement in ['portid="bad"', 'portid="70000"']:
            source = self.directory / "bad.xml"
            source.write_text(FIXTURE.read_text().replace('portid="445"', replacement))
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.import_fixture(source)
        history = sr.review_run_history(str(self.output))
        self.assertTrue(all(run["ended"] for run in history["runs"]))
        self.assertTrue(all(job["outcome"] == "Import failed" for job in history["jobs"]))

    def test_port_filter_exports_only_selected_services(self):
        self.import_fixture()
        records = self.command("inventory", "--port", "445", "--transport", "tcp")
        self.assertEqual(len(records), 1)
        self.assertEqual([(service["port"], service["transport"]) for service in records[0]["services"]], [(445, "tcp")])

    def test_exact_states_and_os_guess_confidence_survive_normalization(self):
        source = self.directory / "states.xml"
        states = ["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown"]
        for state in states:
            text = FIXTURE.read_text().replace('<state state="open"/>', f'<state state="{state}"/>', 1)
            text = text.replace('<hostnames>', '<os><osmatch name="Synthetic OS guess" accuracy="80"/></os><hostnames>', 1)
            source.write_text(text)
            self.import_fixture(source)
            host = next(record for record in self.command("inventory") if record["service_address"] == "192.0.2.10")
            self.assertEqual(host["services"][0]["state"], state)
            self.assertEqual(host["os_guesses"], [{"name": "Synthetic OS guess", "confidence": "80"}])
            self.assertEqual(assessment.inventory_rows([host])[0]["state"], state)

    def test_failed_local_operation_closes_its_run(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            self.command("asset", "missing", "--add-address", "192.0.2.99")
        self.assertTrue(all(run["ended"] for run in sr.review_run_history(str(self.output))["runs"]))

    def test_registered_scope_cannot_be_widened_by_scan_arguments(self):
        self.scope.write_text("192.0.2.0/24\n")
        self.command("engagement", "create", "--name", "default", "--scope-file", str(self.scope))
        wider = self.directory / "wider.txt"
        wider.write_text("198.51.100.0/24\n")
        argv = ["scanrunner", "-i", "198.51.100.1", "--scope-file", str(wider), "-o", str(self.output), "--yes", "--skip-ping"]
        with mock.patch("sys.argv", argv), mock.patch("sys.stderr", io.StringIO()), \
                mock.patch.object(sr, "scanner_version") as version, mock.patch.object(sr.socket, "getaddrinfo") as dns, \
                self.assertRaises(SystemExit) as raised:
            sr.main()
        self.assertEqual(raised.exception.code, 1)
        version.assert_not_called()
        dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()

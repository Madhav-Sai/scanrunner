"""Conservative parser and outcome regressions using synthetic evidence only."""
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
spec = importlib.util.spec_from_file_location("fixture_scanrunner", ROOT / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class EvidenceFixtureTests(unittest.TestCase):
    def test_only_exact_open_ports_and_correct_hosts_are_exported(self):
        hosts = sr._hosts_from_xml(FIXTURES / "nmap-mixed.xml")
        self.assertEqual([(h["address"], [p["port"] for p in h["ports"]]) for h in hosts],
                         [("192.0.2.10", ["445/tcp"]), ("2001:db8::10", ["53/udp"]),
                          ("192.0.2.11", [])])
        self.assertEqual(hosts[2]["status"], "down")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copyfile(FIXTURES / "nmap-mixed.xml", Path(tmp) / "fixture.xml")
            sr.write_inventory(tmp, ["fixture"], {}, True)
            rows = json.loads((Path(tmp) / "open-ports-inventory.json").read_text())
            self.assertEqual(len(rows), 2)
            self.assertFalse(any("confirmed" in str(row).lower() for row in rows))
            self.assertNotIn("vulnerab", (Path(tmp) / "open-ports-report.html").read_text().lower())

    def test_empty_broken_partial_and_missing_evidence_never_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "fixture.txt"
            report.write_text("")
            for name in ("nmap-broken.xml", "nmap-partial.xml"):
                with self.subTest(name=name):
                    shutil.copyfile(FIXTURES / name, report.with_suffix(".xml"))
                    self.assertEqual(sr.parse_nmap_hosts(str(report)), [])
                    self.assertNotEqual(sr.get_file_status(str(report)), "COMPLETE")

    def test_failed_empty_and_timeout_process_results_do_not_complete(self):
        scenarios = json.loads((FIXTURES / "scenarios.json").read_text())
        for scenario in scenarios["processes"]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp) / "fixture.txt"
                report.write_text(scenario["stdout"])
                result = subprocess.CompletedProcess([], **scenario)
                with mock.patch.object(sr.subprocess, "run", return_value=result) as launch:
                    status, attempts, _ = sr.run_nmap_quiet("192.0.2.10", str(report), [], False, 0)
                self.assertEqual((status, attempts), ("FAILED", 1))
                launch.assert_called_once()

    def test_netexec_ambiguity_does_not_create_confirmation(self):
        rows = sr.parse_nxc_output((FIXTURES / "netexec.txt").read_text(), ["192.0.2.10"])
        unknown = next(row for row in rows if row["target"] == "192.0.2.12")
        self.assertEqual(unknown["smb_signing"], "None")
        self.assertFalse(any("confirmed" in str(row).lower() for row in rows))

    def test_different_coverage_and_missing_host_do_not_claim_remediation(self):
        old = {"192.0.2.10": {"22/tcp": "ssh", "80/tcp": "http"},
               "192.0.2.11": {"445/tcp": "microsoft-ds"}}
        # A smaller port selection is indistinguishable from closure in these maps.
        new = {"192.0.2.10": {"22/tcp": "ssh"}}
        with tempfile.TemporaryDirectory() as before, tempfile.TemporaryDirectory() as after:
            output = io.StringIO()
            with mock.patch.object(sr, "collect_open_ports", side_effect=[old, new]), \
                    mock.patch("sys.stdout", output):
                self.assertEqual(sr.print_diff(before, after), 0)
            result = json.loads((Path(after) / "scan-diff.json").read_text())
        self.assertIn("no longer observed open: 80/tcp/http", output.getvalue())
        self.assertNotIn("now closed:", output.getvalue())
        self.assertEqual(result["closed"], {"192.0.2.10": ["80/tcp/http"]})
        self.assertEqual(result["missing_hosts"], ["192.0.2.11"])
        self.assertEqual(result["coverage_comparability"], "Not verified")


if __name__ == "__main__":
    unittest.main()

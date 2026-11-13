"""PingMe adapter contracts; ordinary tests never launch network probes."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scanrunner_lib import scanrunner_discovery as discovery
from scanrunner_lib import scanrunner_plugins as plugins
from test_roadmap import backend


def row(address="127.0.0.1", status="REACHABLE", **changes):
    return {"ip": address, "status": status, "alive": status == "REACHABLE",
            "icmp_alive": status == "REACHABLE", "tcp_open": [], **changes}


def reports(directory, alive=None, silent=None, errors=None):
    for name, rows in (("alive.json", alive or []), ("no-response.json", silent or []), ("errors.json", errors or [])):
        (Path(directory) / name).write_text(json.dumps(rows), encoding="utf-8")


class DiscoveryTests(unittest.TestCase):
    def test_literal_expansion_bounded_and_no_dns(self):
        with mock.patch.object(backend.socket, "getaddrinfo") as dns:
            self.assertEqual(discovery.expand_targets(["127.0.0.0/30", "::1/128"]), ["127.0.0.1", "127.0.0.2", "::1"])
            for value in ("localhost", "10.0.0.0/8", "224.0.0.1", "0.0.0.0", "255.255.255.255"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    discovery.expand_targets([value])
            dns.assert_not_called()

    def test_positive_negative_error_and_tcp_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            addresses = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
            reports(tmp, [row(tcp_open=[443], icmp_alive=False)], [row(addresses[1], "NO RESPONSE")],
                    [row(addresses[2], "PROBE ERROR", tcp_open=[443], probe_error="Proxy suspected")])
            parsed = discovery.parse_results(tmp, addresses, [443])
            self.assertEqual([r["outcome"] for _, rows in parsed for r in rows], ["REACHABLE", "NO RESPONSE", "PROBE ERROR"])
            self.assertEqual(len({r["evidence_location"] for _, rows in parsed for r in rows}), 3)
            with self.assertRaises(ValueError):
                discovery.parse_results(tmp, addresses, [])

    def test_malformed_conflicting_missing_and_off_scope_outputs_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for result in (row(alive=False), row(icmp_alive=False), row(status="CONFIRMED"),
                           row(ip="192.0.2.1"), row(icmp_alive="yes"), row(tcp_open=[True]), row(tcp_open="443")):
                reports(tmp, [result])
                with self.subTest(result=result), self.assertRaises(ValueError):
                    discovery.parse_results(tmp, ["127.0.0.1"], [])
            reports(tmp, [row(), row()])
            with self.assertRaises(ValueError):
                discovery.parse_results(tmp, ["127.0.0.1"], [])
            reports(tmp)
            with self.assertRaises(ValueError):
                discovery.parse_results(tmp, ["127.0.0.1"], [])
            (Path(tmp) / "alive.json").write_text("{}")
            with self.assertRaises(ValueError):
                discovery.parse_results(tmp, ["127.0.0.1"], [])

    def test_preview_never_executes_or_writes_and_scope_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / "scope.txt"
            scope.write_text("127.0.0.1\n")
            args = ["--target", "127.0.0.1", "--scope-file", str(scope), "--pingme-script", "missing-pingme.py",
                    "--authorization-note", "Owned lab", "-o", str(root / "out"), "--dry-run"]
            with mock.patch.object(discovery.subprocess, "run") as run, mock.patch.object(backend, "capture_process") as capture, \
                    mock.patch.object(backend.socket, "getaddrinfo") as dns, mock.patch("sys.stdout", io.StringIO()) as output:
                self.assertEqual(discovery.cli(args, backend), 0)
                preview = json.loads(output.getvalue())
                self.assertIn("--no-config", preview["argv"])
                self.assertNotIn("--notify", preview["argv"])
                args[1] = "127.0.0.2"
                with self.assertRaises(ValueError):
                    discovery.cli(args, backend)
                run.assert_not_called()
                capture.assert_not_called()
                dns.assert_not_called()
            self.assertFalse((root / "out").exists())

    def test_real_child_capture_persists_associated_evidence_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / "scope.txt"
            scope.write_text("127.0.0.0/30\n")
            script = root / "pingme fixture.py"
            # A real subprocess exercises argv quoting and the output contract;
            # this fixture performs no DNS or network actions.
            script.write_text('''import sys,json
from pathlib import Path
if "--version" in sys.argv:
    print("pingme 3.3.0 (reliable-cross-platform)")
    raise SystemExit(0)
def value(flag): return sys.argv[sys.argv.index(flag)+1]
addresses=Path(value("--file")).read_text().splitlines()
for index,flag in enumerate(("--alive-out","--dead-out","--error-out")):
    rows=[dict(ip=ip,status="REACHABLE" if i==0 else "NO RESPONSE",alive=i==0,icmp_alive=i==0,tcp_open=[]) for i,ip in enumerate(addresses) if i==index]
    Path(value(flag)).write_text(json.dumps(rows))
raise SystemExit(1)
''', encoding="utf-8")
            args = ["--target", "127.0.0.0/30", "--scope-file", str(scope), "--pingme-script", str(script),
                    "--authorization-note", "Owned lab", "-o", str(root / "out"), "--json"]
            with mock.patch("sys.stdout", io.StringIO()) as output:
                self.assertEqual(discovery.cli(args, backend), 0)
                result = json.loads(output.getvalue())
            self.assertEqual(result["counts"], {"REACHABLE": 1, "NO RESPONSE": 1, "PROBE ERROR": 0})
            reachable = Path(result["reachable_file"])
            self.assertEqual(reachable.read_text(), "127.0.0.1\n")
            with mock.patch("sys.stdout", io.StringIO()) as output:
                self.assertEqual(plugins.cli(["observations", "-o", str(root / "out")], backend), 0)
                observations = json.loads(output.getvalue())
            self.assertEqual(len(observations), 2)
            self.assertTrue(all(r["status"] == "Needs Verification" and r["source_tool"] == "pingme" for r in observations))
            (reachable.parent / "alive.json").write_text("[]")
            with self.assertRaises(ValueError):
                plugins.cli(["observations", "-o", str(root / "out")], backend)

    def test_engagement_exclusion_scope_and_expiry_are_enforced_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / "scope.txt"
            scope.write_text("127.0.0.0/24\n")
            args = ["--target", "127.0.0.1", "--scope-file", str(scope), "--pingme-script", "missing.py",
                    "--authorization-note", "Owned lab", "--dry-run", "-o", str(root / "out")]
            policies = [dict(scope=["127.0.0.0/24"], exclusions=["127.0.0.1"]),
                        dict(scope=["127.0.0.2"], exclusions=[]),
                        dict(scope=["127.0.0.1"], exclusions=[], expires_at="2000-01-01T00:00:00Z")]
            for policy in policies:
                with self.subTest(policy=policy), mock.patch.object(discovery.assessment, "engagement_policy", return_value=policy), \
                        mock.patch.object(discovery.subprocess, "run") as run, self.assertRaises(ValueError):
                    discovery.cli(args, backend)
                run.assert_not_called()
            self.assertFalse((root / "out").exists())

    def test_wrong_version_and_failed_child_never_publish_reachable_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / "scope.txt"
            scope.write_text("127.0.0.1\n")
            script = root / "pingme.py"
            script.write_text('print("pingme 99.0.0")\n')
            args = ["--target", "127.0.0.1", "--scope-file", str(scope), "--pingme-script", str(script),
                    "--authorization-note", "Owned lab", "-o", str(root / "out")]
            with self.assertRaisesRegex(ValueError, "version"):
                discovery.cli(args, backend)
            self.assertFalse(list((root / "out").rglob("reachable.txt")))
            script.write_text('import sys\nprint("pingme 3.3.0 (reliable-cross-platform)")\nraise SystemExit(0 if "--version" in sys.argv else 2)\n')
            with self.assertRaisesRegex(ValueError, "failed"):
                discovery.cli(args, backend)
            self.assertFalse(list((root / "out").rglob("reachable.txt")))

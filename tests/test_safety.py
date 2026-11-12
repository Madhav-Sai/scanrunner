import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("safety_scanrunner", ROOT / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class ScopeSafetyTests(unittest.TestCase):
    def test_netexec_version_exit_one_requires_a_version_line(self):
        result = subprocess.CompletedProcess([], 1, stdout=b"1.5.1 - Fixture - abc - 0\n", stderr=b"")
        with mock.patch.object(sr.subprocess, "run", return_value=result):
            self.assertEqual(sr.scanner_version("nxc", True), ("1.5.1 - Fixture - abc - 0", 1))
        result.stdout = b"an unrelated failure"
        with mock.patch.object(sr.subprocess, "run", return_value=result), self.assertRaises(ValueError):
            sr.scanner_version("nxc", True)

    def test_mixed_dns_denied_and_all_inside_answers_pinned(self):
        resolver = mock.Mock(return_value=(["192.0.2.1", "198.51.100.1"], "fixture"))
        with self.assertRaises(ValueError):
            sr.ScopeGuard(["fixture.invalid"], ["192.0.2.0/24"], resolver=resolver)
        resolver.return_value = (["192.0.2.1", "192.0.2.2"], "fixture")
        guard = sr.ScopeGuard(["fixture.invalid"], ["192.0.2.0/24"], resolver=resolver)
        with mock.patch.object(sr, "ACTIVE_SCOPE", guard):
            command = sr._build_nmap_command("fixture.invalid", "r.txt", [])
        self.assertEqual(command[command.index("--") + 1:], ["192.0.2.1", "192.0.2.2"])

    def test_named_dns_changes_and_failed_resolution_denied(self):
        resolver = mock.Mock(return_value=(["192.0.2.1"], "fixture"))
        guard = sr.ScopeGuard(["fixture.invalid"], ["fixture.invalid"], resolver=resolver)
        for changed in (["198.51.100.1"], []):
            resolver.return_value = (changed, "fixture")
            with self.assertRaises(ValueError):
                guard.destinations("fixture.invalid")

    def test_empty_scope_exclusions_and_expansion_fail_closed(self):
        for targets, scope, exclusions in [
                (["192.0.2.1"], [], []),
                (["192.0.2.0/24"], ["192.0.2.0/24"], ["192.0.2.1"]),
                (["192.0.2.0/23"], ["192.0.2.0/24"], []),
                (["2001:db8:1::1"], ["2001:db8::/64"], []),
                (["../../outside"], ["192.0.2.0/24"], [])]:
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                sr.ScopeGuard(targets, scope, exclusions)
        guard = sr.ScopeGuard(["192.0.2.1-5", "2001:db8::1"], None)
        self.assertEqual(guard.destinations("192.0.2.1-5"), ["192.0.2.1-5"])

    def test_all_address_families_resolved_without_selecting_first(self):
        answers = [(socket.AF_INET, 1, 6, "", ("192.0.2.1", 0)),
                   (socket.AF_INET6, 1, 6, "", ("2001:db8::1", 0, 0, 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=answers):
            addresses, _ = sr.resolve_scope_addresses("fixture.invalid")
        self.assertEqual(addresses, ["192.0.2.1", "2001:db8::1"])

    def test_scope_extending_arguments_and_credential_defaults_denied(self):
        for argv in (["--script", "broadcast-*"], ["--script-args", "newtargets=true"],
                     ["--resume", "external.xml"], ["192.0.2.2"], ["--exclude", "192.0.2.2"],
                     ["-iL", "external.txt"], ["--datadir", "custom"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                sr.validate_scan_options(argv)
        with self.assertRaises(ValueError):
            sr.validate_scan_options(["-u", "analyst"], nxc=True)

    def test_dry_run_spawns_nothing_resolves_nothing_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "must-not-exist"
            for target in ("192.0.2.1", "fixture.invalid", "2001:db8::1"):
                captured = io.StringIO()
                with mock.patch("sys.argv", ["scanrunner", "-i", target, "--dry-run", "--json", "-o", str(output)]), \
                        mock.patch.object(sr.subprocess, "Popen") as popen, \
                        mock.patch.object(sr.subprocess, "run") as run, \
                        mock.patch.object(sr.socket, "getaddrinfo") as dns, \
                        mock.patch("sys.stdout", captured):
                    sr.main()
                preview = json.loads(captured.getvalue())
                self.assertEqual(preview["commands"][0]["target"], target)
                popen.assert_not_called()
                run.assert_not_called()
                dns.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

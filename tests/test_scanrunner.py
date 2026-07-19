import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scanrunner.py"
spec = importlib.util.spec_from_file_location("scanrunner", SCRIPT)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class TargetTests(unittest.TestCase):
    def test_normalize_targets(self):
        cases = {
            "https://example.com/login": "example.com",
            "example.com:443": "example.com",
            "http://sub.example.com:8080/a": "sub.example.com",
            "10.0.0.0/24": "10.0.0.0/24",
            "[2001:db8::1]:443": "2001:db8::1",
        }
        for raw, expected in cases.items():
            self.assertEqual(sr.normalize_target(raw), expected)

    def test_load_targets_deduplicates_and_removes_comments(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("example.com # site\nhttps://example.com/path\n10.0.0.1\n\n")
            name = fh.name
        try:
            self.assertEqual(sr.load_targets(name), ["example.com", "10.0.0.1"])
        finally:
            os.unlink(name)

    def test_resolution_timeout_or_success_contract(self):
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("1.2.3.4", 0))]):
            target, message = sr.resolve_scan_target("example.com")
        self.assertEqual(target, "1.2.3.4")
        self.assertIn("resolved", message)


class HelpAndCompletionTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_top_help_is_nested(self):
        result = self.run_cli("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Focused help:", result.stdout)
        self.assertNotIn("Target input (choose one):", result.stdout)

    def test_focused_help_pages(self):
        for args, phrase in [
            (("-nxc", "-h"), "NetExec (NXC) help"),
            (("--template", "-h"), "Nmap templates help"),
            (("--split", "-h"), "Target splitting help"),
            (("--nmap", "-h"), "Nmap scan help"),
            (("--reports", "-h"), "Reporting and automation help"),
        ]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0)
                self.assertIn(phrase, result.stdout)

    def test_invalid_parallel_requires_yes(self):
        result = self.run_cli("-i", "127.0.0.1", "--parallel", "2")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--parallel requires --yes", result.stderr)

    def test_completion_generation(self):
        for shell in ("zsh", "bash"):
            result = self.run_cli("--completion", shell)
            self.assertEqual(result.returncode, 0)
            self.assertIn("scanrunner", result.stdout)

    def test_bad_completion_shell(self):
        result = self.run_cli("--completion", "fish")
        self.assertEqual(result.returncode, 2)


class NxcParsingTests(unittest.TestCase):
    def test_parse_smb_output(self):
        output = "SMB 10.10.10.10 445 DC01 [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:LAB) (signing:True) (SMBv1:False)"
        row = sr.parse_nxc_output(output, ["10.10.10.10"])[0]
        self.assertEqual(row["hostname"], "DC01")
        self.assertEqual(row["smbv1"], "False")
        self.assertEqual(row["smb_signing"], "True")
        self.assertIn("Windows Server 2022", row["os"])


class CommandTests(unittest.TestCase):
    def test_nmap_command_preserves_quoted_argument_token(self):
        cmd = sr._build_nmap_command("10.0.0.1", "/tmp/a.txt",
                                     ["--script-args", "user=admin pass=test"])
        self.assertIn("user=admin pass=test", cmd)
        self.assertEqual(cmd[-2:], ["--", "10.0.0.1"])


if __name__ == "__main__":
    unittest.main()

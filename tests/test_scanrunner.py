import importlib.util
import os
import subprocess
import sys
import tempfile
import types
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

    def test_skip_no_ping_flag_parses(self):
        with mock.patch.object(sys, "argv", ["scanrunner", "-i", "127.0.0.1", "-ok"]):
            args = sr.parse_args()
        self.assertTrue(args.skip_no_ping)
        self.assertNotIn("-ok", args.nmap_extra)

    def test_skip_no_ping_long_flag_parses(self):
        with mock.patch.object(sys, "argv", ["scanrunner", "-i", "127.0.0.1", "--skip-no-ping"]):
            args = sr.parse_args()
        self.assertTrue(args.skip_no_ping)

    def test_nxc_rejects_skip_no_ping(self):
        result = self.run_cli("-i", "127.0.0.1", "-nxc", "smb", "-ok")
        self.assertEqual(result.returncode, 2)
        self.assertIn("skip-no-ping", result.stderr)

    def test_output_defaults_to_results_for_nmap_mode(self):
        with mock.patch.object(sys, "argv", ["scanrunner", "-i", "127.0.0.1"]):
            args = sr.parse_args()
        self.assertEqual(args.output, "results")

    def test_output_defaults_to_cwd_for_nxc_mode(self):
        with mock.patch.object(sys, "argv", ["scanrunner", "-i", "127.0.0.1", "-nxc", "smb"]):
            args = sr.parse_args()
        self.assertEqual(args.output, ".")

    def test_explicit_output_overrides_nxc_default(self):
        with mock.patch.object(sys, "argv",
                               ["scanrunner", "-i", "127.0.0.1", "-nxc", "smb", "-o", "myresults"]):
            args = sr.parse_args()
        self.assertEqual(args.output, "myresults")

    def test_split_size_flag_parses(self):
        with mock.patch.object(sys, "argv",
                               ["scanrunner", "-f", "targets.txt", "--split-size", "50"]):
            args = sr.parse_args()
        self.assertEqual(args.split_size, 50)
        self.assertIsNone(args.split)

    def test_split_and_split_size_are_mutually_exclusive(self):
        result = self.run_cli("-f", "targets.txt", "--split", "2", "--split-size", "5")
        self.assertEqual(result.returncode, 2)
        self.assertIn("only one of --split or --split-size", result.stderr)

    def test_split_size_help_routes_to_split_topic(self):
        result = self.run_cli("--split-size", "-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Target splitting help", result.stdout)


class AuditTrailTests(unittest.TestCase):
    def test_read_logged_ips_deduplicates(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("2026-01-01 00:00:00 | 10.0.0.1\n"
                     "2026-01-01 00:00:01 | 10.0.0.1\n"
                     "2026-01-01 00:00:02 | 10.0.0.2\n")
            name = fh.name
        try:
            self.assertEqual(sr.read_logged_ips(name), {"10.0.0.1", "10.0.0.2"})
        finally:
            os.unlink(name)

    def test_read_logged_ips_missing_file_returns_empty_set(self):
        self.assertEqual(sr.read_logged_ips(os.path.join(tempfile.gettempdir(), "no-such-file.txt")),
                         set())

    def test_print_summary_flags_unaccounted_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            completed, skipped, rescanned, not_ping, failed = (
                os.path.join(tmp, name) for name in
                ("completed.txt", "skipped.txt", "rescanned.txt", "not-pingip.txt", "failed.txt")
            )
            sr.log_to_file(completed, "10.0.0.1")
            with mock.patch("builtins.print"):
                sr.print_summary(["10.0.0.1", "10.0.0.2"], completed, skipped, rescanned,
                                 not_ping, failed, tmp)
            unaccounted_path = os.path.join(tmp, "unaccounted.txt")
            self.assertTrue(os.path.exists(unaccounted_path))
            with open(unaccounted_path, encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "10.0.0.2")

    def test_print_summary_writes_no_unaccounted_file_when_all_accounted(self):
        with tempfile.TemporaryDirectory() as tmp:
            completed, skipped, rescanned, not_ping, failed = (
                os.path.join(tmp, name) for name in
                ("completed.txt", "skipped.txt", "rescanned.txt", "not-pingip.txt", "failed.txt")
            )
            sr.log_to_file(completed, "10.0.0.1")
            with mock.patch("builtins.print"):
                sr.print_summary(["10.0.0.1"], completed, skipped, rescanned,
                                 not_ping, failed, tmp)
            self.assertFalse(os.path.exists(os.path.join(tmp, "unaccounted.txt")))


def _tab_args(**overrides):
    base = dict(no_auto_tabs=False, yes=False, parallel=1, nmap_extra=["-sV"],
                retries=0, skip_ping=False, skip_no_ping=False, no_color=False,
                scope_file=None, metadata_csv=None, html_report=False)
    base.update(overrides)
    return types.SimpleNamespace(**base)


class TerminalTabTests(unittest.TestCase):
    def test_skips_when_not_a_tty(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            result = sr.offer_terminal_tabs(_tab_args(), [f"10.0.0.{i}" for i in range(30)], "out")
        self.assertFalse(result)

    def test_skips_when_yes_flag_set(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True):
            result = sr.offer_terminal_tabs(_tab_args(yes=True), [f"10.0.0.{i}" for i in range(30)], "out")
        self.assertFalse(result)

    def test_skips_when_parallel_already_requested(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True):
            result = sr.offer_terminal_tabs(_tab_args(parallel=4), [f"10.0.0.{i}" for i in range(30)], "out")
        self.assertFalse(result)

    def test_skips_below_threshold(self):
        small_list = [f"10.0.0.{i}" for i in range(5)]
        with mock.patch.object(sys.stdin, "isatty", return_value=True):
            result = sr.offer_terminal_tabs(_tab_args(), small_list, "out")
        self.assertFalse(result)

    def test_declines_on_empty_answer(self):
        pending = [f"10.0.0.{i}" for i in range(30)]
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch.object(sr, "safe_input", return_value=""):
            result = sr.offer_terminal_tabs(_tab_args(), pending, "out")
        self.assertFalse(result)

    def test_launches_tabs_and_writes_manifest(self):
        pending = [f"10.0.0.{i}" for i in range(30)]
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = os.path.join(tmp, "out")
            os.makedirs(output_dir)
            with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(sr, "safe_input", return_value="3"), \
                 mock.patch.object(sr, "_spawn_windows_terminal", return_value=True) as win_spawn, \
                 mock.patch.object(sr, "_spawn_macos_terminal", return_value=True) as mac_spawn, \
                 mock.patch.object(sr, "_spawn_linux_terminal", return_value=True) as linux_spawn:
                result = sr.offer_terminal_tabs(_tab_args(), pending, output_dir)

            self.assertTrue(result)
            spawn_calls = win_spawn.call_count + mac_spawn.call_count + linux_spawn.call_count
            self.assertEqual(spawn_calls, 3)

            manifest_path = os.path.join(output_dir, "tab-manifest.txt")
            self.assertTrue(os.path.exists(manifest_path))
            with open(manifest_path, encoding="utf-8") as f:
                manifest_lines = [line for line in f.read().splitlines() if line]
            self.assertEqual(len(manifest_lines), 3)

            # Every pending target must appear in exactly one tab's target list —
            # this is the invariant that matters: nobody gets dropped or duplicated.
            all_manifest_targets = []
            for line in manifest_lines:
                _, tab_dir, targets_field = line.split("\t")
                all_manifest_targets.extend(targets_field.split(","))
                self.assertTrue(os.path.isdir(tab_dir))
            self.assertEqual(sorted(all_manifest_targets), sorted(pending))

            for index in (1, 2, 3):
                part_file = os.path.join(output_dir, "tabs", f"tab_{index}_targets.txt")
                self.assertTrue(os.path.exists(part_file))

            # Spawned command must force --yes/--no-auto-tabs and never leak
            # into a shared output directory across tabs.
            spawned_mock = next(m for m in (win_spawn, mac_spawn, linux_spawn) if m.call_count)
            command = spawned_mock.call_args_list[0][0][0]
            self.assertIn("--yes", command)
            self.assertIn("--no-auto-tabs", command)
            output_dirs_used = {command_call[0][0][command_call[0][0].index("-o") + 1]
                                for command_call in spawned_mock.call_args_list}
            self.assertEqual(len(output_dirs_used), 3)

    def test_falls_back_to_background_when_no_terminal_available(self):
        pending = [f"10.0.0.{i}" for i in range(30)]
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = os.path.join(tmp, "out")
            os.makedirs(output_dir)
            with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(sr, "safe_input", return_value="2"), \
                 mock.patch.object(sr, "_spawn_windows_terminal", return_value=False), \
                 mock.patch.object(sr, "_spawn_macos_terminal", return_value=False), \
                 mock.patch.object(sr, "_spawn_linux_terminal", return_value=False), \
                 mock.patch.object(sr, "_spawn_background") as background_spawn:
                result = sr.offer_terminal_tabs(_tab_args(), pending, output_dir)
            self.assertTrue(result)
            self.assertEqual(background_spawn.call_count, 2)


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

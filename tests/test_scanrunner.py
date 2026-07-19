import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import scanrunner


class ScanrunnerTests(unittest.TestCase):
    def parse_arguments(self, arguments):
        previous_argv = sys.argv
        try:
            sys.argv = ["scanrunner.py", *arguments]
            return scanrunner.parse_args()
        finally:
            sys.argv = previous_argv


def add_test(name, function):
    setattr(ScanrunnerTests, name, function)


def write_executable(path, content):
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
    os.chmod(path, 0o755)


for profile_name, profile_options in scanrunner.SCAN_PROFILES.items():
    def test_profile(self, profile_name=profile_name, profile_options=profile_options):
        args = self.parse_arguments(["-f", "targets.txt", "--template", profile_name, "-vv"])
        self.assertEqual(args.profile, profile_name)
        self.assertEqual(args.nmap_extra, profile_options + ["-vv"])
    add_test(f"test_profile_{profile_name.replace('-', '_')}", test_profile)


for source, expected in (
    ("10.0.0.1", "10.0.0.1"),
    ("10.0.0.1 # web", "10.0.0.1"),
    (" # comment", ""),
    ("hostname # note", "hostname"),
    ("2001:db8::1", "2001:db8::1"),
    ("\tserver.internal\t", "server.internal"),
):
    def test_strip_comment(self, source=source, expected=expected):
        self.assertEqual(scanrunner.strip_inline_comment(source), expected)
    add_test(f"test_strip_comment_{len(ScanrunnerTests.__dict__)}", test_strip_comment)


for source, expected in (
    ("10.0.0.1", "10.0.0.1"),
    ("2001:db8::1", "2001_db8__1"),
    ("10.0.0.0/24", "10.0.0.0_24"),
    ("host.example", "host.example"),
    ("a/b/c", "a_b_c"),
    ("", ""),
):
    def test_sanitize_filename(self, source=source, expected=expected):
        self.assertEqual(scanrunner.sanitize_filename(source), expected)
    add_test(f"test_sanitize_filename_{len(ScanrunnerTests.__dict__)}", test_sanitize_filename)


for target, scope, expected in (
    ("10.0.0.1", [], True),
    ("10.0.0.1", ["10.0.0.1"], True),
    ("10.0.0.1", ["10.0.0.0/24"], True),
    ("10.0.1.1", ["10.0.0.0/24"], False),
    ("10.0.0.0/25", ["10.0.0.0/24"], True),
    ("10.0.0.0/23", ["10.0.0.0/24"], False),
    ("server.internal", ["server.internal"], True),
    ("server.internal", ["other.internal"], False),
):
    def test_target_scope(self, target=target, scope=scope, expected=expected):
        self.assertEqual(scanrunner.target_in_scope(target, scope), expected)
    add_test(f"test_target_scope_{len(ScanrunnerTests.__dict__)}", test_target_scope)


NXC_OUTPUT = "SMB 10.0.0.10 445 DC01 [*] Windows Server 2019 (name:DC01) (signing:True) (SMBv1:False)\n"

for output, target, null_auth_attempt, expected in (
    (NXC_OUTPUT, "10.0.0.10", False, {"hostname": "DC01", "os": "Windows Server 2019", "smbv1": "False", "smb_signing": "True"}),
    ("\x1b[32mSMB 10.0.0.10 445 DC01 [+] LAB\\guest:\x1b[0m\n", "10.0.0.10", False, {"null_auth": ""}),
    ("SMB 10.0.0.10 445 DC01 [+] LAB\\guest:\n", "10.0.0.10", True, {"null_auth": "Success"}),
    ("RDP 10.0.0.20 3389 WIN01 [*] (NLA:True)\n", "10.0.0.20", False, {"rdp_nla": "True"}),
    ("unstructured output\n", "10.0.0.10", False, {"hostname": "", "details": ""}),
    ("12:00 SMB 10.0.0.30 445 FILE01 [*] Windows 11 (name:FILE01)\n", "10.0.0.30", False, {"hostname": "FILE01"}),
):
    def test_parse_nxc_output(self, output=output, target=target, null_auth_attempt=null_auth_attempt, expected=expected):
        rows = scanrunner.parse_nxc_output(output, ["10.0.0.10", "10.0.0.20", "10.0.0.30"], null_auth_attempt)
        row = next(row for row in rows if row["target"] == target)
        for field, value in expected.items():
            self.assertEqual(row[field], value)
    add_test(f"test_parse_nxc_output_{len(ScanrunnerTests.__dict__)}", test_parse_nxc_output)


for options, expected in (
    (["-u", "", "-p", ""], True),
    (["--username=", "--password="], True),
    (["-u", "guest", "-p", ""], False),
    (["--username", "", "--password", "secret"], False),
    ([], False),
):
    def test_anonymous_credentials(self, options=options, expected=expected):
        self.assertEqual(scanrunner.uses_anonymous_nxc_credentials(options), expected)
    add_test(f"test_anonymous_credentials_{len(ScanrunnerTests.__dict__)}", test_anonymous_credentials)


for command, expected in (
    (["nxc", "smb", "host", "-p", "secret"], ["nxc", "smb", "host", "-p", "***"]),
    (["nxc", "smb", "host", "--password=secret"], ["nxc", "smb", "host", "--password=***"]),
    (["nxc", "smb", "host", "-H", "abc"], ["nxc", "smb", "host", "-H", "***"]),
):
    def test_redact_command(self, command=command, expected=expected):
        self.assertEqual(scanrunner.redact_command(command), expected)
    add_test(f"test_redact_command_{len(ScanrunnerTests.__dict__)}", test_redact_command)


for protocol, queries, expected_headers in (
    ("smb", [], ["target", "port", "hostname", "details"]),
    ("smb", ["os", "hostname", "smbv1"], ["target", "os", "hostname", "smbv1"]),
    ("rdp", ["rdp-nla"], ["target", "rdp_nla"]),
    ("smb", ["all"], ["target", "os", "hostname", "smbv1", "smb_signing", "null_auth", "rdp_nla"]),
):
    def test_nxc_columns(self, protocol=protocol, queries=queries, expected_headers=expected_headers):
        self.assertEqual([field for field, _ in scanrunner.nxc_table_columns(protocol, queries)], expected_headers)
    add_test(f"test_nxc_columns_{len(ScanrunnerTests.__dict__)}", test_nxc_columns)


for parts, expected_counts in ((1, [4]), (2, [2, 2]), (3, [2, 1, 1])):
    def test_split_target_file(self, parts=parts, expected_counts=expected_counts):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, "targets.txt")
            original = "one\ntwo\nthree\nfour\n"
            with open(source, "w", encoding="utf-8") as file:
                file.write(original)
            with contextlib.redirect_stdout(io.StringIO()):
                scanrunner.split_target_file(source, ["one", "two", "three", "four"], parts)
            with open(source, encoding="utf-8") as file:
                self.assertEqual(file.read(), original)
            counts = []
            for index in range(1, parts + 1):
                with open(os.path.join(directory, f"targets_part_{index}.txt"), encoding="utf-8") as file:
                    counts.append(len(file.readlines()))
            self.assertEqual(counts, expected_counts)
    add_test(f"test_split_target_file_{len(ScanrunnerTests.__dict__)}", test_split_target_file)


for arguments in (
    ["-i", "10.0.0.1", "--split", "1"],
    ["-f", "targets.txt", "--split", "0"],
    ["-f", "targets.txt", "--nxc-query", "os"],
    ["-f", "targets.txt", "--nxc", "smb", "--template", "quick"],
    ["-f", "targets.txt", "--parallel", "2"],
):
    def test_argument_rejections(self, arguments=arguments):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self.parse_arguments(arguments)
    add_test(f"test_argument_rejections_{len(ScanrunnerTests.__dict__)}", test_argument_rejections)


for platform, expected_timeout in (("darwin", "1000"), ("linux", "1")):
    def test_ping_timeout(self, platform=platform, expected_timeout=expected_timeout):
        with patch.object(scanrunner.sys, "platform", platform), patch.object(scanrunner.subprocess, "run") as run:
            run.return_value = SimpleNamespace(returncode=0)
            self.assertTrue(scanrunner.ping_host("10.0.0.1"))
            self.assertEqual(run.call_args.args[0], ["ping", "-c", "1", "-W", expected_timeout, "10.0.0.1"])
    add_test(f"test_ping_timeout_{platform}", test_ping_timeout)


for returncode in (0, 1):
    def test_run_nxc_writes_exports(self, returncode=returncode):
        with tempfile.TemporaryDirectory() as directory:
            result = SimpleNamespace(returncode=returncode, stdout=NXC_OUTPUT)
            with patch.object(scanrunner.subprocess, "run", return_value=result):
                with contextlib.redirect_stdout(io.StringIO()):
                    success = scanrunner.run_nxc("smb", "targets.txt", ["10.0.0.10"], [], ["os"], directory)
            self.assertEqual(success, returncode == 0)
            self.assertEqual(len([name for name in os.listdir(directory) if name.endswith(".txt")]), 1)
            self.assertEqual(len([name for name in os.listdir(directory) if name.endswith(".csv")]), 1)
            self.assertEqual(len([name for name in os.listdir(directory) if name.endswith(".json")]), 1)
    add_test(f"test_run_nxc_writes_exports_{returncode}", test_run_nxc_writes_exports)


for flag, value, attribute, expected in (
    ("--yes", None, "yes", True),
    ("--resume", None, "resume", True),
    ("--skip-ping", None, "skip_ping", True),
    ("--no-color", None, "no_color", True),
    ("--scope-file", "scope.txt", "scope_file", "scope.txt"),
    ("--retries", "2", "retries", 2),
    ("--parallel", "2", "parallel", 2),
    ("--metadata-csv", "assets.csv", "metadata_csv", "assets.csv"),
    ("--html-report", None, "html_report", True),
    ("--exclude", "10.0.0.5", "exclude", ["10.0.0.5"]),
    ("--exclude-file", "excluded.txt", "exclude_file", "excluded.txt"),
    ("-o", "assessment", "output", "assessment"),
):
    def test_flag_parsing(self, flag=flag, value=value, attribute=attribute, expected=expected):
        arguments = ["-f", "targets.txt", "--yes"] if flag == "--parallel" else ["-f", "targets.txt"]
        arguments.append(flag)
        if value is not None:
            arguments.append(value)
        args = self.parse_arguments(arguments)
        self.assertEqual(getattr(args, attribute), expected)
    add_test(f"test_flag_parsing_{attribute.replace('_', '')}", test_flag_parsing)


for extra, use_pn, expected in (
    ([], False, ["nmap", "--stats-every", "15s", "-oN", "report.txt", "-oX", "report.xml", "--", "host"]),
    (["-Pn", "-sV"], True, ["nmap", "--stats-every", "15s", "-Pn", "-sV", "-oN", "report.txt", "-oX", "report.xml", "--", "host"]),
    (["--stats-every", "30s"], True, ["nmap", "-Pn", "--stats-every", "30s", "-oN", "report.txt", "-oX", "report.xml", "--", "host"]),
):
    def test_build_nmap_command(self, extra=extra, use_pn=use_pn, expected=expected):
        self.assertEqual(scanrunner._build_nmap_command("host", "report.txt", extra, use_pn), expected)
    add_test(f"test_build_nmap_command_{len(ScanrunnerTests.__dict__)}", test_build_nmap_command)


for content, expected in (
    ("22/tcp open ssh\n443/tcp open https\n", ["22/tcp/ssh", "443/tcp/https"]),
    ("80/tcp closed http\n", []),
    ("\n  53/udp   open  domain\n", ["53/udp/domain"]),
):
    def test_parse_open_ports(self, content=content, expected=expected):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
            file.write(content)
            path = file.name
        try:
            self.assertEqual(scanrunner.parse_open_ports(path), expected)
        finally:
            os.unlink(path)
    add_test(f"test_parse_open_ports_{len(ScanrunnerTests.__dict__)}", test_parse_open_ports)


for write_html in (False, True):
    def test_write_inventory(self, write_html=write_html):
        with tempfile.TemporaryDirectory() as directory:
            report = os.path.join(directory, "10.0.0.1.txt")
            with open(report, "w", encoding="utf-8") as file:
                file.write("443/tcp open https\nNmap done\n")
            scanrunner.write_inventory(directory, ["10.0.0.1"],
                                       {"10.0.0.1": {"owner": "IT", "environment": "test"}}, write_html)
            with open(os.path.join(directory, "open-ports-inventory.json"), encoding="utf-8") as file:
                self.assertIn("https", file.read())
            self.assertEqual(os.path.exists(os.path.join(directory, "open-ports-report.html")), write_html)
    add_test(f"test_write_inventory_{write_html}", test_write_inventory)


for arguments, expected in (
    (["--help", "nxc"], "NetExec (NXC) help"),
    (["--template", "-h"], "Nmap templates help"),
    (["--parallel", "-h"], "--parallel N"),
):
    def test_help_routes(self, arguments=arguments, expected=expected):
        previous_argv = sys.argv
        try:
            sys.argv = ["scanrunner.py", *arguments]
            with contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as result:
                    scanrunner.handle_topic_help()
            self.assertEqual(result.exception.code, 0)
            self.assertIn(expected, output.getvalue())
        finally:
            sys.argv = previous_argv
    add_test(f"test_help_routes_{len(ScanrunnerTests.__dict__)}", test_help_routes)



def test_cli_nmap_end_to_end(self):
    with tempfile.TemporaryDirectory() as directory:
        binary_dir = os.path.join(directory, "bin")
        output_dir = os.path.join(directory, "output")
        os.mkdir(binary_dir)
        targets = os.path.join(directory, "targets.txt")
        with open(targets, "w", encoding="utf-8") as file:
            file.write("10.0.0.1\n")
        nmap_script = (
            "#!/bin/sh\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = \"-oN\" ]; then normal=\"$2\"; shift 2; continue; fi\n"
            "  if [ \"$1\" = \"-oX\" ]; then xml=\"$2\"; shift 2; continue; fi\n"
            "  shift\n"
            "done\n"
            "printf '22/tcp open ssh\\nNmap done\\n' > \"$normal\"\n"
            "printf '<nmaprun/>\\n' > \"$xml\"\n"
            "printf 'Nmap done\\n'\n"
        )
        write_executable(os.path.join(binary_dir, "nmap"), nmap_script)
        environment = os.environ.copy()
        environment["PATH"] = binary_dir + os.pathsep + environment["PATH"]
        result = subprocess.run(
            [sys.executable, "scanrunner.py", "-f", targets, "-o", output_dir,
             "--yes", "--skip-ping", "--html-report", "-sV"],
            cwd=PROJECT_ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.exists(os.path.join(output_dir, "10.0.0.1.txt")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "10.0.0.1.xml")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "open-ports-report.html")))


def test_cli_nxc_end_to_end(self):
    with tempfile.TemporaryDirectory() as directory:
        binary_dir = os.path.join(directory, "bin")
        output_dir = os.path.join(directory, "output")
        os.mkdir(binary_dir)
        targets = os.path.join(directory, "targets.txt")
        with open(targets, "w", encoding="utf-8") as file:
            file.write("10.0.0.10\n")
        nxc_script = (
            "#!/bin/sh\n"
            "printf 'SMB 10.0.0.10 445 DC01 [*] Windows Server 2019 (name:DC01) (signing:True) (SMBv1:False)\\n'\n"
        )
        write_executable(os.path.join(binary_dir, "nxc"), nxc_script)
        environment = os.environ.copy()
        environment["PATH"] = binary_dir + os.pathsep + environment["PATH"]
        result = subprocess.run(
            [sys.executable, "scanrunner.py", "-f", targets, "-o", output_dir,
             "--nxc", "smb", "--nxc-query", "os,hostname,smbv1"],
            cwd=PROJECT_ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Windows Server 2019", result.stdout)
        self.assertEqual(len([name for name in os.listdir(output_dir) if name.endswith(".csv")]), 1)


add_test("test_cli_nmap_end_to_end", test_cli_nmap_end_to_end)
add_test("test_cli_nxc_end_to_end", test_cli_nxc_end_to_end)


if __name__ == "__main__":
    unittest.main()

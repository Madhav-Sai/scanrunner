"""Beginner help discovery and executable preview examples without scans."""
import io
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest import mock

import scanrunner_help as help_content
from test_roadmap import backend


class BeginnerHelpTests(unittest.TestCase):
    def run_help(self, arguments):
        with mock.patch("sys.argv", ["scanrunner", *arguments]), mock.patch("sys.stdout", io.StringIO()) as output, \
                mock.patch.object(backend.subprocess, "Popen") as process, mock.patch.object(backend.subprocess, "run") as run, \
                mock.patch.object(backend.socket, "getaddrinfo") as dns:
            with self.assertRaises(SystemExit) as ended:
                backend.main()
            self.assertEqual(ended.exception.code, 0)
        process.assert_not_called()
        run.assert_not_called()
        dns.assert_not_called()
        return output.getvalue()

    def test_main_help_and_whats_new_expose_every_new_command(self):
        main = self.run_help(["--help"])
        self.assertIn("scanrunner guide", main)
        for command in help_content.GUIDES:
            self.assertIn("scanrunner " + command, main)
        changes = self.run_help(["--whats-new"])
        for command in ("plugin", "probe", "share", "attest", "schedule", "advisory", "template", "tui"):
            self.assertIn("scanrunner " + command, changes)

    def test_each_command_help_has_prerequisites_examples_and_next_action(self):
        for command in help_content.GUIDES:
            with self.subTest(command=command):
                content = self.run_help([command, "--help"])
                self.assertIn("Before you start", content)
                self.assertIn("Examples", content)
                self.assertIn("What to do next", content)
        self.assertIn("Create a readable assessment report", self.run_help(["help", "report"]))
        self.assertIn("Before you start", self.run_help(["plugin"]))

    def test_first_scan_walkthrough_produces_a_valid_nonexecuting_preview(self):
        guide = self.run_help(["guide"])
        example = next(line.strip() for line in guide.splitlines() if line.strip().startswith("scanrunner -i") and "--dry-run" in line)
        previous_directory = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            try:
                os.chdir(temporary)
                Path("scope.txt").write_text("127.0.0.1\n")
                with mock.patch("sys.argv", shlex.split(example)), mock.patch("sys.stdout", io.StringIO()) as output, \
                        mock.patch.object(backend.subprocess, "Popen") as process, mock.patch.object(backend.socket, "getaddrinfo") as dns:
                    backend.main()
                self.assertIn("127.0.0.1", output.getvalue())
                self.assertFalse(Path("results").exists())
                process.assert_not_called()
                dns.assert_not_called()
            finally:
                os.chdir(previous_directory)

    def test_output_paths_with_spaces_are_quoted_in_guides(self):
        guide = self.run_help(["guide", "--task", "reports", "--output", "client results"])
        self.assertIn("'client results'", guide)
        self.assertIn("'" + os.path.join("client results", "report.html") + "'", guide)

    def test_checkout_examples_use_the_current_python_and_script(self):
        with mock.patch("sys.argv", [backend.__file__, "guide"]):
            command = help_content.command_line(["inventory", "-o", "client results"])
        self.assertIn(str(Path(backend.__file__).resolve()), command)
        self.assertIn(sys.executable, command)
        self.assertIn("'client results'", command)

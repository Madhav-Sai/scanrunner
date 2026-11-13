"""Exercise the downloadable payload independently of the source checkout."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_builder", ROOT / "scripts/build_release.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ReleaseTests(unittest.TestCase):
    def test_extracted_release_runs_and_installs_complete_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = builder.build(directory)
            with zipfile.ZipFile(archive) as payload:
                names = payload.namelist()
                self.assertFalse(any("/tests/" in name or "/lab/" in name or "/.github/" in name for name in names))
                self.assertTrue(any(name.endswith("/scanrunner_lib/__init__.py") for name in names))
                payload.extractall(directory / "extracted")
            app = next((directory / "extracted").iterdir())
            environment = {**os.environ, "PYTHONPATH": "", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}
            for args in (["scanrunner.py", "--help"], ["scanrunner.py", "guide"],
                         ["scanrunner.py", "rules"], ["scanrunner.py", "help", "report"], ["install.py", "--help"]):
                completed = subprocess.run([sys.executable, "-B", *args], cwd=app, env=environment,
                                           capture_output=True, text=True, timeout=20)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            check = subprocess.run([sys.executable, "-B", "-c",
                                    "import install; assert len(install.payload_sources(install.project_script())) == len(install.COMPANIONS)"],
                                   cwd=app, env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(check.returncode, 0, check.stderr)

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installer", ROOT / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerCompatibilityTests(unittest.TestCase):
    def test_missing_companions_fail_before_installation_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "scanrunner.py"
            source.write_text("# synthetic incomplete payload\n")
            with mock.patch.object(installer, "windows_scripts_dir") as destination, \
                    mock.patch.object(installer, "add_windows_user_path") as update_path, \
                    self.assertRaises(SystemExit):
                installer.install_windows_launcher(source)
            destination.assert_not_called()
            update_path.assert_not_called()
    def test_windows_payload_copies_the_standalone_application(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(installer, "windows_scripts_dir", return_value=Path(tmp)), \
                mock.patch.object(installer, "add_windows_user_path") as update_path:
            launcher = installer.install_windows_launcher(ROOT / "scanrunner.py")
            self.assertEqual((Path(tmp) / "scanrunner.py").read_bytes(), (ROOT / "scanrunner.py").read_bytes())
            for name in installer.COMPANIONS:
                self.assertEqual((Path(tmp) / name).read_bytes(), (ROOT / name).read_bytes())
            self.assertIn("%*", launcher.read_text())
            update_path.assert_called_once_with(Path(tmp))

    def test_completion_updates_are_idempotent_and_preserve_user_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            profile.write_text("user setting\n")
            installer.replace_managed_block(profile, "completion")
            installer.replace_managed_block(profile, "completion")
            self.assertEqual(profile.read_text().count(installer.MARKER_START), 1)
            self.assertIn("user setting", profile.read_text())


if __name__ == "__main__":
    unittest.main()

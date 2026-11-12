import importlib.util
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import time
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("state_scanrunner", ROOT / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class DurableEvidenceTests(unittest.TestCase):
    def test_duplicate_claims_and_crashed_worker_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores = [sr.RunStore(tmp, {"tool": "nmap"}) for _ in range(4)]
            with ThreadPoolExecutor(max_workers=4) as pool:
                claims = list(pool.map(lambda store: store.claim("192.0.2.1"), stores))
            self.assertEqual(sum(claim is not None for claim in claims), 1)
            first = next(claim for claim in claims if claim)
            with stores[0].connect() as database:
                database.execute("UPDATE claims SET expires=0")
            recovered = stores[0].claim("192.0.2.1")
            self.assertIsNotNone(recovered)
            self.assertNotEqual(first["directory"], recovered["directory"])
            with stores[0].connect() as database:
                old = database.execute("SELECT outcome FROM jobs WHERE id=?", (first["id"],)).fetchone()[0]
            self.assertEqual(old, "Interrupted")

    def test_fingerprint_and_hashes_gate_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = sr.RunStore(tmp, {"tool": "nmap", "options": ["-sV"], "tool_version": "fixture"})
            job = store.claim("192.0.2.1")
            artifact = Path(job["directory"]) / "stdout.bin"
            artifact.write_bytes(b"synthetic evidence\x00\xff")
            store.finish_job(job, "COMPLETE", 0, True, ["nmap", "192.0.2.1"])
            self.assertTrue(store.completed("192.0.2.1"))
            changed = sr.RunStore(tmp, {"tool": "nmap", "options": ["-sV", "-p", "443"], "tool_version": "fixture"})
            self.assertFalse(changed.completed("192.0.2.1"))
            artifact.write_bytes(b"corrupt")
            self.assertFalse(store.completed("192.0.2.1"))
            artifact.unlink()
            self.assertFalse(store.completed("192.0.2.1"))

    def test_stdout_stderr_are_exact_and_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = [sys.executable, "-c", "import os; os.write(1, b'out\\x00\\xff'); os.write(2, b'err\\r\\n')"]
            code, state = sr.capture_process(command, tmp, timeout=5)
            self.assertEqual((code, state), (0, "Exited"))
            self.assertEqual((Path(tmp) / "stdout.bin").read_bytes(), b"out\x00\xff")
            self.assertEqual((Path(tmp) / "stderr.bin").read_bytes(), b"err\r\n")
        with tempfile.TemporaryDirectory() as tmp:
            start = time.monotonic()
            code, state = sr.capture_process([sys.executable, "-c", "import os,time; os.write(1,b'partial'); time.sleep(20)"], tmp, timeout=1)
            self.assertEqual(state, "TIMEOUT")
            self.assertLess(time.monotonic() - start, 8)
            self.assertEqual((Path(tmp) / "stdout.bin").read_bytes(), b"partial")

    def test_unassociated_and_partial_xml_cannot_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "nmap.txt"
            report.write_text("# Nmap done -- 1 IP address (1 host up) scanned\n")
            report.with_suffix(".xml").write_text('<nmaprun><host><status state="up"/><address addr="198.51.100.1" addrtype="ipv4"/></host><runstats><finished exit="success"/><hosts up="1" total="1"/></runstats></nmaprun>')
            guard = sr.ScopeGuard(["192.0.2.1"], None)
            with mock.patch.object(sr, "ACTIVE_SCOPE", guard):
                self.assertEqual(sr.validate_nmap_evidence(str(report), "192.0.2.1", 0), ("INCONCLUSIVE", False))
            report.with_suffix(".xml").write_text("<nmaprun>")
            self.assertEqual(sr.validate_nmap_evidence(str(report), "192.0.2.1", 0), ("INCOMPLETE", False))

    def test_legacy_cache_bytes_survive_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = sr.RunStore(tmp)
            job = store.claim("192.0.2.1")
            cache = Path(tmp) / "192.0.2.1.txt"
            cache.write_bytes(b"original legacy bytes")
            (Path(job["directory"]) / "nmap.txt").write_bytes(b"new synthetic run")
            sr.publish_report_cache(job, str(cache))
            self.assertEqual((Path(job["directory"]) / "legacy-before.txt").read_bytes(), b"original legacy bytes")
            self.assertEqual(cache.read_bytes(), b"new synthetic run")

    def test_global_and_per_subnet_ceilings_apply_across_stores(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {"global_workers": 2, "subnet_workers": 1}
            first = sr.RunStore(tmp, config)
            second = sr.RunStore(tmp, config)
            first.claim("192.0.2.1")
            with self.assertRaises(sr.CapacityBusy):
                second.claim("192.0.2.2")
            second.claim("198.51.100.1")
            with self.assertRaises(sr.CapacityBusy):
                first.claim("203.0.113.1")

    def test_cancellation_retains_partial_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            timer = threading.Timer(0.4, sr.CANCEL_EVENT.set)
            timer.start()
            try:
                code, state = sr.capture_process([sys.executable, "-c", "import os,time; os.write(1,b'partial'); time.sleep(20)"], tmp, timeout=5)
                self.assertEqual(state, "Interrupted")
                self.assertEqual((Path(tmp) / "stdout.bin").read_bytes(), b"partial")
            finally:
                timer.join()
                sr.CANCEL_EVENT.clear()

    def test_csv_formula_and_xml_entity_payloads_are_refused(self):
        for text in ("=SUM(A1)", " +cmd", "\tformula", "@lookup"):
            self.assertTrue(sr.csv_safe(text).startswith("'"))
        self.assertNotIn("sensitive-fixture", sr.redact_output_text("password=sensitive-fixture"))
        with mock.patch.object(sr, "ACTIVE_CONFIG", {"tool": "nxc", "options": ["--password", "credential-fixture"]}):
            self.assertNotIn("credential-fixture", sr.redact_output_text("server echoed credential-fixture"))
        with tempfile.TemporaryDirectory() as tmp:
            xml = Path(tmp) / "payload.xml"
            xml.write_text('<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun>&x;</nmaprun>')
            with self.assertRaises(ValueError):
                sr.read_nmap_xml(xml)
            xml.write_text('<!DOCTYPE nmaprun><nmaprun><script output="[valid banner]"/></nmaprun>')
            self.assertEqual(sr.read_nmap_xml(xml).tag, "nmaprun")
            with open(xml, "wb") as file:
                file.truncate(33 * 1024 * 1024)
            with self.assertRaises(ValueError):
                sr.read_nmap_xml(xml)
        for value in ("..", "..\\outside", "host\nother"):
            with self.assertRaises(ValueError):
                sr.sanitize_filename(value)

    def test_timeout_cleans_up_child_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "child-must-not-survive"
            child = f"import time,pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).write_text('survived')"
            parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(20)"
            _, state = sr.capture_process([sys.executable, "-c", parent], tmp, timeout=0.5)
            self.assertEqual(state, "TIMEOUT")
            time.sleep(2)
            self.assertFalse(marker.exists())

    def test_worker_crash_does_not_leave_scanner_children_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "orphan-must-not-survive"
            output = Path(tmp) / "capture"
            output.mkdir()
            child = f"import os,time,pathlib; os.write(1,b'ready'); time.sleep(2); pathlib.Path({str(marker)!r}).write_text('survived')"
            parent = (f"import importlib.util,sys; spec=importlib.util.spec_from_file_location('worker',{str(ROOT / 'scanrunner.py')!r}); "
                      f"sr=importlib.util.module_from_spec(spec); spec.loader.exec_module(sr); "
                      f"sr.capture_process([sys.executable,'-c',{child!r}],{str(output)!r},timeout=20)")
            process = subprocess.Popen([sys.executable, "-c", parent], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    artifact = output / "stdout.bin"
                    if artifact.exists() and artifact.read_bytes() == b"ready":
                        break
                    time.sleep(0.05)
                else:
                    self.fail("Controlled child never started")
                process.kill()
                process.wait(timeout=3)
                time.sleep(2.2)
                self.assertFalse(marker.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()

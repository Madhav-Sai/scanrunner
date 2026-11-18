"""Tests for the --pingme / --pingme-only host-discovery integration.

A fake pingme.py (run through the current Python) writes PingMe 3.x JSON
result files, so these tests never send packets.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scanrunner.py"
spec = importlib.util.spec_from_file_location("scanrunner_pingme", SCRIPT)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

# Mimics PingMe 3.x: targets are the arguments before the first option, each
# either a file or a CIDR. Like the real PingMe, a file may only hold single
# hosts (a CIDR or a 10.0.0.1-5 range line there is "unresolvable"). Live IPs
# come from FAKE_PINGME_UP; every other address is "dead".
FAKE_PINGME = r'''
import ipaddress, json, os, sys
argv = sys.argv[1:]
def opt(name):
    return argv[len(argv) - 1 - argv[::-1].index(name) + 1] if name in argv else None
with open(os.environ["FAKE_PINGME_ARGV_LOG"], "a") as f:   # one line per PingMe run
    f.write(json.dumps(argv) + "\n")
up = set(filter(None, os.environ.get("FAKE_PINGME_UP", "").split(",")))
positional = []
for arg in argv:
    if arg.startswith("-"):
        break
    positional.append(arg)
addresses = []
for target in positional:
    if os.path.isfile(target):
        for line in open(target):
            line = line.strip()
            if line and "/" not in line and "-" not in line:
                addresses.append(line)
    else:
        addresses += [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
if not addresses:
    print("No valid IPs or resolvable hostnames supplied.")
    sys.exit(1)
def row(ip, alive):
    return {"ip": ip, "alive": alive, "status": "REACHABLE" if alive else "NO RESPONSE",
            "hostname": "", "tcp_open": []}
alive = [row(a, True) for a in addresses if a in up]
dead = [row(a, False) for a in addresses if a not in up]
for name, rows in (("--alive-out", alive), ("--dead-out", dead), ("--error-out", [])):
    with open(opt(name), "w") as f:
        json.dump(rows, f)
print("Scan complete: total=%d reachable=%d" % (len(addresses), len(alive)))
sys.exit(0 if not dead else 1)
'''


class FilterLiveTargetsTests(unittest.TestCase):
    def test_ips_cidrs_and_hostnames(self):
        results = {"alive": [{"ip": "10.0.0.1"}, {"ip": "10.9.0.2"}, {"ip": "10.0.0.7", "hostname": "web01"}],
                   "dead": [{"ip": "10.0.0.2"}], "errors": [{"ip": "10.0.0.3"}]}
        live, dead = sr.filter_live_targets(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.9.0.0/29", "10.8.0.0/30", "web01"], results)
        # The CIDR becomes its live hosts; probe errors are kept, not dropped.
        self.assertEqual(live, ["10.0.0.1", "10.0.0.3", "10.9.0.2", "web01"])
        self.assertEqual(dead, ["10.0.0.2", "10.8.0.0/30"])

    def test_last_octet_range_becomes_its_live_hosts(self):
        live, dead = sr.filter_live_targets(
            ["10.0.0.5-9", "10.0.1.1-3"], {"alive": [{"ip": "10.0.0.7"}, {"ip": "10.0.0.10"}]})
        self.assertEqual((live, dead), (["10.0.0.7"], ["10.0.1.1-3"]))

    def test_hostname_matched_by_resolved_address(self):
        with mock.patch.object(sr, "resolve_scan_target", return_value=("10.0.0.5", "")):
            live, dead = sr.filter_live_targets(["db.local"], {"alive": [{"ip": "10.0.0.5"}]})
        self.assertEqual((live, dead), (["db.local"], []))


class FindPingmeTests(unittest.TestCase):
    def test_explicit_script_and_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "pingme.py"
            script.write_text("")
            self.assertEqual(sr.find_pingme(str(script)), [sys.executable, str(script)])
            self.assertEqual(sr.find_pingme(tmp), [sys.executable, str(script)])
            self.assertIsNone(sr.find_pingme(str(Path(tmp) / "missing.py")))


class PingmeArgumentTests(unittest.TestCase):
    def parse(self, *argv):
        with mock.patch.object(sys, "argv", ["scanrunner", *argv]):
            return sr.parse_args()

    def test_pingme_flags_do_not_leak_into_nmap(self):
        args = self.parse("-i", "10.0.0.0/24", "--pingme", "--pingme-args", "--tcp-ports 22,445 --fast", "-A")
        self.assertTrue(args.pingme)
        self.assertEqual(args.pingme_extra, ["--tcp-ports", "22,445", "--fast"])
        self.assertEqual(args.nmap_extra, ["-A"])

    def test_single_option_pingme_args(self):
        self.assertEqual(self.parse("-i", "10.0.0.1", "--pingme", "--pingme-args", "--fast").pingme_extra,
                         ["--fast"])

    def test_pingme_only_implies_pingme(self):
        self.assertTrue(self.parse("-i", "10.0.0.1", "--pingme-only").pingme)

    def test_never_ending_pingme_modes_are_refused(self):
        for extra in ("--watch 60", "--serve 8080", "--ping-tool ask", "--wol AA:BB:CC:DD:EE:FF"):
            with self.subTest(extra=extra), mock.patch("sys.stderr"), self.assertRaises(SystemExit):
                self.parse("-i", "10.0.0.1", "--pingme", "--pingme-args", extra)

    def test_pingme_path_requires_pingme(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            self.parse("-i", "10.0.0.1", "--pingme-path", "x.py")


class PingmeOnlyEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.pingme = self.root / "pingme.py"
        self.pingme.write_text(FAKE_PINGME)
        self.argv_log = self.root / "pingme-argv.json"
        self.out = self.root / "out"
        self.env = dict(os.environ, FAKE_PINGME_ARGV_LOG=str(self.argv_log),
                        FAKE_PINGME_UP="10.0.0.1,10.9.0.2")

    def tearDown(self):
        self.tmp.cleanup()

    def test_sweep_writes_live_list_and_passes_extra_args(self):
        targets = self.root / "targets.txt"
        targets.write_text("10.0.0.1\n10.0.0.2\n10.9.0.0/30\n")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-f", str(targets), "--pingme-only",
             "--pingme-path", str(self.pingme), "--pingme-args", "--tcp-ports 22",
             "-o", str(self.out), "--no-color"],
            text=True, encoding="utf-8", errors="replace", capture_output=True, stdin=subprocess.DEVNULL, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        live = (self.out / "pingme" / "live.txt").read_text().split()
        self.assertEqual(live, ["10.0.0.1", "10.9.0.2"])
        self.assertIn("2 live host(s) to scan, 1 target(s) with no response", result.stdout)
        argv = json.loads(self.argv_log.read_text().splitlines()[-1])
        self.assertIn("--tcp-ports", argv)
        self.assertEqual(argv[argv.index("--out-format") + 1], "json")

    def test_cidr_only_and_range_targets(self):
        # Real PingMe rejects CIDRs and ranges inside a targets file.
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-i", "10.9.0.0/30", "--pingme-only",
             "--pingme-path", str(self.pingme), "-o", str(self.out), "--no-color"],
            text=True, encoding="utf-8", errors="replace", capture_output=True,
            stdin=subprocess.DEVNULL, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.out / "pingme" / "live.txt").read_text().split(), ["10.9.0.2"])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-i", "10.0.0.1-3", "--pingme-only",
             "--pingme-path", str(self.pingme), "-o", str(self.out), "--no-color"],
            text=True, encoding="utf-8", errors="replace", capture_output=True,
            stdin=subprocess.DEVNULL, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.out / "pingme" / "live.txt").read_text().split(), ["10.0.0.1"])

    def test_missing_pingme_is_a_clear_error(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "-i", "10.0.0.1", "--pingme-only",
             "--pingme-path", str(self.root / "nope.py"), "-o", str(self.out), "--no-color"],
            text=True, encoding="utf-8", errors="replace", capture_output=True, stdin=subprocess.DEVNULL, env=self.env, timeout=60)
        self.assertEqual(result.returncode, 1)
        self.assertIn("PingMe not found", result.stdout)


sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_workflow as wf  # noqa: E402  (reuses the fake nmap harness)


class PingmeScanEndToEndTests(wf.EndToEndBase):
    def setup_pingme(self, *up):
        self.pingme = self.root / "pingme.py"
        self.pingme.write_text(FAKE_PINGME)
        self.pingme_log = self.root / "pingme-argv.jsonl"
        self.env.update(FAKE_PINGME_ARGV_LOG=str(self.pingme_log), FAKE_PINGME_UP=",".join(up))
        self.scenarios(**{t: {"kind": "up", "ports": [[22, "tcp", "ssh", ""]]} for t in up})

    def test_only_live_hosts_are_scanned_and_dead_ones_are_logged(self):
        self.setup_pingme("10.0.0.1", "10.9.0.2")
        result = self.run_scan("-f", self.targets("10.0.0.1", "10.0.0.2", "10.9.0.0/30"),
                               "--pingme", "--pingme-path", str(self.pingme), "--yes", "-A")
        self.assertEqual(result.returncode, 0, self.last_output)
        scanned = [call[-1] for call in self.nmap_calls()]
        self.assertEqual(sorted(scanned), ["10.0.0.1", "10.9.0.2"])
        self.assertTrue(all("-A" in call for call in self.nmap_calls()))
        self.assertEqual(self.logged("completed.txt"), {"10.0.0.1", "10.9.0.2"})
        self.assertEqual(self.logged("not-pingip.txt"), {"10.0.0.2"})
        self.assertIn("Reconciliation OK", self.last_output)
        self.assertIn("PingMe already confirmed it is up", self.last_output)
        # Scanrunner's default host timeout is added when none was given.
        self.assertTrue(all("--host-timeout" in call for call in self.nmap_calls()))

    def test_own_host_timeout_is_kept(self):
        self.setup_pingme("10.0.0.1")
        result = self.run_scan("-i", "10.0.0.1", "--yes", "--skip-ping", "--host-timeout", "5m")
        self.assertEqual(result.returncode, 0, self.last_output)
        call = self.nmap_calls()[0]
        self.assertEqual(call.count("--host-timeout"), 1)
        self.assertEqual(call[call.index("--host-timeout") + 1], "5m")

    def test_parallel_scans_only_live_hosts(self):
        live = [f"10.0.0.{i}" for i in (1, 3, 5)]
        self.setup_pingme(*live)
        result = self.run_scan("-f", self.targets(*[f"10.0.0.{i}" for i in range(1, 7)]),
                               "--pingme", "--pingme-path", str(self.pingme),
                               "--yes", "--parallel", "3")
        self.assertEqual(result.returncode, 0, self.last_output)
        self.assertEqual(sorted(call[-1] for call in self.nmap_calls()), live)
        self.assertEqual(self.logged("completed.txt"), set(live))
        self.assertEqual(self.logged("not-pingip.txt"), {"10.0.0.2", "10.0.0.4", "10.0.0.6"})
        self.assertIn("Reconciliation OK", self.last_output)

    def test_tabs_get_live_hosts_and_do_not_rerun_pingme(self):
        live = [f"10.9.0.{i}" for i in (1, 2, 5, 6)]
        self.setup_pingme(*live)
        self.env["SCANRUNNER_BACKGROUND_TABS"] = "1"
        result = self.run_scan("-i", "10.9.0.0/29", "--pingme", "--pingme-path", str(self.pingme),
                               "--tabs", "2")
        self.assertEqual(result.returncode, 0, self.last_output)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and len(self.logged("completed.txt")) < len(live):
            time.sleep(0.2)
        self.assertEqual(self.logged("completed.txt"), set(live))
        self.assertEqual(sorted(call[-1] for call in self.nmap_calls()), live)
        self.assertEqual(len(self.pingme_log.read_text().splitlines()), 1)   # sweep ran once
        for index in (1, 2):
            tab_targets = (self.out / "tabs" / f"tab_{index}_targets.txt").read_text().split()
            self.assertEqual(len(tab_targets), 2)
            self.assertTrue(set(tab_targets) <= set(live))


if __name__ == "__main__":
    unittest.main()

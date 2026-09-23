"""Tests for report parsing, outcome tracking, and end-to-end scan workflows.

End-to-end tests put fake `nmap`, `ping` and `nxc` executables first on PATH,
so the full CLI runs without touching the network. The fake Nmap writes
normal and XML output in the same format as Nmap 7.99. One test at the end
scans a local listener on 127.0.0.1 with the real Nmap when it is installed.
"""
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scanrunner.py"
spec = importlib.util.spec_from_file_location("scanrunner_workflow", SCRIPT)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


def write(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def log_line(path, target, when):
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{when.strftime(sr.LOG_TIME_FORMAT)} | {target}\n")


# Report fixtures in real Nmap 7.99 normal-output format.
COMPLETE_REPORT = textwrap.dedent("""\
    # Nmap 7.99 scan initiated Wed Sep 23 17:59:26 2026 as: nmap -sV -oN r.txt 10.0.0.1
    Nmap scan report for 10.0.0.1
    Host is up (0.00010s latency).
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 9.6p1 Debian 4 (protocol 2.0)
    80/tcp open  http    nginx 1.24.0
    443/tcp closed https

    # Nmap done at Wed Sep 23 17:59:29 2026 -- 1 IP address (1 host up) scanned in 3.09 seconds
    """)
DOWN_REPORT = textwrap.dedent("""\
    # Nmap 7.99 scan initiated Wed Sep 23 17:59:26 2026 as: nmap -sT -p 80 10.255.255.1
    # Nmap done at Wed Sep 23 17:59:29 2026 -- 1 IP address (0 hosts up) scanned in 3.09 seconds
    """)
TIMEOUT_REPORT = textwrap.dedent("""\
    # Nmap 7.99 scan initiated Wed Sep 23 17:59:48 2026 as: nmap -sT -Pn -p- --host-timeout 3s 10.255.255.1
    Nmap scan report for 10.255.255.1
    Host is up.
    Skipping host 10.255.255.1 due to host timeout
    # Nmap done at Wed Sep 23 17:59:51 2026 -- 1 IP address (1 host up) scanned in 3.52 seconds
    """)
UNRESOLVED_REPORT = textwrap.dedent("""\
    # Nmap 7.99 scan initiated Wed Sep 23 17:59:48 2026 as: nmap -sT -p 22 no-such-host.invalid
    # Nmap done at Wed Sep 23 17:59:48 2026 -- 0 IP addresses (0 hosts up) scanned in 0.52 seconds
    """)
INCOMPLETE_REPORT = textwrap.dedent("""\
    # Nmap 7.99 scan initiated Wed Sep 23 17:59:26 2026 as: nmap -sV 10.0.0.1
    Nmap scan report for 10.0.0.1
    Host is up (0.00010s latency).
    """)
CIDR_REPORT = textwrap.dedent("""\
    # Nmap 7.99 scan initiated Wed Sep 23 17:59:26 2026 as: nmap 10.9.0.0/30
    Nmap scan report for gw.lab (10.9.0.1)
    Host is up (0.00010s latency).
    PORT   STATE SERVICE
    22/tcp open  ssh
    Nmap scan report for 10.9.0.2
    Host is up (0.00010s latency).
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http

    # Nmap done at Wed Sep 23 17:59:29 2026 -- 4 IP addresses (2 hosts up) scanned in 3.09 seconds
    """)
CIDR_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap 10.9.0.0/30">
    <host><status state="up" reason="syn-ack"/>
    <address addr="10.9.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="gw.lab" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="protocol 2.0"/></port>
    <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
    </ports></host>
    <host><status state="up" reason="syn-ack"/>
    <address addr="10.9.0.2" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <hostnames/>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
    <port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp"/></port>
    </ports></host>
    <runstats><finished/><hosts up="2" down="2" total="4"/></runstats>
    </nmaprun>
    """)


# ═══════════════════════════════════════════════════════════════════════════════
#  Argument handling
# ═══════════════════════════════════════════════════════════════════════════════

def run_cli(*args, env=None, cwd=None, timeout=120):
    return subprocess.run([sys.executable, str(SCRIPT), *args], text=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, cwd=cwd, timeout=timeout)


def parse(*argv):
    with mock.patch.object(sys, "argv", ["scanrunner", *argv]):
        return sr.parse_args()


class ArgumentConflictTests(unittest.TestCase):
    def test_nmap_n_flag_passes_through_anywhere(self):
        for argv in (["-f", "t.txt", "-n", "-sV"], ["-f", "t.txt", "-sV", "-n"],
                     ["-i", "10.0.0.1", "-n"]):
            with self.subTest(argv=argv):
                args = parse(*argv)
                self.assertIsNone(args.nxc)
                self.assertIn("-n", args.nmap_extra)

    def test_abbreviated_scanrunner_options_are_not_guessed(self):
        args = parse("-i", "10.0.0.1", "--res")
        self.assertFalse(args.resume)
        self.assertIn("--res", args.nmap_extra)

    def test_nmap_output_flags_are_refused_with_explanation(self):
        for flag in ("-oA", "-oN", "-oX", "-oG", "-oS"):
            with self.subTest(flag=flag):
                result = run_cli("-f", "t.txt", flag, "scan", "-sV")
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"{flag} is not needed", result.stderr)
                self.assertIn("-o DIR", result.stderr)

    def test_ok_flag_is_not_mistaken_for_output_flag(self):
        args = parse("-i", "10.0.0.1", "-ok")
        self.assertTrue(args.skip_no_ping)
        self.assertEqual(args.output, "results")

    def test_iL_is_translated_to_file(self):
        self.assertEqual(parse("-iL", "hosts.txt", "-sV").file, "hosts.txt")
        self.assertEqual(parse("-iLhosts.txt").file, "hosts.txt")

    def test_iL_together_with_f_is_rejected(self):
        result = run_cli("-f", "a.txt", "-iL", "b.txt")
        self.assertEqual(result.returncode, 2)

    def test_iR_is_refused(self):
        result = run_cli("-iR", "100")
        self.assertEqual(result.returncode, 2)
        self.assertIn("-iR", result.stderr)

    def test_nxc_module_options_pass_through_and_output_still_works(self):
        args = parse("-f", "t.txt", "-nxc", "smb", "-M", "spider_plus",
                     "-o", "DOWNLOAD_FLAG=False", "MAX_FILE_SIZE=100", "-o", "outdir")
        self.assertEqual(args.output, "outdir")
        self.assertEqual(args.nmap_extra[-3:], ["-o", "DOWNLOAD_FLAG=False", "MAX_FILE_SIZE=100"])
        self.assertIn("spider_plus", args.nmap_extra)

    def test_nmap_mode_does_not_treat_key_value_output_dir_as_module_option(self):
        args = parse("-i", "10.0.0.1", "-o", "run=1")
        self.assertEqual(args.output, "run=1")


# ═══════════════════════════════════════════════════════════════════════════════
#  Scope
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeTests(unittest.TestCase):
    scope = ["10.0.0.0/24", "192.168.1.10", "app.corp.local", "2001:db8::/64"]

    def check(self, target, resolver=None):
        return sr.target_in_scope(target, self.scope, resolver=resolver or self.fail_resolver)

    @staticmethod
    def fail_resolver(target, timeout=5):
        return target, "failed"

    def test_empty_scope_allows_everything(self):
        self.assertTrue(sr.target_in_scope("8.8.8.8", []))

    def test_ip_and_cidr_membership(self):
        self.assertTrue(self.check("10.0.0.7"))
        self.assertTrue(self.check("192.168.1.10"))
        self.assertTrue(self.check("10.0.0.0/25"))
        self.assertFalse(self.check("10.0.1.7"))
        self.assertFalse(self.check("10.0.0.0/23"))
        self.assertFalse(self.check("192.168.1.11"))

    def test_mixed_ip_versions_do_not_crash(self):
        self.assertTrue(self.check("2001:db8::5"))
        self.assertFalse(self.check("2001:db9::5"))
        self.assertFalse(self.check("::ffff:10.0.0.1/128"))

    def test_last_octet_range_must_be_fully_inside(self):
        self.assertTrue(self.check("10.0.0.1-254"))
        self.assertFalse(sr.target_in_scope("192.168.1.9-10", self.scope))
        self.assertFalse(self.check("10.0.0.20-10"))   # reversed range is not valid

    def test_hostname_listed_by_name(self):
        self.assertTrue(self.check("APP.corp.local"))

    def test_hostname_resolving_into_scope(self):
        resolver = mock.Mock(return_value=("10.0.0.42", "resolved"))
        self.assertTrue(self.check("db.corp.local", resolver=resolver))
        resolver.assert_called_once()

    def test_hostname_resolving_outside_scope_or_unresolvable(self):
        self.assertFalse(self.check("evil.example", resolver=lambda t, timeout=5: ("8.8.8.8", "")))
        self.assertFalse(self.check("nothing.invalid"))

    def test_unparseable_target_is_refused(self):
        self.assertFalse(self.check("10.0.0-5.1"))


# ═══════════════════════════════════════════════════════════════════════════════
#  Report parsing and status
# ═══════════════════════════════════════════════════════════════════════════════

class ReportStatusTests(unittest.TestCase):
    def status_of(self, content):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.txt")
            write(path, content)
            return sr.get_file_status(path)

    def test_statuses(self):
        self.assertEqual(self.status_of(COMPLETE_REPORT), "COMPLETE")
        self.assertEqual(self.status_of(CIDR_REPORT), "COMPLETE")
        self.assertEqual(self.status_of(DOWN_REPORT), "DOWN")
        self.assertEqual(self.status_of(TIMEOUT_REPORT), "TIMEOUT")
        self.assertEqual(self.status_of(UNRESOLVED_REPORT), "UNRESOLVED")
        self.assertEqual(self.status_of(INCOMPLETE_REPORT), "INCOMPLETE")
        self.assertEqual(sr.get_file_status("/nonexistent/report.txt"), "UNKNOWN")

    def test_every_problem_status_has_an_explanation(self):
        for status in ("TIMEOUT", "UNRESOLVED", "INCOMPLETE", "UNKNOWN"):
            self.assertIn(status, sr.REPORT_STATUS_PROBLEMS)


class ParseHostsTests(unittest.TestCase):
    def test_xml_is_preferred_and_split_per_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "10.9.0.0_30.txt")
            write(report, CIDR_REPORT)
            write(os.path.join(tmp, "10.9.0.0_30.xml"), CIDR_XML)
            hosts = sr.parse_nmap_hosts(report)
        self.assertEqual([h["address"] for h in hosts], ["10.9.0.1", "10.9.0.2"])
        self.assertEqual(hosts[0]["hostname"], "gw.lab")
        self.assertEqual(hosts[0]["ports"], [
            {"port": "22/tcp", "service": "ssh", "version": "OpenSSH 9.6p1 protocol 2.0"}])
        # closed and open|filtered ports are not "open"
        self.assertEqual([p["port"] for p in hosts[1]["ports"]], ["22/tcp", "80/tcp"])
        self.assertEqual(hosts[1]["ports"][1]["version"], "nginx")

    def test_truncated_xml_falls_back_to_text_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "10.9.0.0_30.txt")
            write(report, CIDR_REPORT)
            write(os.path.join(tmp, "10.9.0.0_30.xml"), CIDR_XML[:200])
            hosts = sr.parse_nmap_hosts(report)
        self.assertEqual([h["address"] for h in hosts], ["10.9.0.1", "10.9.0.2"])
        self.assertEqual(hosts[0]["hostname"], "gw.lab")
        self.assertEqual(sr.port_label(hosts[1]["ports"][1]), "80/tcp/http")

    def test_text_only_report_keeps_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "10.0.0.1.txt")
            write(report, COMPLETE_REPORT)
            hosts = sr.parse_nmap_hosts(report)
            self.assertEqual(sr.parse_open_ports(report), ["22/tcp/ssh", "80/tcp/http"])
            self.assertEqual(sr.hosts_with_open_ports(report),
                             [("10.0.0.1", ["22/tcp/ssh", "80/tcp/http"])])
        self.assertEqual(hosts[0]["ports"][0]["version"], "OpenSSH 9.6p1 Debian 4 (protocol 2.0)")

    def test_cidr_ports_are_no_longer_merged_into_one_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "cidr.txt")
            write(report, CIDR_REPORT)
            self.assertEqual(sr.hosts_with_open_ports(report), [
                ("10.9.0.1", ["22/tcp/ssh"]), ("10.9.0.2", ["22/tcp/ssh", "80/tcp/http"])])

    def test_missing_report_and_non_nmap_xml(self):
        self.assertEqual(sr.parse_nmap_hosts("/nonexistent/x.txt"), [])
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "a.txt")
            write(report, COMPLETE_REPORT)
            write(os.path.join(tmp, "a.xml"), "<other/>")
            self.assertEqual(len(sr.parse_nmap_hosts(report)[0]["ports"]), 2)


class InventoryTests(unittest.TestCase):
    def test_cidr_inventory_has_one_row_per_host_port_and_merges_legacy_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, "10.9.0.0_30.txt"), CIDR_REPORT)
            write(os.path.join(tmp, "10.9.0.0_30.xml"), CIDR_XML)
            # A legacy row from v1.2 (no host/hostname/version) for another target
            write(os.path.join(tmp, "open-ports-inventory.json"), json.dumps([
                {"target": "10.1.1.1", "owner": "", "environment": "", "port_service": "22/tcp/ssh"}]))
            sr.write_inventory(tmp, ["10.9.0.0/30"], {"10.9.0.0/30": {"owner": "net<ops>"}}, True)
            with open(os.path.join(tmp, "open-ports-inventory.json"), encoding="utf-8") as f:
                rows = json.load(f)
            with open(os.path.join(tmp, "open-ports-inventory.csv"), encoding="utf-8") as f:
                csv_header = f.readline().strip()
            with open(os.path.join(tmp, "open-ports-report.html"), encoding="utf-8") as f:
                page = f.read()
        self.assertEqual(csv_header, ",".join(sr.INVENTORY_FIELDS))
        self.assertEqual(rows[0]["target"], "10.1.1.1")
        self.assertEqual(rows[0]["host"], "")
        new = [(r["host"], r["port_service"]) for r in rows[1:]]
        self.assertEqual(new, [("10.9.0.1", "22/tcp/ssh"), ("10.9.0.2", "22/tcp/ssh"),
                               ("10.9.0.2", "80/tcp/http")])
        self.assertTrue(all(r["owner"] == "net<ops>" for r in rows[1:]))
        self.assertIn("net&lt;ops&gt;", page)
        self.assertNotIn("net<ops>", page)
        self.assertIn("By service", page)
        self.assertIn("<td>22/tcp/ssh</td><td>3</td>", page)   # 10.1.1.1, 10.9.0.1, 10.9.0.2

    def test_rescanning_a_target_replaces_its_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, "10.0.0.1.txt"), COMPLETE_REPORT)
            sr.write_inventory(tmp, ["10.0.0.1"], {}, False)
            write(os.path.join(tmp, "10.0.0.1.txt"), DOWN_REPORT)
            sr.write_inventory(tmp, ["10.0.0.1"], {}, False)
            with open(os.path.join(tmp, "open-ports-inventory.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f), [])


# ═══════════════════════════════════════════════════════════════════════════════
#  Outcomes, summary, resume
# ═══════════════════════════════════════════════════════════════════════════════

class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.now = datetime.now().replace(microsecond=0)
        self.files = {name: os.path.join(self.dir, filename) for name, filename in sr.OUTCOME_LOGS}

    def tearDown(self):
        self.tmp.cleanup()

    def summary(self, ips, since=None):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            sr.print_summary(ips, self.files["completed"], self.files["skipped"],
                             os.path.join(self.dir, "rescanned.txt"), self.files["no_ping"],
                             self.files["failed"], self.dir, since=since)
        return sr.strip_ansi(out.getvalue())

    def test_latest_outcome_wins(self):
        log_line(self.files["failed"], "10.0.0.1", self.now - timedelta(days=7))
        log_line(self.files["completed"], "10.0.0.1", self.now)
        log_line(self.files["completed"], "10.0.0.2", self.now - timedelta(days=1))
        log_line(self.files["failed"], "10.0.0.2", self.now)
        self.assertEqual(sr.latest_outcomes(self.dir), {"10.0.0.1": "completed", "10.0.0.2": "failed"})

    def test_same_second_tie_prefers_completed(self):
        log_line(self.files["failed"], "10.0.0.1", self.now)
        log_line(self.files["completed"], "10.0.0.1", self.now)
        self.assertEqual(sr.latest_outcomes(self.dir), {"10.0.0.1": "completed"})

    def test_since_filter_and_unparseable_timestamps(self):
        log_line(self.files["completed"], "old", self.now - timedelta(hours=1))
        log_line(self.files["completed"], "new", self.now)
        with open(self.files["completed"], "a", encoding="utf-8") as f:
            f.write("garbage | legacy\n\n|\n")
        self.assertEqual(set(sr.latest_outcomes(self.dir, since=self.now)), {"new"})
        self.assertEqual(set(sr.latest_outcomes(self.dir)), {"old", "new", "legacy"})
        self.assertEqual(sr.read_logged_ips(self.files["completed"], since=self.now), {"new"})

    def test_summary_counts_each_target_once(self):
        log_line(self.files["failed"], "10.0.0.1", self.now - timedelta(days=7))
        log_line(self.files["completed"], "10.0.0.1", self.now)
        log_line(self.files["completed"], "10.9.9.9", self.now)   # not in this list
        text = self.summary(["10.0.0.1"])
        self.assertIn("Completed : 1", text)
        self.assertIn("Failed    : 0", text)
        self.assertIn("Reconciliation OK", text)

    def test_outcome_from_an_earlier_run_does_not_hide_an_unreached_target(self):
        log_line(self.files["completed"], "10.0.0.2", self.now - timedelta(days=1))
        log_line(self.files["completed"], "10.0.0.1", self.now)
        text = self.summary(["10.0.0.1", "10.0.0.2"], since=self.now)
        self.assertIn("1 target(s) have NO recorded outcome", text)
        with open(os.path.join(self.dir, "unaccounted.txt"), encoding="utf-8") as f:
            self.assertEqual(f.read().split(), ["10.0.0.2"])

    def test_summary_lists_cidr_hosts_individually(self):
        write(os.path.join(self.dir, "10.9.0.0_30.txt"), CIDR_REPORT)
        log_line(self.files["completed"], "10.9.0.0/30", self.now)
        text = self.summary(["10.9.0.0/30"])
        self.assertIn("10.9.0.1 (10.9.0.0/30)", text)
        self.assertIn("10.9.0.2 (10.9.0.0/30)", text)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.completed = os.path.join(self.dir, "completed.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, target, content, age_seconds=0):
        path = os.path.join(self.dir, f"{sr.sanitize_filename(target)}.txt")
        write(path, content)
        stamp = datetime.now().timestamp() - age_seconds
        os.utime(path, (stamp, stamp))

    def test_rules(self):
        now = datetime.now().replace(microsecond=0)
        self.report("complete", COMPLETE_REPORT)                    # complete report → done
        self.report("rescan-interrupted", INCOMPLETE_REPORT)          # rewritten after its log → not done
        log_line(self.completed, "rescan-interrupted", now - timedelta(hours=2))
        self.report("marked", INCOMPLETE_REPORT, age_seconds=7200)    # marked done afterwards → done
        log_line(self.completed, "marked", now)
        self.report("down", DOWN_REPORT, age_seconds=7200)            # down is never done
        log_line(self.completed, "down", now)
        log_line(self.completed, "no-report", now)                    # logged, no report file → done
        self.report("never-logged", INCOMPLETE_REPORT)                # nothing → not done
        ips = ["complete", "rescan-interrupted", "marked", "down", "no-report", "never-logged"]
        self.assertEqual(sr.previously_completed(ips, self.dir, self.completed),
                         {"complete", "marked", "no-report"})

    def test_only_this_target_list_is_considered(self):
        log_line(self.completed, "other-list-host", datetime.now())
        self.assertEqual(sr.previously_completed(["mine"], self.dir, self.completed), set())


class TabDashboardTests(unittest.TestCase):
    def test_outcomes_from_before_launch_are_not_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime.now().replace(microsecond=0)
            log_line(os.path.join(tmp, "completed.txt"), "10.0.0.1", now - timedelta(days=1))
            log_line(os.path.join(tmp, "completed.txt"), "10.0.0.2", now)
            out = io.StringIO()
            out.isatty = lambda: True
            with mock.patch("sys.stdout", out), \
                 mock.patch.object(sr.time, "sleep", side_effect=KeyboardInterrupt):
                sr._watch_tab_progress(tmp, ["10.0.0.1", "10.0.0.2"], poll_interval=0, since=now)
            text = sr.strip_ansi(out.getvalue())
        self.assertIn("(1/2 accounted for)", text)
        self.assertIn("Stopped watching", text)


# ═══════════════════════════════════════════════════════════════════════════════
#  NXC
# ═══════════════════════════════════════════════════════════════════════════════

NXC_OUTPUT = textwrap.dedent("""\
    [*] First time use detected
    SMB         10.0.0.5        445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
    SMB         10.0.0.9        445    WS01             [*] Windows 10 Build 19041 x64 (name:WS01) (domain:corp.local) (signing:False) (SMBv1:True)
    SMB         10.0.0.9        445    WS01             [+] corp.local\\:
    Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
    """)


class NxcTests(unittest.TestCase):
    def test_cidr_target_gets_no_blank_row(self):
        rows = sr.parse_nxc_output(NXC_OUTPUT, ["10.0.0.0/24"], resolver=mock.Mock())
        self.assertEqual([r["target"] for r in rows], ["10.0.0.5", "10.0.0.9"])

    def test_range_target_gets_no_blank_row(self):
        rows = sr.parse_nxc_output(NXC_OUTPUT, ["10.0.0.1-20"], resolver=mock.Mock())
        self.assertEqual([r["target"] for r in rows], ["10.0.0.5", "10.0.0.9"])

    def test_hostname_target_is_merged_into_its_ip_row(self):
        resolver = mock.Mock(return_value=("10.0.0.5", "resolved"))
        rows = sr.parse_nxc_output(NXC_OUTPUT, ["dc01.corp.local", "10.0.0.9"], resolver=resolver)
        self.assertEqual([r["target"] for r in rows], ["10.0.0.9", "10.0.0.5"])
        self.assertEqual(rows[1]["hostname"], "DC01")

    def test_silent_hosts_keep_a_blank_row(self):
        resolver = mock.Mock(return_value=("gone.corp.local", "failed"))
        rows = sr.parse_nxc_output(NXC_OUTPUT, ["10.0.0.77", "gone.corp.local"], resolver=resolver)
        targets = {r["target"]: r for r in rows}
        self.assertEqual(targets["10.0.0.77"]["port"], "")
        self.assertIn("gone.corp.local", targets)

    def test_ip_targets_never_trigger_dns(self):
        resolver = mock.Mock()
        sr.parse_nxc_output(NXC_OUTPUT, ["10.0.0.5", "10.0.0.77"], resolver=resolver)
        resolver.assert_not_called()

    def test_non_protocol_lines_are_ignored(self):
        rows = sr.parse_nxc_output("Running nxc against 3 targets 100 0:00:00 x\n", [], resolver=mock.Mock())
        self.assertEqual(rows, [])

    def test_null_auth_and_fields(self):
        rows = sr.parse_nxc_output(NXC_OUTPUT, [], null_auth_attempt=True, resolver=mock.Mock())
        ws = [r for r in rows if r["target"] == "10.0.0.9"][0]
        self.assertEqual((ws["smbv1"], ws["smb_signing"], ws["null_auth"], ws["os"]),
                         ("True", "False", "Success", "Windows 10 Build 19041 x64"))

    def test_credentials_in_equals_form_suppress_null_auth_injection(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(sr.subprocess, "Popen") as popen, \
             mock.patch("builtins.print"):
            popen.return_value.stdout = iter([])
            popen.return_value.returncode = 0
            sr.run_nxc("nxc", "smb", "10.0.0.5", ["10.0.0.5"], ["--username=alice", "--password=x"],
                       ["null-auth"], tmp)
            command = popen.call_args[0][0]
        self.assertNotIn("-u", command)
        self.assertEqual(sr.redact_command(command)[-1], "--password=***")


class FatalErrorTests(unittest.TestCase):
    def test_markers(self):
        self.assertIn("root", sr.nmap_fatal_reason(
            ["Starting Nmap", "You requested a scan type which requires root privileges.", "QUITTING!"]))
        self.assertIn("--bogus", sr.nmap_fatal_reason(
            ["nmap: unrecognized option '--bogus'", "See the output of nmap -h for a summary of options."]))
        self.assertIsNone(sr.nmap_fatal_reason(["Nmap done: 1 IP address (1 host up)"]))


class DisplayTests(unittest.TestCase):
    def test_host_label(self):
        self.assertEqual(sr.host_label("10.0.0.1", "10.0.0.1"), "10.0.0.1")
        self.assertEqual(sr.host_label("10.0.0.0/24", "10.0.0.5"), "10.0.0.5 (10.0.0.0/24)")
        self.assertEqual(sr.host_label("10.0.0.1-9", "10.0.0.5"), "10.0.0.5 (10.0.0.1-9)")
        self.assertEqual(sr.host_label("localhost", "127.0.0.1"), "localhost (127.0.0.1)")

    def test_no_escape_codes_when_colors_are_disabled(self):
        out = io.StringIO()
        with mock.patch.object(sr, "COLORS_ENABLED", False), mock.patch("sys.stdout", out):
            sr.progress_bar(3, 4)
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("75.0%", out.getvalue())

    def test_live_ticker_is_silent_when_output_is_not_a_terminal(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            sr._rticker("  [00:01]  scanning 10.0.0.1")
            sr._rclear()
        self.assertEqual(out.getvalue(), "")


class DiffTests(unittest.TestCase):
    def test_diff_open_ports(self):
        old = {"10.0.0.1": {"22/tcp": "ssh", "80/tcp": "http"}, "10.0.0.2": {"22/tcp": "ssh"}}
        new = {"10.0.0.1": {"22/tcp": "ssh", "443/tcp": "https"}, "10.0.0.3": {}}
        self.assertEqual(sr.diff_open_ports(old, new), {
            "opened": {"10.0.0.1": ["443/tcp/https"]},
            "closed": {"10.0.0.1": ["80/tcp/http"]},
            "new_hosts": ["10.0.0.3"],
            "missing_hosts": ["10.0.0.2"],
        })

    def test_identical_runs_have_no_differences(self):
        same = {"10.0.0.1": {"22/tcp": "ssh"}}
        self.assertFalse(any(sr.diff_open_ports(same, same).values()))

    def test_find_reports_ignores_logs_and_other_text_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, "10.0.0.1.txt"), COMPLETE_REPORT)
            write(os.path.join(tmp, "completed.txt"), "2026-01-01 00:00:00 | 10.0.0.1\n")
            write(os.path.join(tmp, "notes.txt"), "remember the milk\n")
            write(os.path.join(tmp, "nxc-smb-1.txt"), "# Nmap lookalike\n")
            self.assertEqual([os.path.basename(p) for p in sr.find_reports(tmp)], ["10.0.0.1.txt"])


# ═══════════════════════════════════════════════════════════════════════════════
#  End-to-end with fake nmap / ping / nxc
# ═══════════════════════════════════════════════════════════════════════════════

FAKE_NMAP = r'''#!{python}
"""Fake nmap: behaviour per target comes from $FAKE_NMAP_SCENARIOS (JSON)."""
import json, os, sys
argv = sys.argv[1:]
if os.environ.get("FAKE_NMAP_ARGV_LOG"):
    with open(os.environ["FAKE_NMAP_ARGV_LOG"], "a") as f:
        f.write(json.dumps(argv) + "\n")
target = argv[argv.index("--") + 1]
normal = argv[argv.index("-oN") + 1]
xml = argv[argv.index("-oX") + 1]
spec = json.loads(os.environ.get("FAKE_NMAP_SCENARIOS", "{{}}")).get(target, {{"kind": "up"}})
kind = spec["kind"]

if kind == "flaky":
    counter = os.path.join(os.environ["FAKE_NMAP_STATE"], target.replace("/", "_"))
    attempts = int(open(counter).read()) + 1 if os.path.exists(counter) else 1
    open(counter, "w").write(str(attempts))
    kind = "crash" if attempts <= spec.get("fail_times", 1) else "up"
if kind == "fatal":
    print("Starting Nmap 7.99 ( https://nmap.org )")
    print("You requested a scan type which requires root privileges.")
    print("QUITTING!")
    sys.exit(1)
if kind == "badopt":
    print("/usr/lib/nmap/nmap: unrecognized option '--bogus'", file=sys.stderr)
    print("See the output of nmap -h for a summary of options.", file=sys.stderr)
    sys.exit(255)
if kind == "crash":
    open(normal, "w").write("# Nmap 7.99 scan initiated as: nmap " + target + "\n")
    open(xml, "w").write("<?xml version=\"1.0\"?><nmaprun>")
    print("segfault-ish failure")
    sys.exit(1)

hosts = spec.get("hosts")
if hosts is None:
    hosts = [] if kind in ("down", "unresolved") else [{{"addr": target, "ports": spec.get("ports", [])}}]
lines = ["# Nmap 7.99 scan initiated Wed Sep 23 17:59:26 2026 as: nmap " + " ".join(argv)]
x = ['<?xml version="1.0" encoding="UTF-8"?>', '<nmaprun scanner="nmap">']
for h in hosts:
    lines += ["Nmap scan report for " + h["addr"], "Host is up (0.00010s latency)."]
    if kind == "timeout":
        lines.append("Skipping host " + h["addr"] + " due to host timeout")
        x.append('<host timedout="true"><status state="up"/><address addr="%s" addrtype="ipv4"/></host>' % h["addr"])
        continue
    lines.append("PORT   STATE SERVICE VERSION")
    x.append('<host><status state="up"/><address addr="%s" addrtype="ipv4"/><hostnames/><ports>' % h["addr"])
    for port, proto, service, product in h["ports"]:
        lines.append(("%s/%s open  %s %s" % (port, proto, service, product)).rstrip())
        x.append('<port protocol="%s" portid="%s"><state state="open"/><service name="%s" product="%s"/></port>'
                 % (proto, port, service, product))
    x.append("</ports></host>")
total = 0 if kind == "unresolved" else spec.get("total", max(1, len(hosts)))
up = len(hosts)
if kind == "unresolved":
    print('Failed to resolve "%s".' % target)
done = "# Nmap done at Wed Sep 23 17:59:29 2026 -- %d IP address%s (%d host%s up) scanned in 0.10 seconds" % (
    total, "" if total == 1 else "es", up, "" if up == 1 else "s")
lines.append(done)
x.append('<runstats><finished/><hosts up="%d" down="%d" total="%d"/></runstats></nmaprun>' % (up, total - up, total))
open(normal, "w").write("\n".join(lines) + "\n")
open(xml, "w").write("\n".join(x) + "\n")
print("\n".join(lines[1:]))
print(done.lstrip("# "))
'''

FAKE_PING = r'''#!{python}
import os, sys
sys.exit(0 if sys.argv[-1] in os.environ.get("FAKE_PING_UP", "").split(",") else 1)
'''

FAKE_NXC = r'''#!{python}
import json, os, sys
with open(os.environ["FAKE_NXC_ARGV_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
print(os.environ["FAKE_NXC_OUTPUT"])
'''


class EndToEndBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, source in (("nmap", FAKE_NMAP), ("ping", FAKE_PING), ("nxc", FAKE_NXC)):
            path = self.bin / name
            path.write_text(source.format(python=sys.executable))
            path.chmod(0o755)
        self.state = self.root / "state"
        self.state.mkdir()
        self.argv_log = self.root / "nmap-argv.jsonl"
        self.out = self.root / "out"
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                        FAKE_NMAP_STATE=str(self.state), FAKE_NMAP_ARGV_LOG=str(self.argv_log),
                        FAKE_PING_UP="", FAKE_NMAP_SCENARIOS="{}")

    def tearDown(self):
        self.tmp.cleanup()

    def targets(self, *targets):
        path = self.root / "targets.txt"
        path.write_text("\n".join(targets) + "\n")
        return str(path)

    def scenarios(self, **by_target):
        self.env["FAKE_NMAP_SCENARIOS"] = json.dumps(by_target)

    def run_scan(self, *args):
        result = run_cli(*args, "-o", str(self.out), "--no-color", env=self.env, cwd=str(self.root))
        self.last_output = result.stdout + result.stderr
        return result

    def logged(self, name):
        return sr.read_logged_ips(str(self.out / name))

    def nmap_calls(self):
        if not self.argv_log.exists():
            return []
        return [json.loads(line) for line in self.argv_log.read_text().splitlines()]

    def inventory(self):
        with open(self.out / "open-ports-inventory.json", encoding="utf-8") as f:
            return json.load(f)


def _mixed_scenarios():
    return {
        "10.0.0.1": {"kind": "up", "ports": [[22, "tcp", "ssh", "OpenSSH"], [80, "tcp", "http", "nginx"]]},
        "10.0.0.2": {"kind": "down"},
        "10.0.0.3": {"kind": "timeout"},
        "ghost.invalid": {"kind": "unresolved"},
        "10.9.0.0/30": {"kind": "up", "total": 4, "hosts": [
            {"addr": "10.9.0.1", "ports": [[22, "tcp", "ssh", ""]]},
            {"addr": "10.9.0.2", "ports": [[443, "tcp", "https", ""]]}]},
    }


MIXED_TARGETS = ("10.0.0.1", "10.0.0.2", "10.0.0.3", "ghost.invalid", "10.0.0.4", "10.9.0.0/30")


class SerialEndToEndTests(EndToEndBase):
    def test_every_outcome_is_classified_correctly(self):
        self.scenarios(**_mixed_scenarios())
        self.env["FAKE_PING_UP"] = "10.0.0.1,10.0.0.2,10.0.0.3,ghost.invalid"   # 10.0.0.4 won't ping
        result = self.run_scan("-f", self.targets(*MIXED_TARGETS), "--yes", "-n", "-sV")
        self.assertEqual(result.returncode, 0, self.last_output)
        self.assertEqual(self.logged("completed.txt"), {"10.0.0.1", "10.9.0.0/30"})
        self.assertEqual(self.logged("not-pingip.txt"), {"10.0.0.2", "10.0.0.4"})
        self.assertEqual(self.logged("failed.txt"), {"10.0.0.3", "ghost.invalid"})
        self.assertIn("Reconciliation OK", self.last_output)
        self.assertIn("host timeout", self.last_output)
        self.assertIn("could not resolve", self.last_output)
        self.assertFalse((self.out / "unaccounted.txt").exists())
        # -n reached Nmap; nothing was scanned for the no-ping host
        calls = self.nmap_calls()
        self.assertTrue(all("-n" in call for call in calls))
        self.assertEqual(len(calls), 5)
        rows = {(r["target"], r["host"], r["port_service"]) for r in self.inventory()}
        self.assertEqual(rows, {("10.0.0.1", "10.0.0.1", "22/tcp/ssh"), ("10.0.0.1", "10.0.0.1", "80/tcp/http"),
                                ("10.9.0.0/30", "10.9.0.1", "22/tcp/ssh"),
                                ("10.9.0.0/30", "10.9.0.2", "443/tcp/https")})

    def test_fatal_error_stops_the_run_and_leaves_rest_unaccounted(self):
        self.scenarios(**{"10.0.0.1": {"kind": "badopt"}})
        result = self.run_scan("-f", self.targets("10.0.0.1", "10.0.0.2", "10.0.0.3"),
                               "--yes", "--skip-ping", "--retries", "2", "--bogus")
        self.assertEqual(len(self.nmap_calls()), 1)           # no retries, no further hosts
        self.assertEqual(self.logged("failed.txt"), {"10.0.0.1"})
        self.assertIn("Stopping: Nmap refused to run", self.last_output)
        self.assertIn("unrecognized option", self.last_output)
        self.assertEqual((self.out / "unaccounted.txt").read_text().split(), ["10.0.0.2", "10.0.0.3"])
        self.assertEqual(result.returncode, 0)

    def test_retries_recover_a_flaky_scan(self):
        self.scenarios(**{"10.0.0.1": {"kind": "flaky", "fail_times": 1, "ports": [[22, "tcp", "ssh", ""]]}})
        result = self.run_scan("-i", "10.0.0.1", "--yes", "--skip-ping", "--retries", "1")
        self.assertEqual(result.returncode, 0, self.last_output)
        self.assertEqual(len(self.nmap_calls()), 2)
        self.assertEqual(self.logged("completed.txt"), {"10.0.0.1"})
        self.assertEqual(self.logged("retried.txt"), {"10.0.0.1"})

    def test_resume_rescans_an_interrupted_rescan(self):
        target_file = self.targets("10.0.0.1", "10.0.0.2")
        self.run_scan("-f", target_file, "--yes", "--skip-ping")
        self.assertEqual(self.logged("completed.txt"), {"10.0.0.1", "10.0.0.2"})
        # Simulate a later rescan of 10.0.0.2 that was killed mid-way
        report = self.out / "10.0.0.2.txt"
        report.write_text(INCOMPLETE_REPORT)
        later = datetime.now().timestamp() + 5
        os.utime(report, (later, later))
        self.argv_log.unlink()
        self.run_scan("-f", target_file, "--resume", "--yes", "--skip-ping")
        self.assertEqual([call[-1] for call in self.nmap_calls()], ["10.0.0.2"])
        self.assertEqual(sr.get_file_status(str(report)), "COMPLETE")
        self.assertIn("Reconciliation OK", self.last_output)

    def test_resume_retries_hosts_that_were_down(self):
        self.scenarios(**{"10.0.0.2": {"kind": "down"}})
        target_file = self.targets("10.0.0.1", "10.0.0.2")
        self.run_scan("-f", target_file, "--yes", "--skip-ping")
        self.argv_log.unlink()
        self.scenarios()
        self.run_scan("-f", target_file, "--resume", "--yes", "--skip-ping")
        self.assertEqual([call[-1] for call in self.nmap_calls()], ["10.0.0.2"])
        self.assertIn("Completed : 2", self.last_output)

    def test_scope_file_refuses_out_of_scope_hostname(self):
        scope = self.root / "scope.txt"
        scope.write_text("10.0.0.0/24\n")
        result = self.run_scan("-f", self.targets("10.0.0.1", "outside.invalid"),
                               "--yes", "--skip-ping", "--scope-file", str(scope))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Refusing targets outside --scope-file: outside.invalid", self.last_output)
        self.assertEqual(self.nmap_calls(), [])


class ParallelEndToEndTests(EndToEndBase):
    def test_parallel_matches_serial_outcomes_and_logs_existing_reports(self):
        self.scenarios(**_mixed_scenarios())
        self.env["FAKE_PING_UP"] = "10.0.0.1,10.0.0.2,10.0.0.3,ghost.invalid,10.0.0.5"
        self.out.mkdir()
        (self.out / "10.0.0.5.txt").write_text(COMPLETE_REPORT)   # already complete, never logged
        result = self.run_scan("-f", self.targets(*MIXED_TARGETS, "10.0.0.5"),
                               "--yes", "--parallel", "3", "-ok")
        self.assertEqual(result.returncode, 0, self.last_output)
        self.assertEqual(self.logged("completed.txt"), {"10.0.0.1", "10.9.0.0/30"})
        self.assertEqual(self.logged("not-pingip.txt"), {"10.0.0.2", "10.0.0.4"})
        self.assertEqual(self.logged("failed.txt"), {"10.0.0.3", "ghost.invalid"})
        self.assertEqual(self.logged("skipped.txt"), {"10.0.0.5"})
        self.assertIn("Reconciliation OK", self.last_output)
        self.assertNotIn("10.0.0.4", [call[-1] for call in self.nmap_calls()])
        error_log = self.out / "10.0.0.3.error.log"
        self.assertTrue(error_log.exists())
        self.assertIn("due to host timeout", error_log.read_text())

    def test_parallel_fatal_error_stops_queued_scans(self):
        self.scenarios(**{f"10.0.0.{i}": {"kind": "fatal"} for i in range(1, 21)})
        result = self.run_scan("-f", self.targets(*[f"10.0.0.{i}" for i in range(1, 21)]),
                               "--yes", "--parallel", "2", "--skip-ping", "-sS")
        self.assertEqual(result.returncode, 0, self.last_output)
        calls = len(self.nmap_calls())
        self.assertLessEqual(calls, 3)    # at most the scans already running
        self.assertEqual(len(self.logged("failed.txt")), calls)
        unaccounted = (self.out / "unaccounted.txt").read_text().split()
        self.assertEqual(len(unaccounted), 20 - calls)
        self.assertIn("requires root privileges", self.last_output)
        self.assertIn("Stopping: Nmap refused to run", self.last_output)


class TabEndToEndTests(EndToEndBase):
    def test_headless_tabs_fall_back_to_background_and_all_targets_finish(self):
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "TMUX"):
            self.env.pop(name, None)
        targets = [f"10.0.0.{i}" for i in range(1, 7)]
        self.scenarios(**{t: {"kind": "up", "ports": [[22, "tcp", "ssh", ""]]} for t in targets})
        result = self.run_scan("-f", self.targets(*targets), "--tabs", "3", "--skip-ping")
        self.assertEqual(result.returncode, 0, self.last_output)
        self.assertIn("0 in terminal windows, 3 running in background", self.last_output)
        deadline = datetime.now() + timedelta(seconds=60)
        while datetime.now() < deadline and len(self.logged("completed.txt")) < len(targets):
            time.sleep(0.2)
        self.assertEqual(self.logged("completed.txt"), set(targets))
        for index in (1, 2, 3):
            self.assertTrue((self.out / "tabs" / f"tab_{index}_console.log").exists())
        status = run_cli("--status", str(self.out), "--no-color", env=self.env)
        self.assertIn("Tab run: 6/6 target(s) have an outcome", status.stdout)
        self.assertEqual(len(self.inventory()), 6)


class ReviewCommandTests(EndToEndBase):
    def test_status_and_diff(self):
        old_dir, new_dir = self.root / "old", self.root / "new"
        self.scenarios(**{"10.0.0.1": {"kind": "up", "ports": [[22, "tcp", "ssh", ""], [80, "tcp", "http", ""]]},
                          "10.0.0.2": {"kind": "up", "ports": [[22, "tcp", "ssh", ""]]}})
        run_cli("-f", self.targets("10.0.0.1", "10.0.0.2"), "--yes", "--skip-ping", "-o", str(old_dir),
                env=self.env, cwd=str(self.root))
        self.scenarios(**{"10.0.0.1": {"kind": "up", "ports": [[22, "tcp", "ssh", ""], [443, "tcp", "https", ""]]},
                          "10.0.0.2": {"kind": "down"},
                          "10.0.0.3": {"kind": "up", "ports": [[3389, "tcp", "ms-wbt-server", ""]]}})
        run_cli("-f", self.targets("10.0.0.1", "10.0.0.2", "10.0.0.3"), "--yes", "--skip-ping",
                "-o", str(new_dir), env=self.env, cwd=str(self.root))

        status = run_cli("--status", str(new_dir), "--no-color", env=self.env)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("Completed   : 2", status.stdout)
        self.assertIn("Down/NoPing : 1", status.stdout)
        self.assertIn("Open ports: 3 across 2 host(s)", status.stdout)

        diff = run_cli("--diff", str(old_dir), str(new_dir), "--no-color", env=self.env)
        self.assertEqual(diff.returncode, 0, diff.stderr)
        self.assertIn("newly open: 443/tcp/https", diff.stdout)
        self.assertIn("now closed: 80/tcp/http", diff.stdout)
        self.assertIn("new host: 3389/tcp/ms-wbt-server", diff.stdout)
        self.assertIn("10.0.0.2", diff.stdout)
        with open(new_dir / "scan-diff.json", encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["missing_hosts"], ["10.0.0.2"])

    def test_review_command_errors(self):
        self.assertEqual(run_cli("--status", str(self.root / "missing")).returncode, 1)
        self.assertEqual(run_cli("--diff", "only-one").returncode, 2)
        self.assertEqual(run_cli("--status", "a", "b").returncode, 2)
        help_result = run_cli("--status", "-h")
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--status [DIR]", help_result.stdout)


class NxcEndToEndTests(EndToEndBase):
    def test_nxc_table_and_module_options(self):
        nxc_log = self.root / "nxc-argv.jsonl"
        self.env.update(FAKE_NXC_ARGV_LOG=str(nxc_log), FAKE_NXC_OUTPUT=NXC_OUTPUT)
        # Keep only the fake nxc on PATH so a real netexec install can't be picked up
        result = self.run_scan("-f", self.targets("10.0.0.0/24"), "-nxc", "smb",
                               "--nxc-query", "smbv1,smb-signing", "-M", "spider_plus",
                               "-o", "DOWNLOAD_FLAG=False")
        self.assertEqual(result.returncode, 0, self.last_output)
        argv = json.loads(nxc_log.read_text().splitlines()[0])
        self.assertEqual(argv[-2:], ["-o", "DOWNLOAD_FLAG=False"])
        csv_file = next(self.out.glob("nxc-smb-*.csv"))
        lines = csv_file.read_text().splitlines()
        self.assertEqual(lines[0], "target,smbv1,smb_signing")
        self.assertEqual(lines[1:], ["10.0.0.5,False,True", "10.0.0.9,True,False"])
        self.assertIn("2 findings across 2 host(s)", self.last_output)


# ═══════════════════════════════════════════════════════════════════════════════
#  Real Nmap against a local listener (skipped when Nmap isn't installed)
# ═══════════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class RealNmapTests(unittest.TestCase):
    def test_scan_localhost_listener(self):
        with socket.socket() as server, tempfile.TemporaryDirectory() as tmp:
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            out = os.path.join(tmp, "out")
            result = run_cli("-i", "127.0.0.1", "--yes", "--skip-ping", "-n", "-sT",
                             "-p", str(port), "--host-timeout", "60s", "-o", out,
                             "--html-report", "--no-color", timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(sr.get_file_status(os.path.join(out, "127.0.0.1.txt")), "COMPLETE")
            with open(os.path.join(out, "open-ports-inventory.json"), encoding="utf-8") as f:
                rows = json.load(f)
            self.assertEqual([(r["host"], r["port_service"].split("/")[0]) for r in rows],
                             [("127.0.0.1", str(port))])
            self.assertIn("Reconciliation OK", result.stdout)
            self.assertTrue(os.path.exists(os.path.join(out, "open-ports-report.html")))


if __name__ == "__main__":
    unittest.main()

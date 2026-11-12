"""Offline regressions for misleading completion and security observations."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("guard_scanrunner", Path(__file__).resolve().parents[1] / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class EvidenceGuards(unittest.TestCase):
    def test_netexec_smb_default_enumeration_requires_explicit_authorization(self):
        with mock.patch("sys.argv", ["scanrunner", "-i", "192.0.2.1", "-nxc", "smb", "--dry-run"]), \
                mock.patch.object(sr.subprocess, "Popen") as launch, mock.patch.object(sr.socket, "getaddrinfo") as dns, \
                self.assertRaisesRegex(ValueError, "null and Guest"):
            sr.main()
        launch.assert_not_called()
        dns.assert_not_called()

    def test_authorization_notes_redact_recognized_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = sr.RunStore(temporary, {"authorization_note": "password=fixture-secret"})
            self.assertNotIn("fixture-secret", store.public_config()["authorization_note"])
            store.end("Synthetic test completed")
        output = io.StringIO()
        with mock.patch("sys.argv", ["scanrunner", "-i", "192.0.2.1", "--dry-run", "--json", "--allow-intrusive", "--authorization-note", "password=fixture-secret"]), \
                mock.patch("sys.stdout", output):
            sr.main()
        self.assertNotIn("fixture-secret", json.loads(output.getvalue())["authorization"])
    def test_netexec_partial_targets_and_unknown_settings_do_not_complete(self):
        rows = sr.parse_nxc_output("SMB 192.0.2.1 445 HOST [*] Windows (name:HOST) (signing:False)", ["192.0.2.0/24"])
        self.assertEqual(sr.nxc_target_outcomes(rows, ["192.0.2.0/24"], ["smb-signing"], "smb"), {"192.0.2.0/24": "PARTIAL"})
        self.assertEqual(sr.nxc_target_outcomes(rows, ["192.0.2.1", "192.0.2.2"], ["smb-signing"], "smb"),
                         {"192.0.2.1": "COMPLETE", "192.0.2.2": "INCONCLUSIVE"})
        self.assertEqual(sr.nxc_target_outcomes(rows, ["192.0.2.1"], ["rdp-nla"], "rdp"), {"192.0.2.1": "INCONCLUSIVE"})
        self.assertEqual(sr.nxc_target_outcomes([{**rows[0], "smb_signing": "Inconclusive"}], ["192.0.2.1"], ["smb-signing"], "smb"),
                         {"192.0.2.1": "INCONCLUSIVE"})
        different_port = [{**rows[0], "port": "1445"}]
        self.assertEqual(sr.nxc_target_outcomes(different_port, ["192.0.2.1"], ["smb-signing"], "smb"), {"192.0.2.1": "INCONCLUSIVE"})
        self.assertEqual(sr.nxc_target_outcomes(different_port, ["192.0.2.1"], ["smb-signing"], "smb", expected_port=1445),
                         {"192.0.2.1": "COMPLETE"})

    def test_netexec_rejected_anonymous_login_is_a_tested_negative(self):
        rows = sr.parse_nxc_output("SMB 192.0.2.1 445 HOST [-] corp.local\\: STATUS_LOGON_FAILURE", ["192.0.2.1"], null_auth_attempt=True)
        self.assertEqual(rows[0]["null_auth"], "Rejected")
        self.assertEqual(sr.nxc_target_outcomes(rows, ["192.0.2.1"], ["null-auth"], "smb"), {"192.0.2.1": "COMPLETE"})
        denied = sr.parse_nxc_output("SMB 192.0.2.1 445 HOST [-] corp.local\\: STATUS_ACCESS_DENIED", ["192.0.2.1"], null_auth_attempt=True)
        self.assertEqual(denied[0]["null_auth"], "Inconclusive")

    def test_netexec_hash_credentials_and_status_text_do_not_become_anonymous_or_os_proof(self):
        for options in [["-H", "synthetic-hash"], ["--hash=synthetic-hash"]]:
            with self.subTest(options=options):
                self.assertEqual(sr.effective_nxc_options(options, ["null-auth"]), options)
                self.assertFalse(sr.uses_anonymous_nxc_credentials(["-u", "", "-p", "", *options]))
        row = sr.parse_nxc_output("SMB 192.0.2.1 445 HOST [*] Enumeration finished", ["192.0.2.1"])[0]
        self.assertEqual(row["os"], "")

    def test_netexec_hostname_coverage_uses_pinned_answers_without_dns(self):
        pinned = {"fixture.invalid": ["192.0.2.1", "192.0.2.2"]}
        with mock.patch.object(sr, "resolve_scan_target") as resolver:
            rows = sr.parse_nxc_output("SMB 192.0.2.1 445 HOST [*] (signing:False)", ["fixture.invalid"],
                                       dns_answers=pinned, allowed_addresses=pinned["fixture.invalid"])
            coverage = sr.nxc_target_outcomes(rows, ["fixture.invalid"], ["smb-signing"], "smb", pinned)
        resolver.assert_not_called()
        self.assertEqual(coverage, {"fixture.invalid": "PARTIAL"})

    def test_netexec_all_preview_shows_explicit_blank_authentication(self):
        output = io.StringIO()
        argv = ["scanrunner", "-i", "192.0.2.1", "-nxc", "smb", "--nxc-query", "all", "--allow-intrusive",
                "--authorization-note", "Synthetic fixture authorization", "--dry-run", "--json"]
        with mock.patch("sys.argv", argv), mock.patch("sys.stdout", output), mock.patch.object(sr.subprocess, "Popen") as launch:
            sr.main()
        command = json.loads(output.getvalue())["commands"][0]["argv"]
        self.assertIn("-u", command)
        self.assertIn("-p", command)
        launch.assert_not_called()
        output = io.StringIO()
        with mock.patch("sys.argv", ["scanrunner", "-i", "192.0.2.1", "-nxc", "rdp", "--nxc-query", "all", "--dry-run", "--json"]), \
                mock.patch("sys.stdout", output):
            sr.main()
        self.assertNotIn("-u", json.loads(output.getvalue())["commands"][0]["argv"])
        self.assertNotIn("-p", json.loads(output.getvalue())["commands"][0]["argv"])
        with self.assertRaises(ValueError):
            sr.validate_nxc_queries("rdp", ["null-auth"])

    def test_netexec_execution_persists_partial_coverage_and_successful_single_host(self):
        for targets, expected in [(["192.0.2.1"], "COMPLETE"), (["192.0.2.1", "192.0.2.2"], "PARTIAL")]:
            with self.subTest(targets=targets), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "targets.txt"
                source.write_text("\n".join(targets) + "\n")
                output = Path(temporary) / "out"
                def capture(command, directory, timeout, live):
                    (Path(directory) / "stdout.bin").write_bytes(b"SMB 192.0.2.1 445 HOST [*] (signing:False)\n")
                    (Path(directory) / "stderr.bin").write_bytes(b"")
                    return 0, "Exited"
                with mock.patch.object(sr, "ACTIVE_STORE", None), mock.patch.object(sr, "ACTIVE_SCOPE", None), \
                        mock.patch.object(sr, "ACTIVE_CONFIG", {}), mock.patch.object(sr, "capture_process", side_effect=capture):
                    successful = sr.run_nxc("fixture-nxc", "smb", str(source), targets, [], ["smb-signing"], str(output))
                self.assertEqual(successful, expected == "COMPLETE")
                history = sr.review_run_history(str(output))
                self.assertEqual(history["jobs"][0]["outcome"], expected)
                coverage = json.loads((Path(history["jobs"][0]["directory"]) / "coverage.json").read_text())
                self.assertEqual(coverage["targets"]["192.0.2.1"], "COMPLETE")
                if expected == "PARTIAL":
                    self.assertEqual(coverage["targets"]["192.0.2.2"], "INCONCLUSIVE")
    def test_all_advertised_profiles_preview_through_cli(self):
        installer_spec = importlib.util.spec_from_file_location("guard_installer", Path(sr.__file__).with_name("install.py"))
        installer = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer)
        self.assertEqual(set(installer.PROFILES), set(sr.SCAN_PROFILES))
        for name in sr.SCAN_PROFILES:
            with self.subTest(profile=name):
                argv = ["scanrunner", "-i", "192.0.2.1", "--profile", name, "--dry-run", "--json"]
                if name in sr.PROFILE_REQUIRES_AUTHORIZATION:
                    argv += ["--allow-intrusive", "--authorization-note", "Synthetic fixture authorization"]
                output = io.StringIO()
                with mock.patch("sys.argv", argv), mock.patch("sys.stdout", output), \
                        mock.patch("sys.stderr", io.StringIO()), mock.patch.object(sr.subprocess, "Popen") as process, \
                        mock.patch.object(sr.socket, "getaddrinfo") as dns:
                    sr.main()
                self.assertEqual(json.loads(output.getvalue())["commands"][0]["target"], "192.0.2.1")
                process.assert_not_called()
                dns.assert_not_called()

    def test_smb_profile_requires_authorization_through_cli(self):
        argv = ["scanrunner", "-i", "192.0.2.1", "--profile", "smb-audit", "--dry-run"]
        for extra in [[], ["--allow-intrusive"]]:
            with self.subTest(extra=extra), mock.patch("sys.argv", argv + extra), \
                    mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as raised:
                sr.main()
            self.assertEqual(raised.exception.code, 2)

    def parse(self, details, **kwargs):
        output = "\n".join("SMB 192.0.2.1 445 HOST " + item for item in details)
        return sr.parse_nxc_output(output, ["192.0.2.1"], **kwargs)[0]

    def test_anonymous_auth_requires_exact_result_and_explicit_attempt(self):
        for detail, attempted, expected in [
                ("[+] corp.local\\:", True, "Success"),
                ("[+] :", True, "Success"),
                ("[+] corp.local\\:", False, ""),
                ("[+] Enumeration finished", True, ""),
                ("[+] corp.local\\alice:password", True, ""),
                ("[-] corp.local\\:", True, ""),
                ("[*] port open", True, "")]:
            with self.subTest(detail=detail, attempted=attempted):
                self.assertEqual(self.parse([detail], null_auth_attempt=attempted)["null_auth"], expected)

    def test_conflicting_security_observations_stay_inconclusive(self):
        for first, second in [("True", "False"), ("False", "True"), ("None", "False")]:
            with self.subTest(first=first, second=second):
                row = self.parse([f"[*] (signing:{first})", f"[*] (signing:{second})", "[*] (signing:False)"])
                self.assertEqual(row["smb_signing"], "Inconclusive")
        self.assertEqual(self.parse(["[*] (signing:True)", "[*] (signing:true)"])["smb_signing"], "True")

    def test_conflicting_authentication_results_never_become_success(self):
        for details in [["[+] corp.local\\:", "[-] corp.local\\: STATUS_LOGON_FAILURE"],
                        ["[-] corp.local\\: STATUS_ACCESS_DENIED", "[+] corp.local\\:"]]:
            with self.subTest(details=details):
                self.assertEqual(self.parse(details, null_auth_attempt=True)["null_auth"], "Inconclusive")

    def test_endpoint_and_protocol_are_not_mixed(self):
        output = ("SMB 192.0.2.1 445 HOST [*] (signing:False)\n"
                  "RDP 192.0.2.1 3389 HOST [*] (NLA:False)\n"
                  "SMB 192.0.2.1 1445 HOST [*] (signing:True)")
        rows = sr.parse_nxc_output(output, ["192.0.2.1"])
        self.assertEqual(len(rows), 3)
        self.assertEqual([(r["port"], r["smb_signing"], r["rdp_nla"]) for r in rows],
                         [("445", "False", ""), ("3389", "", "False"), ("1445", "True", "")])
        self.assertEqual(len(sr.parse_nxc_output(output, ["192.0.2.1"], expected_protocol="rdp")), 1)

    def test_scope_pinning_and_invalid_ports(self):
        for address, port in [("198.51.100.1", "445"), ("192.0.2.1", "0"), ("192.0.2.1", "65536")]:
            with self.subTest(address=address, port=port):
                row = sr.parse_nxc_output(f"SMB {address} {port} HOST [*] (signing:False)", ["192.0.2.1"])[0]
                self.assertEqual(row["smb_signing"], "")
        rows = sr.parse_nxc_output("SMB 192.0.2.2 445 HOST [*] (signing:False)", ["192.0.2.0/24"],
                                   allowed_addresses=["192.0.2.1"])
        self.assertEqual(rows, [])

    def test_empty_or_unrecognized_netexec_cannot_complete(self):
        for content in [b"", b"[+] Enumeration finished\n", b"SMB 198.51.100.1 445 HOST [*] (signing:False)"]:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                store = sr.RunStore(temporary, {"tool": "nxc"})
                def capture(command, directory, timeout, live):
                    (Path(directory) / "stdout.bin").write_bytes(content)
                    (Path(directory) / "stderr.bin").write_bytes(b"")
                    return 0, "Exited"
                with mock.patch.object(sr, "ACTIVE_STORE", store), mock.patch.object(sr, "capture_process", side_effect=capture):
                    self.assertFalse(sr.run_nxc("fixture-nxc", "smb", "192.0.2.1", ["192.0.2.1"], [], [], temporary))
                with store.connect() as database:
                    row = database.execute("SELECT outcome,parser_ok FROM jobs").fetchone()
                self.assertNotEqual(row["outcome"], "COMPLETE")
                self.assertFalse(row["parser_ok"])

    def test_completion_cannot_be_asserted_without_artifacts(self):
        for tool in ["nmap", "nxc"]:
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as temporary:
                store = sr.RunStore(temporary, {"tool": tool})
                job = store.claim("192.0.2.1")
                store.finish_job(job, "COMPLETE", 0, True, [tool])
                self.assertFalse(store.completed("192.0.2.1"))
                with store.connect() as database:
                    row = database.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()
                # An incomplete artifact set limits coverage; it is not evidence tampering.
                self.assertTrue(store.verify_job(row))

    def test_anonymous_nse_requires_opt_in(self):
        with self.assertRaises(ValueError):
            sr.validate_scan_options(["--script", "smb-os-discovery"])
        sr.validate_scan_options(["--script", "smb-os-discovery"], allow_intrusive=True)

    def test_nmap_semantic_validation(self):
        template = ('<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>'
                    '<ports><port portid="{port}" protocol="{protocol}"><state state="{state}"/></port></ports>'
                    '</host><runstats><finished exit="success"/><hosts up="{up}" total="1"/></runstats></nmaprun>')
        for port, protocol, state, up, expected in [
                ("22", "tcp", "open", 1, True), ("53", "udp", "open|filtered", 1, True),
                ("bad", "tcp", "open", 1, False), ("65536", "tcp", "open", 1, False),
                ("22", "unknown", "open", 1, False), ("22", "tcp", "probably-open", 1, False),
                ("22", "tcp", "open", 0, False)]:
            with self.subTest(port=port, protocol=protocol, state=state, up=up), tempfile.TemporaryDirectory() as temporary:
                report = Path(temporary) / "nmap.txt"
                report.write_text(f"# Nmap done -- 1 IP address ({up} hosts up) scanned\n")
                report.with_suffix(".xml").write_text(template.format(port=port, protocol=protocol, state=state, up=up))
                self.assertEqual(sr.validate_nmap_evidence(str(report), "192.0.2.1", 0)[1], expected)

    def test_nmap_impossible_host_totals_cannot_complete(self):
        for statistics in ['up="1" total="-1"', 'up="1" down="1" total="1"', 'up="1" down="-1" total="1"']:
            with self.subTest(statistics=statistics), tempfile.TemporaryDirectory() as temporary:
                report = Path(temporary) / "nmap.txt"
                report.write_text("# Nmap done -- 1 IP address (1 host up) scanned\n")
                report.with_suffix(".xml").write_text('<nmaprun><host><status state="up"/>'
                    '<address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/>'
                    '<hosts ' + statistics + '/></runstats></nmaprun>')
                self.assertFalse(sr.validate_nmap_evidence(str(report), "192.0.2.1", 0)[1])

    def test_parser_revision_invalidates_resume_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = sr.RunStore(temporary)
            previous = store.fingerprint("192.0.2.1")
            with mock.patch.object(sr, "EVIDENCE_PARSER_VERSION", "future"):
                self.assertNotEqual(store.fingerprint("192.0.2.1"), previous)


if __name__ == "__main__":
    unittest.main()

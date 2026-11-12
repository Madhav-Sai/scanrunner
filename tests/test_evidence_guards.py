"""Offline regressions for misleading completion and security observations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("guard_scanrunner", Path(__file__).resolve().parents[1] / "scanrunner.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class EvidenceGuards(unittest.TestCase):
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

    def test_parser_revision_invalidates_resume_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = sr.RunStore(temporary)
            previous = store.fingerprint("192.0.2.1")
            with mock.patch.object(sr, "EVIDENCE_PARSER_VERSION", "future"):
                self.assertNotEqual(store.fingerprint("192.0.2.1"), previous)


if __name__ == "__main__":
    unittest.main()

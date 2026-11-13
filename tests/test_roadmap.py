"""Protocol counterexamples and exported workbook schemas."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import io
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

from scanrunner_lib import scanrunner_assessment as assessment
from scanrunner_lib import scanrunner_findings as findings
from scanrunner_lib import scanrunner_rules as rules
from scanrunner_lib import scanrunner_probes as probes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("roadmap_backend", ROOT / "scanrunner.py")
backend = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = backend
spec.loader.exec_module(backend)


def node(key, values):
    return {"tag": "table", "key": key, "children": [{"tag": "elem", "text": value} for value in values]}


def observation(check, output, children=()):
    rule = rules.RULES[check]
    return {"check_id": check, "port": min(rule["ports"]), "transport": rule["transport"], "source_tool": "nmap",
            "addresses": ["192.0.2.1"], "host_state": "up", "service_state": "open", "execution_outcome": "Imported",
            "scan_completion": "success", "check_execution": "Output observed", "output": output,
            "structured": {"children": list(children)}, "observed_at": "2026-11-13T00:00:00+00:00"}


class ProtocolContractTests(unittest.TestCase):
    def test_rdp_requires_explicit_non_nla_acceptance_or_required_rejections(self):
        positive = observation("rdp-enum-encryption", "SSL: SUCCESS\nCredSSP (NLA): SUCCESS")
        negative = observation("rdp-enum-encryption", "SSL: FAILED (HYBRID_REQUIRED_BY_SERVER)\nNative RDP: FAILED (HYBRID_REQUIRED_BY_SERVER)\nCredSSP (NLA): SUCCESS")
        self.assertEqual(findings.evaluate(positive)["outcome"], "Potential")
        self.assertEqual(findings.evaluate(negative)["outcome"], "Not observed")
        for value in ("CredSSP (NLA): SUCCESS", "SSL: Unknown", "malformed", "SSL: SUCCESS\nFailed to connect to server", "SSL: SUCCESS\nSSL: FAILED (HYBRID_REQUIRED_BY_SERVER)"):
            self.assertEqual(findings.evaluate(observation("rdp-enum-encryption", value))["outcome"], "Inconclusive")

    def test_tls_negotiated_protocol_and_cipher_evidence(self):
        cipher = {"tag": "table", "children": [{"tag": "elem", "key": "name", "text": "TLS_AES_128_GCM_SHA256"}]}
        for protocol, expected in (("TLSv1.0", "Potential"), ("TLSv1.2", "Not observed")):
            value = observation("ssl-enum-ciphers", protocol + " TLS_AES_128_GCM_SHA256",
                                [{"tag": "table", "key": protocol, "children": [{"tag": "table", "key": "ciphers", "children": [cipher]}]}])
            self.assertEqual(findings.evaluate(value)["outcome"], expected)
            contradictory = copy.deepcopy(value)
            contradictory["structured"]["children"].append(copy.deepcopy(value["structured"]["children"][0]))
            self.assertEqual(findings.evaluate(contradictory)["outcome"], "Inconclusive")
            value["output"] = "TLS handshake timeout"
            self.assertEqual(findings.evaluate(value)["outcome"], "Inconclusive")
        self.assertEqual(findings.evaluate(observation("ssl-enum-ciphers", "TLSv1.0"))["outcome"], "Inconclusive")

    def test_certificate_validity_uses_observation_time_and_unique_dates(self):
        for expiry, expected in (("2025-01-01T00:00:00", "Potential"), ("2027-01-01T00:00:00", "Not observed")):
            dates = {"tag": "table", "key": "validity", "children": [
                {"tag": "elem", "key": "notBefore", "text": "2024-01-01T00:00:00"},
                {"tag": "elem", "key": "notAfter", "text": expiry}]}
            value = observation("ssl-cert", "2024-01-01T00:00:00 " + expiry, [dates])
            self.assertEqual(findings.evaluate(value)["outcome"], expected)
            value["structured"]["children"].append(copy.deepcopy(dates))
            self.assertEqual(findings.evaluate(value)["outcome"], "Inconclusive")
        for output in ("expired", "timeout", "self-signed"):
            self.assertEqual(findings.evaluate(observation("ssl-cert", output))["outcome"], "Inconclusive")

    def test_ssh_offers_require_complete_reviewed_groups_for_negative(self):
        groups = [node("kex_algorithms", ["curve25519-sha256"]), node("server_host_key_algorithms", ["ssh-ed25519"]),
                  node("encryption_algorithms", ["aes128-ctr"]), node("mac_algorithms", ["hmac-sha2-256"])]
        value = observation("ssh2-enum-algos", "curve25519-sha256 ssh-ed25519 aes128-ctr hmac-sha2-256", groups)
        self.assertEqual(findings.evaluate(value)["outcome"], "Not observed")
        value["structured"]["children"][1]["children"].append({"tag": "elem", "text": "ssh-dss"})
        value["output"] += " ssh-dss"
        self.assertEqual(findings.evaluate(value)["outcome"], "Potential")
        value["structured"]["children"].append(node("server_host_key_algorithms", ["ssh-ed25519"]))
        self.assertEqual(findings.evaluate(value)["outcome"], "Inconclusive")
        self.assertEqual(findings.evaluate(observation("ssh2-enum-algos", "SSH-2.0-banner"))["outcome"], "Inconclusive")

    def test_ftp_dns_and_management_observations_do_not_infer_security_from_ports(self):
        for text, expected in (("Anonymous FTP login allowed (FTP code 230)", "Potential"),
                               ("Anonymous FTP login rejected (FTP code 530)", "Not observed"),
                               ("Anonymous FTP login allowed (FTP code 230)\n530 rejected", "Inconclusive"),
                               ("220 FTP service", "Inconclusive"), ("timeout", "Inconclusive")):
            self.assertEqual(findings.evaluate(observation("ftp-anon", text))["outcome"], expected)
        self.assertEqual(findings.evaluate(observation("dns-recursion", "Recursion appears to be enabled"))["outcome"], "Inconclusive")
        self.assertEqual(findings.evaluate(observation("management-exposure", "Open tcp/22"))["outcome"], "Exposure")
        for check in rules.RULES:
            value = observation(check, "some output")
            for field, wrong in (("port", 1), ("transport", "sctp"), ("addresses", []), ("scan_completion", "error")):
                altered = {**value, field: wrong}
                self.assertEqual(findings.evaluate(altered)["outcome"], "Inconclusive")

    def test_xlsx_round_trip_preserves_typed_endpoint_and_blocks_formula_cells(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "inventory.xlsx"
            rows = [{"address": "2001:db8::1", "port": 445, "state": "open|filtered", "notes": "=HYPERLINK(\"bad\")", "at": "2026-11-13T00:00:00Z"}]
            assessment.export_records(backend, rows, destination, "xlsx")
            book = load_workbook(destination)
            sheet = book.active
            self.assertEqual(list(sheet.values), [tuple(rows[0]), tuple(rows[0].values())])
            self.assertEqual(sheet["D2"].data_type, "s")
            book.close()

    def test_dns_controls_validate_transaction_question_answer_and_recursion_difference(self):
        proof = {"check_id": "sr-dns-recursion", "expected_answer": "192.0.2.99", "exchanges": []}
        for recursive in (False, True):
            request = probes.dns_question("owned.example.invalid", recursive)
            flags = 0x8180 if recursive else 0x8085
            response = request[:2] + struct.pack("!HHHHH", flags, 1, int(recursive), 0, 0) + request[12:]
            if recursive:
                response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.99")
            proof["exchanges"].append({"request_hex": request.hex(), "response_hex": response.hex()})
        self.assertIn("verified", probes.interpret(proof))
        altered = copy.deepcopy(proof)
        altered["expected_answer"] = "192.0.2.100"
        self.assertIn("inconclusive", probes.interpret(altered))
        altered["exchanges"][1]["response_hex"] = "ffff" + altered["exchanges"][1]["response_hex"][4:]
        with self.assertRaisesRegex(ValueError, "Unassociated"):
            probes.interpret(altered)
        with self.assertRaises(ValueError):
            probes.dns_name(b"\xc0\x00", 0)
        denied = copy.deepcopy(proof)
        for item in denied["exchanges"]:
            request = bytes.fromhex(item["request_hex"])
            flags = 0x8085 | (struct.unpack_from("!H", request, 2)[0] & 0x0100)
            item["response_hex"] = (request[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + request[12:]).hex()
        self.assertIn("rejected", probes.interpret(denied))

    def test_native_ftp_cli_persists_reparseable_evidence_and_requires_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scope = root / "scope.txt"
            scope.write_text("127.0.0.1\n")
            with socket.socket() as server:
                server.bind(("127.0.0.1", 0))
                server.listen()
                port = server.getsockname()[1]
                def serve():
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(b"220 Owned local FTP fixture\r\n")
                        self.assertEqual(connection.recv(4096), b"USER anonymous\r\n")
                        connection.sendall(b"331 Password required\r\n")
                        self.assertEqual(connection.recv(4096), b"PASS scanrunner@example.invalid\r\n")
                        connection.sendall(b"230 Login accepted\r\n")
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                with mock.patch("sys.stdout", io.StringIO()):
                    result = probes.cli(["ftp-anon", "--ip", "127.0.0.1", "--port", str(port), "--scope-file", str(scope),
                                         "--output", str(root / "out"), "--authorization-note", "Owned local fixture"], backend)
                thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(result, 0)
            store = backend.RunStore(str(root / "out"), {"tool": "local"})
            repository = findings.FindingRepository(store, backend)
            with store.connect() as database:
                identifier = database.execute("SELECT id FROM security_observations").fetchone()[0]
            finding = repository.create("default", identifier)
            self.assertEqual(finding["evaluation"]["outcome"], "Potential")
            self.assertEqual(finding["status"], "Needs Verification")
            self.assertEqual(finding["cvss_score"], "Not determined")
            self.assertEqual(len(backend.review_run_history(str(root / "out"))["jobs"]), 1)
            store.end("Test finished")

    def test_native_probe_preview_never_opens_socket_or_writes_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            scope = Path(temporary) / "scope.txt"
            scope.write_text("127.0.0.1\n")
            with mock.patch.object(probes.socket, "create_connection") as connect, mock.patch("sys.stdout", io.StringIO()):
                probes.cli(["ftp-anon", "--ip", "127.0.0.1", "--scope-file", str(scope), "--dry-run", "--output", temporary,
                            "--authorization-note", "Owned local fixture"], backend)
            connect.assert_not_called()
            self.assertFalse((Path(temporary) / ".scanrunner").exists())

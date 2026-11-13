"""Optional adapter schema, scope and template policy counterexamples."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import scanrunner_plugins as plugins
from test_roadmap import backend


class PluginTests(unittest.TestCase):
    def test_literal_endpoint_binding_and_redirect_results_are_rejected(self):
        for value in ("https://example.org", "https://127.0.0.1@198.51.100.1", "file:///tmp/input", "https://127.0.0.1/?token=secret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                plugins.endpoint(value)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "output.jsonl"
            for row in ({"url": "http://127.0.0.1/", "status_code": 200, "host": "127.0.0.1"},
                        {"url": "http://198.51.100.1/", "status_code": 200},
                        {"url": "http://127.0.0.1/", "status_code": "200"},
                        {"url": "http://127.0.0.1/", "status_code": 200, "host": "198.51.100.1"}):
                path.write_text(json.dumps(row))
                if row.get("host") == "127.0.0.1":
                    self.assertEqual(len(plugins.parse_output("httpx", path, "http://127.0.0.1/")), 1)
                else:
                    with self.assertRaises(ValueError):
                        plugins.parse_output("httpx", path, "http://127.0.0.1/")

    def test_template_policy_rejects_remote_paths_payloads_and_unreviewed_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "template.yaml"
            template = {"id": "owned-status", "info": {"name": "Owned status", "author": "Fixture", "severity": "info"},
                        "http": [{"method": "GET", "path": ["{{BaseURL}}/"], "matchers": [{"type": "status", "status": [200]}]}]}
            path.write_text(json.dumps(template))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(plugins.reviewed_template(path, digest), path.read_bytes())
            for field, value in (("method", "POST"), ("path", ["https://198.51.100.1/"]), ("path", ["{{BaseURL}}/%2f%2fremote"]),
                                 ("raw", ["GET / HTTP/1.1"]), ("redirects", True)):
                altered = json.loads(json.dumps(template))
                altered["http"][0][field] = value
                path.write_text(json.dumps(altered))
                with self.assertRaises(ValueError):
                    plugins.reviewed_template(path, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):
                plugins.reviewed_template(path, digest)

    def test_tls_conflicts_are_retained_and_empty_matches_do_not_imply_security(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tls.json"
            path.write_text(json.dumps([{"ip": "127.0.0.1", "port": "443", "id": "TLS1", "finding": value, "severity": "INFO"}
                                        for value in ("offered", "not offered")]))
            results = plugins.parse_output("testssl", path, "https://127.0.0.1/")
            self.assertEqual([row["outcome"] for row in results], ["Inconclusive", "Inconclusive"])
            path.write_text("")
            self.assertEqual(plugins.parse_output("nuclei", path, "https://127.0.0.1/"), [])

    def test_plugin_import_retains_raw_evidence_without_starting_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "http.jsonl"
            artifact.write_text(json.dumps({"url": "http://127.0.0.1/", "host": "127.0.0.1", "status_code": 200}))
            scope = root / "scope.txt"
            scope.write_text("127.0.0.1\n")
            with mock.patch.object(plugins.subprocess, "run") as process, mock.patch("sys.stdout", io.StringIO()):
                result = plugins.cli(["import", "--adapter", "httpx", "--target", "http://127.0.0.1/", "--scope-file", str(scope),
                                      "--expected-version", "1.7.1", "--artifact", str(artifact), "--output", str(root / "out")], backend)
            self.assertEqual(result, 0)
            process.assert_not_called()
            with mock.patch("sys.stdout", io.StringIO()) as output:
                plugins.cli(["observations", "--output", str(root / "out")], backend)
            row = json.loads(output.getvalue())[0]
            self.assertTrue(row["imported"])
            self.assertEqual(row["verification_status"], "Needs Verification")
            self.assertEqual(row["raw_sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())

    def test_isolated_tool_environment_and_fixed_arguments_prevent_implicit_expansion(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"HTTP_PROXY": "http://outside", "NUCLEI_TOKEN": "credential"}):
            environment = plugins.isolated_environment(temporary)
            self.assertNotIn("HTTP_PROXY", environment)
            self.assertNotIn("NUCLEI_TOKEN", environment)
            self.assertEqual(environment["DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD"], "true")
            command = plugins.build_argv("nuclei", "nuclei", "http://127.0.0.1/", temporary, "reviewed.yaml")
            self.assertTrue({"-ni", "-dr", "-duc", "-no-stdin", "-t"} <= set(command))
            self.assertNotIn("-headless", command)
            command = plugins.build_argv("testssl", "testssl.sh", "https://127.0.0.1/", temporary)
            self.assertIn("none", command)
            self.assertNotIn("--phone-out", command)

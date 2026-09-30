import tempfile
import unittest
import io
import json
import threading
from contextlib import redirect_stderr, redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from vulcanary.cli import main
from vulcanary.dashboard import DashboardState, make_handler
from vulcanary.vex import NoVexStatements, openvex_document, write_openvex


class VexTests(unittest.TestCase):
    def test_empty_export_is_explicit_and_never_claims_safety(self) -> None:
        with self.assertRaises(NoVexStatements):
            openvex_document("empty", [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, provenance = root / "vex.json", root / "provenance.json"
            error = io.StringIO()
            with redirect_stderr(error), redirect_stdout(io.StringIO()):
                result = main([str(root), "--offline", "--openvex", str(output), "--provenance", str(provenance)])
            self.assertEqual(result, 0)
            self.assertFalse(output.exists())
            self.assertIn("OpenVEX export skipped", error.getvalue())
            self.assertEqual(json.loads(provenance.read_text(encoding="utf-8"))["subject"], [])
            output.write_text("previous output", encoding="utf-8")
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                result = main([str(root), "--offline", "--openvex", str(output)])
            self.assertEqual(result, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous output")

    def test_dashboard_empty_export_has_typed_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = DashboardState(root / "history.json")
            state.control_token = "contract-test"
            state.repositories[str(root)] = SimpleNamespace(name="empty", findings=[])
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(f"http://127.0.0.1:{server.server_port}/api/repositories/openvex?" + urlencode({"repository": str(root)}), headers={"X-Vulcanary-Control": "contract-test"})
                with self.assertRaises(HTTPError) as raised:
                    urlopen(request)
                self.assertEqual(raised.exception.code, 422)
                response = json.loads(raised.exception.read())
                self.assertEqual(response["code"], "no_vex_statements")
                self.assertEqual(response["warnings"][0]["code"], "openvex_no_statements")
                self.assertTrue(response["warnings"][0]["action"])
                raised.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_reports_observed_dependencies_as_affected_without_claiming_safety(self) -> None:
        finding = {"rule_id": "SCA-GHSA-demo", "category": "dependency", "metadata": {"advisory": "GHSA-demo", "package": "demo", "current_version": "1.0.0", "ecosystem": "npm"}}
        document = openvex_document("demo-repo", [finding, finding])
        self.assertEqual(len(document["statements"]), 1)
        statement = document["statements"][0]
        self.assertEqual(statement["status"], "affected")
        self.assertIn("does not prove safety", statement["status_notes"])
        ecosystem_findings = [
            {"rule_id": "SCA-GO-demo", "category": "dependency", "metadata": {"advisory": "GO-demo", "package": "github.com/gin-gonic/gin", "current_version": "1.9.0", "ecosystem": "Go"}},
            {"rule_id": "SCA-RUST-demo", "category": "dependency", "metadata": {"advisory": "RUST-demo", "package": "regex", "current_version": "1.5.1", "ecosystem": "crates.io"}},
            {"rule_id": "SCA-PHP-demo", "category": "dependency", "metadata": {"advisory": "PHP-demo", "package": "symfony/http-foundation", "current_version": "5.4.0", "ecosystem": "Packagist"}},
            {"rule_id": "SCA-RUBY-demo", "category": "dependency", "metadata": {"advisory": "RUBY-demo", "package": "rack", "current_version": "2.2.3", "ecosystem": "RubyGems"}},
        ]
        products = [item["products"][0]["@id"] for item in openvex_document("demo-repo", ecosystem_findings)["statements"]]
        self.assertEqual(products, [
            "pkg:golang/github.com/gin-gonic/gin@1.9.0", "pkg:cargo/regex@1.5.1",
            "pkg:composer/symfony/http-foundation@5.4.0", "pkg:gem/rack@2.2.3",
        ])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "vex.json"
            write_openvex(document, output)
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))

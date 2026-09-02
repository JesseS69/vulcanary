import unittest
import json
import tempfile
import threading
from email.message import Message
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from vulcanary.dashboard import DashboardState, make_handler
from vulcanary.models import Finding, Severity
from vulcanary.webaudit import audit_web_target


class Response:
    def __init__(self, url: str, headers: Message) -> None:
        self.url, self.headers = url, headers
    def geturl(self): return self.url
    def __enter__(self): return self
    def __exit__(self, *args): return False


class Opener:
    def __init__(self, response): self.response = response
    def open(self, request, timeout): return self.response


class WebAuditTests(unittest.TestCase):
    def test_dashboard_adds_authorized_web_findings_to_the_queue(self) -> None:
        finding = Finding("DAST-CSP", "CSP missing", "CSP missing", Severity.MEDIUM, "dast", "web-target/example.test", 1, scanner="vulcanary-web")
        state = DashboardState()
        with patch("vulcanary.dashboard.audit_web_target", return_value=[finding]):
            audit = state.audit_web("https://example.test/health", "example.test")
        snapshot = state.snapshot()
        self.assertEqual(audit["request_count"], 1)
        self.assertEqual(snapshot["web_audits"][0]["host"], "example.test")
        self.assertEqual(snapshot["findings"][0]["repository"], "web:example.test")
        self.assertFalse(snapshot["findings"][0]["metadata"]["fix_eligible"])

    def test_dashboard_persists_web_results_without_response_content(self) -> None:
        finding = Finding("DAST-CSP", "CSP missing", "CSP missing", Severity.MEDIUM, "dast", "web-target/example.test", 1, scanner="vulcanary-web")
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "state.json"
            state = DashboardState(history)
            with patch("vulcanary.dashboard.audit_web_target", return_value=[finding]):
                state.audit_web("https://example.test/", "example.test")
            restored = DashboardState(history).snapshot()
        self.assertEqual(restored["web_audits"][0]["request_count"], 1)
        self.assertNotIn("response", json.dumps(restored["web_audits"]))

    def test_dashboard_web_endpoint_enforces_exact_authorization(self) -> None:
        state = DashboardState()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_port}/api/web-audit"
        try:
            request = Request(endpoint, data=json.dumps({"url": "https://example.test", "authorized_host": "other.test"}).encode(), method="POST", headers={"Content-Type": "application/json"})
            with self.assertRaises(HTTPError) as rejected:
                urlopen(request, timeout=5)
            self.assertEqual(rejected.exception.code, 400)
            rejected.exception.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_requires_exact_authorized_hostname(self) -> None:
        with self.assertRaises(ValueError):
            audit_web_target("https://example.test", "other.test")

    def test_passive_header_and_cookie_findings(self) -> None:
        headers = Message()
        headers["Set-Cookie"] = "session=redacted; Path=/"
        with patch("vulcanary.webaudit.build_opener", return_value=Opener(Response("https://example.test/", headers))):
            findings = audit_web_target("https://example.test/", "example.test")
        rules = {item.rule_id for item in findings}
        self.assertIn("DAST-HSTS", rules)
        self.assertIn("DAST-COOKIE-SECURE", rules)
        self.assertTrue(all(item.metadata["mode"] == "passive" for item in findings))

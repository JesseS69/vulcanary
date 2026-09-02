import unittest
from email.message import Message
from unittest.mock import patch

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

import unittest

from vulcanary.tickets import finding_ticket, ticket_csv, ticket_markdown


class TicketTests(unittest.TestCase):
    def test_ticket_excludes_source_and_evidence(self) -> None:
        finding = {
            "title": "Unsafe call", "severity": "high", "repository": "demo", "repository_path": "C:/secret/demo",
            "rule_id": "CODE-DEMO", "category": "sast", "scanner": "builtin", "path": "src/app.py", "line": 7,
            "description": "Unsafe call detected.", "remediation": "Use the safe API.", "fingerprint": "a" * 20,
            "evidence": "secret-value", "metadata": {"policy": {"owner": "security"}},
        }
        ticket = finding_ticket(finding)
        encoded = str(ticket)
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn("C:/secret", encoded)
        self.assertTrue(ticket["source_excluded"])
        markdown = ticket_markdown(ticket)
        self.assertIn("src/app.py:7", markdown)
        self.assertIn("Source code, evidence, credentials", markdown)
        csv_text = ticket_csv(ticket)
        self.assertIn("src/app.py", csv_text)
        self.assertNotIn("secret-value", csv_text)
        self.assertNotIn("C:/secret", csv_text)


if __name__ == "__main__":
    unittest.main()

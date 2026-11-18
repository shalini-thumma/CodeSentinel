import json
import unittest
from unittest.mock import patch

from codesentinel.ai_reviewer import redact_snippet, review_findings
from codesentinel.models import Finding, RepositoryInfo, RepositorySnapshot, Severity
from codesentinel.report_generator import build_report, html_report, json_report


class ReportTests(unittest.TestCase):
    def test_score_is_determined_by_findings_and_html_escapes_content(self):
        snapshot = RepositorySnapshot(
            repository=RepositoryInfo(
                name="demo", owner="sample", url="https://github.com/sample/demo", default_branch="main"
            ),
            files={"app.py": ""},
        )
        finding = Finding(
            rule_id="SEC-DEMO", category="security", severity=Severity.HIGH,
            title="<script>alert(1)</script>", file="app.py", line=3,
            explanation="A potential issue.", recommendation="Fix safely.",
        )
        report = build_report(snapshot, [finding])

        self.assertEqual(report.health_score, 88)
        self.assertEqual(report.severity_counts["High"], 1)
        self.assertNotIn("<script>", html_report(report))
        self.assertIn("SEC-DEMO", json_report(report))

    def test_redacts_credentials_and_disabled_ai_keeps_static_findings(self):
        text = 'DATABASE_PASSWORD = "sentinel_secret_123"\nkey = "ghp_abcdefghijklmnopqrstuvwxyz123456"'
        redacted = redact_snippet(text)
        self.assertNotIn("sentinel_secret_123", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", redacted)
        finding = Finding(
            rule_id="SEC-DEMO", category="security", severity=Severity.MEDIUM,
            title="Potential issue", file="app.py", line=1,
            explanation="Static explanation", recommendation="Static fix",
        )
        findings, reviewed, warning = review_findings({"app.py": text}, [finding])
        self.assertEqual(findings, [finding])
        self.assertFalse(reviewed)
        self.assertIsNone(warning)

    def test_ai_request_is_redacted_and_response_cannot_change_severity(self):
        secret = "sentinel_secret_123"
        source = f'PASSWORD = "{secret}"\nprint("work")\n'
        finding = Finding(
            rule_id="SEC-DEMO", category="security", severity=Severity.HIGH,
            title="Potential secret", file="app.py", line=1,
            explanation="Static explanation", recommendation="Static fix",
        )
        provider_response = json.dumps({
            "choices": [{"message": {"content": json.dumps({"reviews": [{
                "id": "F1", "explanation": f"Credential {secret} must be rotated.",
                "recommendation": "Use a secret store.", "related": [],
            }]})}}]
        }).encode("utf-8")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return provider_response

        captured = {}

        def fake_open(request, timeout):
            captured["body"] = request.data.decode("utf-8")
            self.assertEqual(timeout, 20)
            return FakeResponse()

        with patch.dict("os.environ", {"CODESENTINEL_AI_API_KEY": "test-key"}), patch(
            "codesentinel.ai_reviewer.urllib.request.urlopen", side_effect=fake_open
        ):
            findings, reviewed, warning = review_findings({"app.py": source}, [finding])

        self.assertNotIn(secret, captured["body"])
        self.assertTrue(reviewed)
        self.assertIsNone(warning)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertNotIn(secret, findings[0].explanation)


if __name__ == "__main__":
    unittest.main()
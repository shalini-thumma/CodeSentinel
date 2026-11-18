import unittest
from pathlib import Path

from codesentinel.security_scanner import scan_security


FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class SecurityScannerTests(unittest.TestCase):
    def test_detects_secret_sql_interpolation_and_shell_command(self):
        findings = scan_security({"vulnerable.py": read_fixture("vulnerable.py")})
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("SEC-HARDCODED-SECRET", rule_ids)
        self.assertIn("SEC-SQL-FSTRING", rule_ids)
        self.assertIn("SEC-COMMAND-SHELL", rule_ids)
        self.assertTrue(all("sentinel_demo_password_123" not in str(finding.model_dump()) for finding in findings))

    def test_clean_parameterized_query_has_no_builtin_findings(self):
        findings = scan_security({"clean.py": read_fixture("clean.py")})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
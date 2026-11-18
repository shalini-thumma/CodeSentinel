import unittest

from codesentinel.analysis_service import analyze_snapshot
from codesentinel.models import RepositoryInfo, RepositorySnapshot


class AnalysisServiceTests(unittest.TestCase):
    def test_runs_all_static_modules_against_a_snapshot(self):
        snapshot = RepositorySnapshot(
            repository=RepositoryInfo(
                name="demo", owner="sample", url="https://github.com/sample/demo", default_branch="main"
            ),
            files={
                "app.py": 'PASSWORD = "sentinel_demo_password_123"\n'
                "def unfinished():\n    pass\n",
                "README.md": "Demo\n",
                "tests/test_app.py": "def test_app(): pass\n",
                "requirements.txt": "",
            },
        )

        report = analyze_snapshot(snapshot)
        rule_ids = {finding.rule_id for finding in report.findings}

        self.assertIn("SEC-HARDCODED-SECRET", rule_ids)
        self.assertIn("GAP-EMPTY-FUNCTION", rule_ids)
        self.assertEqual(report.repository.name, "demo")
        self.assertFalse(report.ai_reviewed)
        self.assertLess(report.health_score, 100)

    def test_clean_project_has_no_findings(self):
        snapshot = RepositorySnapshot(
            repository=RepositoryInfo(
                name="clean-demo", owner="sample", url="https://github.com/sample/clean-demo", default_branch="main"
            ),
            files={
                "app.py": "def find_account(connection, account_id):\n"
                "    return connection.execute('SELECT id FROM accounts WHERE id = ?', (account_id,)).fetchone()\n",
                "README.md": "Clean demo\n",
                "tests/test_app.py": "def test_app():\n    assert True\n",
                "requirements.txt": "",
            },
        )

        report = analyze_snapshot(snapshot)

        self.assertEqual(report.findings, [])
        self.assertEqual(report.health_score, 100)


if __name__ == "__main__":
    unittest.main()
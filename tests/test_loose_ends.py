import unittest

from codesentinel.loose_ends_detector import detect_loose_ends
from codesentinel.models import RepositoryInfo, RepositorySnapshot, Severity
from codesentinel.repository_analyzer import build_inventory


class LooseEndsTests(unittest.TestCase):
    def test_detects_unused_import_local_and_bare_except(self):
        snapshot = RepositorySnapshot(
            repository=RepositoryInfo(
                name="demo", owner="sample", url="https://github.com/sample/demo", default_branch="main"
            ),
            files={
                "app.py": "import json\n"
                "def process(value):\n"
                "    unused_value = value\n"
                "    try:\n"
                "        return int(value)\n"
                "    except:\n"
                "        return None\n",
                "README.md": "Demo\n",
                "tests/test_app.py": "def test_process(): pass\n",
                "requirements.txt": "",
            },
        )
        findings = detect_loose_ends(snapshot, build_inventory(snapshot))
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("LOOSE-UNUSED-IMPORT", rule_ids)
        self.assertIn("LOOSE-UNUSED-VARIABLE", rule_ids)
        self.assertIn("LOOSE-BARE-EXCEPT", rule_ids)
        self.assertFalse(any(f.rule_id.startswith("LOOSE-NO-") for f in findings))

    def test_reports_absent_project_signals_as_informational(self):
        snapshot = RepositorySnapshot(
            repository=RepositoryInfo(
                name="demo", owner="sample", url="https://github.com/sample/demo", default_branch="main"
            ),
            files={"app.js": "export const value = 1;\n"},
        )
        findings = detect_loose_ends(snapshot, build_inventory(snapshot))
        repo_signals = [finding for finding in findings if finding.rule_id.startswith("LOOSE-NO-")]

        self.assertEqual(len(repo_signals), 3)
        self.assertTrue(all(finding.severity == Severity.INFORMATIONAL for finding in repo_signals))


if __name__ == "__main__":
    unittest.main()
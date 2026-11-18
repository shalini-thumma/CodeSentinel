import unittest
from pathlib import Path

from codesentinel.slop_detector import detect_slop


FIXTURES = Path(__file__).parent / "fixtures"


class SlopDetectorTests(unittest.TestCase):
    def test_detects_duplicate_import_and_repeated_code(self):
        source = (FIXTURES / "slop.py").read_text(encoding="utf-8")
        findings = detect_slop({"slop.py": source})
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("SLOP-DUPLICATE-IMPORT", rule_ids)
        self.assertIn("SLOP-DUPLICATE-BLOCK", rule_ids)

    def test_clean_code_has_no_quality_findings(self):
        source = (FIXTURES / "clean.py").read_text(encoding="utf-8")
        self.assertEqual(detect_slop({"clean.py": source}), [])


if __name__ == "__main__":
    unittest.main()
import unittest
from pathlib import Path

from codesentinel.gap_detector import detect_gaps


FIXTURES = Path(__file__).parent / "fixtures"


class GapDetectorTests(unittest.TestCase):
    def test_detects_concrete_gaps_and_markers(self):
        source = (FIXTURES / "gaps.py").read_text(encoding="utf-8")
        findings = detect_gaps({"gaps.py": source})
        rule_ids = [finding.rule_id for finding in findings]

        self.assertIn("GAP-EMPTY-FUNCTION", rule_ids)
        self.assertIn("GAP-TODO", rule_ids)
        self.assertIn("GAP-NOT-IMPLEMENTED", rule_ids)
        empty_finding = next(finding for finding in findings if finding.rule_id == "GAP-EMPTY-FUNCTION")
        self.assertEqual(empty_finding.line, 10)
        self.assertEqual(sum(f.rule_id == "GAP-EMPTY-FUNCTION" for f in findings), 1)

    def test_ignores_abstract_methods(self):
        findings = detect_gaps({
            "port.py": "from abc import ABC, abstractmethod\n"
            "class Port(ABC):\n"
            "    @abstractmethod\n"
            "    def load(self):\n"
            "        pass\n"
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
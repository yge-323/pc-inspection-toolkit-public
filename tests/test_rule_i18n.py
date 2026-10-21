from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from locales.rule_translations import RULE_FINDINGS


RULE_FILES = (
    ROOT / "rules" / "windows_risk_rules.example.json",
    ROOT / "rules" / "platform_risk_rules.example.json",
)
RAW_TO_DISPLAY = {
    "name": "title",
    "title": "title",
    "condition_description": "description",
    "risk": "impact",
}
DISPLAY_FIELDS = {
    "title",
    "description",
    "precheck",
    "applicability",
    "impact",
    "recommendation",
    "rollback",
    "verification_checkpoint",
}
CJK = re.compile(r"[\u3400-\u9fff]")


class BuiltinRuleTranslationsTests(unittest.TestCase):
    def test_rule_ids_and_human_fields_match_both_examples(self) -> None:
        raw_rules = {}
        for path in RULE_FILES:
            payload = json.loads(path.read_text(encoding="utf-8"))
            for rule in payload["rules"]:
                raw_rules[rule["id"]] = rule

        self.assertEqual(set(RULE_FINDINGS), set(raw_rules))
        for rule_id, rule in raw_rules.items():
            expected = {
                RAW_TO_DISPLAY.get(key, key)
                for key, value in rule.items()
                if key in DISPLAY_FIELDS or key in RAW_TO_DISPLAY
                if isinstance(value, str)
            }
            self.assertEqual(set(RULE_FINDINGS[rule_id]), expected, rule_id)

    def test_pairs_retain_exact_source_and_have_both_languages(self) -> None:
        for path in RULE_FILES:
            payload = json.loads(path.read_text(encoding="utf-8"))
            for rule in payload["rules"]:
                translated = RULE_FINDINGS[rule["id"]]
                for raw_key, raw_text in rule.items():
                    display_key = RAW_TO_DISPLAY.get(raw_key, raw_key)
                    if display_key not in translated:
                        continue
                    pair = translated[display_key]
                    self.assertIsInstance(pair, tuple, (rule["id"], display_key))
                    self.assertEqual(len(pair), 2, (rule["id"], display_key))
                    self.assertTrue(all(isinstance(item, str) and item for item in pair))
                    source_index = 0 if CJK.search(raw_text) else 1
                    self.assertEqual(pair[source_index], raw_text, (rule["id"], display_key))
                    self.assertIsNotNone(CJK.search(pair[0]), (rule["id"], display_key, pair[0]))
                    self.assertIsNone(CJK.search(pair[1]), (rule["id"], display_key, pair[1]))


if __name__ == "__main__":
    unittest.main()

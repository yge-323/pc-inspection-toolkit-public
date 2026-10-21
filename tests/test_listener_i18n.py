from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from locales.listener_translations import LISTENER_FINDINGS


HUMAN_FIELDS = (
    "title",
    "impact",
    "recommendation",
    "rollback",
    "verification_checkpoint",
)
CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")


class ListenerTranslationTests(unittest.TestCase):
    def test_every_builtin_listener_rule_has_exact_chinese_source_and_english_pair(self) -> None:
        raw_path = ROOT / "rules" / "listener_knowledge.example.json"
        raw_rules = json.loads(raw_path.read_text(encoding="utf-8"))["rules"]
        self.assertEqual(len(raw_rules), 19)
        self.assertEqual(set(LISTENER_FINDINGS), {rule["id"] for rule in raw_rules})

        for rule in raw_rules:
            with self.subTest(rule_id=rule["id"]):
                source_fields = {key for key in HUMAN_FIELDS if isinstance(rule.get(key), str)}
                translated = LISTENER_FINDINGS[rule["id"]]
                self.assertEqual(set(translated), source_fields)
                self.assertNotIn("id", translated)
                self.assertNotIn("severity", translated)
                self.assertNotIn("source", translated)
                for field in source_fields:
                    chinese, english = translated[field]
                    self.assertEqual(chinese, rule[field])
                    self.assertTrue(english.strip())
                    self.assertIsNone(CJK.search(english), f"English translation contains CJK: {rule['id']}.{field}")

    def test_high_impact_recommendations_keep_review_approval_and_non_blocking_conditions(self) -> None:
        docker = LISTENER_FINDINGS["LISTENER_TCP_2375_REVIEW"]
        redis = LISTENER_FINDINGS["LISTENER_TCP_6379_REVIEW"]
        smb = LISTENER_FINDINGS["LISTENER_TCP_445_REVIEW"]
        memcached = LISTENER_FINDINGS["LISTENER_TCP_UDP_11211_REVIEW"]

        self.assertIn("cannot establish", docker["impact"][1])
        for condition in ("business owner", "maintenance window", "SSH", "mutual TLS", "Do not stop a service"):
            self.assertIn(condition, docker["recommendation"][1])
        for condition in ("full Redis version", "bind/ACL/authentication/TLS", "client sources", "business owner", "unknown version"):
            self.assertIn(condition, redis["recommendation"][1])
        self.assertIn("organizational policy", smb["recommendation"][1])
        self.assertNotIn("block", smb["recommendation"][1].casefold())
        self.assertIn("UDP listener", memcached["impact"][1])
        self.assertIn("cannot establish", memcached["impact"][1])
        self.assertIn("approval", memcached["recommendation"][1])
        self.assertIn("maintenance window", memcached["recommendation"][1])
        self.assertIn("Do not stop the service", memcached["recommendation"][1])


if __name__ == "__main__":
    unittest.main()

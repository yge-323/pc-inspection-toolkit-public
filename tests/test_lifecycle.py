from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from analyzers.lifecycle import DEFAULT_POLICY, analyze_lifecycle


class LifecycleAnalyzerTests(unittest.TestCase):
    def test_centOS7_and_rhel5_6_are_bound_to_collected_ids(self) -> None:
        cases = [
            ({"os_release.txt": 'ID="centos"\nVERSION_ID="7"\n'}, "CENTOS_LINUX_7", "2024-06-30"),
            ({"os_release.txt": 'ID="rhel"\nVERSION_ID="5.11"\n'}, "RHEL_5", "2017-03-31"),
            ({"os_release.txt": 'ID="rhel"\nVERSION_ID="6.10"\n'}, "RHEL_6", "2020-11-30"),
        ]
        for evidence, expected_id, end_date in cases:
            with self.subTest(expected_id=expected_id):
                findings, warnings = analyze_lifecycle({}, evidence)
                self.assertFalse(warnings)
                self.assertEqual(findings[0]["finding_id"], f"OS_LIFECYCLE_{expected_id}")
                self.assertEqual(findings[0]["evidence"]["normal_support_ended"], end_date)
                self.assertTrue(findings[0]["needs_human_review"])
                self.assertEqual(findings[0]["auto_fix"], "否")

    def test_windows_2008_r2_uses_version_to_disambiguate(self) -> None:
        base = "Caption=Microsoft Windows Server 2008 Standard\n"
        plain, _ = analyze_lifecycle({}, {"os_detail.txt": base + "Version=6.0.6002\n"})
        r2, _ = analyze_lifecycle({}, {"os_detail.txt": base.replace("Standard", "R2 Standard") + "Version=6.1.7601\n"})
        self.assertEqual(plain[0]["finding_id"], "OS_LIFECYCLE_WINDOWS_SERVER_2008")
        self.assertEqual(r2[0]["finding_id"], "OS_LIFECYCLE_WINDOWS_SERVER_2008_R2")

    def test_windows_caption_and_version_r2_contradiction_is_not_classified(self) -> None:
        findings, warnings = analyze_lifecycle(
            {}, {"os_detail.txt": "Caption=Windows Server 2008 R2 Standard\nVersion=6.0.6002\n"}
        )
        self.assertEqual(findings[0]["finding_id"], "OS_LIFECYCLE_COVERAGE_GAP")
        self.assertTrue(warnings)

    def test_unknown_modern_and_metadata_only_identity_remain_gaps(self) -> None:
        for target, evidence in [
            ({}, {"os_release.txt": 'ID="ubuntu"\nVERSION_ID="24.04"\n'}),
            ({"product": "CentOS Linux", "version": "7"}, {"os.txt": "Linux"}),
        ]:
            findings, warnings = analyze_lifecycle(target, evidence)
            self.assertEqual(findings[0]["finding_id"], "OS_LIFECYCLE_COVERAGE_GAP")
            self.assertTrue(warnings)

    def test_contradictory_declared_metadata_produces_gap_only(self) -> None:
        findings, warnings = analyze_lifecycle(
            {"product": "Windows Server 2008 R2", "version": "6.1"},
            {"os_detail.txt": "Caption=Windows Server 2008\nVersion=6.0\n"},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "OS_LIFECYCLE_COVERAGE_GAP")
        self.assertIn("CONTRADICTION", warnings[0])

    def test_fixed_product_aliases_are_accepted_and_cross_family_conflicts_are_gaps(self) -> None:
        evidence = {"os_release.txt": 'ID="centos"\nVERSION_ID="7.9"\n'}
        matched, _ = analyze_lifecycle({"os_family": "linux", "product": "CentOS", "version": "7.9"}, evidence)
        self.assertEqual(matched[0]["finding_id"], "OS_LIFECYCLE_CENTOS_LINUX_7")
        conflict, warnings = analyze_lifecycle({"os_family": "windows", "product": "CentOS", "version": "7"}, evidence)
        self.assertEqual(conflict[0]["finding_id"], "OS_LIFECYCLE_COVERAGE_GAP")
        self.assertIn("CONTRADICTION", warnings[0])

    def test_conflicting_collected_os_families_do_not_select_first_match(self) -> None:
        findings, warnings = analyze_lifecycle({}, {
            "os_release.txt": 'ID="centos"\nVERSION_ID="7"\n',
            "os_detail.txt": "Caption=Windows Server 2008 R2 Standard\nVersion=6.1.7601\n",
        })
        self.assertEqual(findings[0]["finding_id"], "OS_LIFECYCLE_COVERAGE_GAP")
        self.assertIn("EVIDENCE_CONTRADICTION", warnings[0])

    def test_policy_missing_or_malformed_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.json"
            self.assertEqual(analyze_lifecycle({}, {}, missing), ([], ["OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE"]))
            invalid = Path(temporary) / "invalid.json"
            invalid.write_text(json.dumps({"schema_version": True, "rules_version": "x", "as_of": "2026-10-03", "records": []}), encoding="utf-8")
            self.assertEqual(analyze_lifecycle({}, {}, invalid), ([], ["OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE"]))

    def test_default_policy_has_unique_identities_and_paid_entitlement_is_unknown(self) -> None:
        policy = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
        identities = [record["identity"] for record in policy["records"]]
        self.assertEqual(len(identities), len(set(identities)))
        findings, _ = analyze_lifecycle({}, {"os_release.txt": 'ID="rhel"\nVERSION_ID="6.10"\n'})
        self.assertEqual(findings[0]["evidence"]["paid_extended_entitlement"], "unknown; not collected or verified")
        self.assertEqual(findings[0]["evidence"]["extended_support_ended"], "2024-06-30")

    def test_valid_policy_snapshot_date_can_advance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            policy = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
            policy["as_of"] = "2026-10-04"
            path.write_text(json.dumps(policy), encoding="utf-8")
            findings, warnings = analyze_lifecycle({}, {"os_release.txt": 'ID="centos"\nVERSION_ID="7"\n'}, path)
            self.assertFalse(warnings)
            self.assertEqual(findings[0]["evidence"]["policy_as_of"], "2026-10-04")


if __name__ == "__main__":
    unittest.main()

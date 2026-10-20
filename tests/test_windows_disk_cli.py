from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _manifest(root: Path, drives: list[tuple[str, int, int]]) -> dict:
    from analyzers.evidence_analyzer import REQUIRED_FILES

    files = {
        "os.txt": "Windows Server 2008 R2\n",
        "os_detail.txt": "Caption=Microsoft Windows Server 2008 R2\nVersion=6.1.7601\n",
        "cpu.txt": "Name=Fixture CPU\nLogicalProcessors=4\n",
        "memory.txt": "TotalBytes=8589934592\n",
        "graphics.txt": "No graphics adapter details collected.\n",
        "disks.txt": "".join(
            f"Drive={drive};FileSystem=NTFS;SizeBytes={size};FreeBytes={free};FreePercent={free / size * 100:.3f}\n"
            for drive, size, free in drives
        ),
        "processes.txt": "ProcessId=1;Name=System;ParentProcessId=0;WorkingSetBytes=4096;ThreadCount=1\n",
        "services.txt": "Name=FixtureService;State=Running;StartMode=Manual;PathName=C:\\Windows\\System32\\svchost.exe\n",
        "listeners.txt": "NO_LISTENERS\n",
        "firewall.txt": "FirewallProfile=DomainProfile;Enabled=1\n",
        "privilege.txt": "Privilege=ordinary\n",
        "accounts.txt": "AdministratorMemberCount=2\nAccountSummary=collected\n",
        "startup_items.txt": "RecordCount=0\nStartupSummary=collected\n",
        "security_status.txt": "\n".join([
            "RdpDisabled=1", "RdpNlaRequired=1", "Smb1ExplicitValue=0",
            "AutoAdminLogonEnabled=0", "GuestEnabled=False",
            "MinimumPasswordLength=12", "PasswordComplexity=1", "LockoutBadCount=5",
            "FirewallProfile=DomainProfile;Enabled=1;DefaultInboundAction=0",
            "FirewallProfile=StandardProfile;Enabled=1;DefaultInboundAction=0",
            "FirewallProfile=PublicProfile;Enabled=1;DefaultInboundAction=0",
        ]) + "\n",
    }
    required = REQUIRED_FILES["windows"]
    assert set(files) == required
    items = []
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
        items.append({"path": name, "status": "collected", "exit_code": 0, "reason": ""})
    return {
        "project_alias": "fixture-project",
        "asset_alias": "fixture-asset",
        "bundle_id": "fixture-" + root.name,
        "target": {
            "os_family": "windows", "product": "Windows Server 2008 R2",
            "version": "6.1.7601", "architecture": "x64", "scope": "basic",
        },
        "items": items,
    }


def _write_analysis(root: Path, name: str, drives: list[tuple[str, int, int]]) -> Path:
    from analyzers.evidence_analyzer import analyze_evidence
    from reports.unified import write_reports

    evidence_root = root / f"evidence-{name}"
    evidence_root.mkdir()
    manifest = _manifest(evidence_root, drives)
    result = analyze_evidence(evidence_root, manifest)
    assert result.status == "OK", result.warnings + result.errors
    finding_ids = [item["finding_id"] for item in result.findings]
    assert len(finding_ids) == len(set(finding_ids)), finding_ids
    rules = result.config_evidence
    rules_sha = hashlib.sha256(json.dumps(rules, sort_keys=True).encode("utf-8")).hexdigest()
    metadata = {
        "project_alias": manifest["project_alias"],
        "asset_alias": manifest["asset_alias"],
        "bundle_id": manifest["bundle_id"],
        "target_identity": manifest["target"],
        "rules_version": "fixture-windows-rules-v1",
        "rules_sha256": rules_sha,
    }
    outputs = write_reports(root / f"reports-{name}", result, metadata)
    assert outputs["html"].is_file()
    return outputs["json"]


def test_two_volume_recovery_survives_real_compare_and_codex_export_cli(cli_executable: Path | None = None) -> None:
    gb = 1024 ** 3
    if cli_executable is None:
        cli_command = [sys.executable, "-B", str(ROOT / "inspection_cli.py")]
    else:
        cli_command = [str(cli_executable)]
    with tempfile.TemporaryDirectory(prefix="pcit-disk-cli-") as temporary:
        root = Path(temporary)
        before = _write_analysis(root, "before", [("C:", 100 * gb, 9 * gb), ("D:", 100 * gb, 5 * gb)])
        after = _write_analysis(root, "after", [("C:", 100 * gb, 20 * gb), ("D:", 100 * gb, 5 * gb)])

        comparison_path = root / "comparison.json"
        comparison = subprocess.run(
            [*cli_command, "compare", str(before), str(after),
             "--output", str(comparison_path)],
            cwd=ROOT, check=False, capture_output=True, text=True, encoding="utf-8", timeout=45,
        )
        assert comparison.returncode == 0, comparison.stderr or comparison.stdout
        compared = json.loads(comparison_path.read_text(encoding="utf-8"))
        assert compared["status"] == "OK"
        states = {item["finding_id"]: item["state"] for item in compared["items"]}
        assert states["WIN_DISK_LOW_SPACE:C:"] == "resolved"
        assert states["WIN_DISK_LOW_SPACE:D:"] == "still_present"

        codex_path = root / "codex-export.json"
        exported = subprocess.run(
            [*cli_command, "codex-export", str(after),
             "--output", str(codex_path)],
            cwd=ROOT, check=False, capture_output=True, text=True, encoding="utf-8", timeout=45,
        )
        assert exported.returncode == 0, exported.stderr or exported.stdout
        handoff = json.loads(codex_path.read_text(encoding="utf-8"))
        assert handoff["status"] == "OK"
        assert "WIN_DISK_LOW_SPACE:D:" in {item["finding_id"] for item in handoff["findings"]}


def test_unknown_or_conflicting_volume_identity_becomes_a_gap() -> None:
    from analyzers.windows_disk_rules import analyze_windows_disk_facts, parse_native_disk_facts
    from analyzers.evidence_analyzer import load_windows_risk_registry

    rules, evidence = load_windows_risk_registry(ROOT / "rules" / "windows_risk_rules.example.json")
    assert rules is not None and evidence["status"] == "loaded"
    gb = 1024 ** 3
    unknown, unknown_gaps = parse_native_disk_facts(
        f"Drive=Volume 1;FileSystem=NTFS;SizeBytes={100 * gb};FreeBytes={5 * gb};FreePercent=5\n"
    )
    assert any(item.startswith("WINDOWS_DISK_VOLUME_ID_UNKNOWN:") for item in unknown_gaps)
    assert analyze_windows_disk_facts(unknown, rules) == []

    conflict, conflict_gaps = parse_native_disk_facts("\n".join([
        f"Drive=C:;FileSystem=NTFS;SizeBytes={100 * gb};FreeBytes={5 * gb};FreePercent=5",
        f"Drive=C:;FileSystem=NTFS;SizeBytes={200 * gb};FreeBytes={5 * gb};FreePercent=2.5",
    ]) + "\n")
    assert "WINDOWS_DISK_VOLUME_ID_CONFLICT:C:" in conflict_gaps
    assert analyze_windows_disk_facts(conflict, rules) == []


def test_analysis_loader_still_rejects_duplicate_finding_ids() -> None:
    from inspection_cli import _load_analysis

    with tempfile.TemporaryDirectory(prefix="pcit-duplicate-id-") as temporary:
        path = Path(temporary) / "duplicate.json"
        path.write_text(json.dumps({
            "status": "OK", "metadata": {}, "config_evidence": {}, "warnings": [], "errors": [],
            "findings": [{"finding_id": "DUPLICATE", "evidence": {}}, {"finding_id": "DUPLICATE", "evidence": {}}],
        }), encoding="utf-8")
        try:
            _load_analysis(path)
        except ValueError as exc:
            assert "duplicate Finding IDs" in str(exc)
        else:
            raise AssertionError("Duplicate Finding IDs must remain rejected.")


if __name__ == "__main__":
    test_two_volume_recovery_survives_real_compare_and_codex_export_cli()
    test_unknown_or_conflicting_volume_identity_becomes_a_gap()
    test_analysis_loader_still_rejects_duplicate_finding_ids()
    print("Windows disk CLI integration tests passed.")

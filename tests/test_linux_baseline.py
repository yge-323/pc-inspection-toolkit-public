from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzers.linux_baseline import analyze_linux_baseline


def test_ssh_root_and_empty_password_findings() -> None:
    findings, gaps = analyze_linux_baseline({
        "accounts.txt": "TOTAL_ACCOUNTS=12\nUID0_COUNT=2\nEMPTY_PASSWORD_COUNT=1\nSHADOW_READABLE=yes\n",
        "security_status.txt": (
            "SSHD_CONFIG_SOURCE=present\n"
            "SSH_PERMIT_ROOT_LOGIN=yes\n"
            "SSH_PERMIT_EMPTY_PASSWORDS=yes\n"
            "PASS_MAX_DAYS=99999\n"
            "PASS_MIN_LEN=5\n"
        ),
    })
    ids = {item["finding_id"] for item in findings}
    assert "LNX_MULTIPLE_UID0_ACCOUNTS" in ids
    assert "LNX_EMPTY_PASSWORD_ACCOUNTS" in ids
    assert "LNX_SSH_ROOT_LOGIN_PERMITTED" in ids
    assert "LNX_SSH_EMPTY_PASSWORDS_PERMITTED" in ids
    assert "LNX_PASSWORD_MAX_DAYS_WEAK" in ids
    assert "LNX_PASSWORD_MIN_LEN_WEAK" in ids
    assert not gaps


def test_missing_summaries_are_gaps_not_findings() -> None:
    findings, gaps = analyze_linux_baseline({})
    assert findings == []
    assert "LINUX_ACCOUNT_SUMMARY_MISSING" in gaps
    assert "LINUX_SECURITY_SUMMARY_MISSING" in gaps


if __name__ == "__main__":
    test_ssh_root_and_empty_password_findings()
    test_missing_summaries_are_gaps_not_findings()
    print("Linux baseline tests passed.")

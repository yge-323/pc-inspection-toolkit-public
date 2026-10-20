from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def _kv(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _finding(finding_id: str, title: str, severity: str, description: str, evidence: dict[str, Any],
             recommendation: str, rollback: str, verification: str) -> dict[str, Any]:
    return {
        "finding_id": finding_id, "rule_id": finding_id, "title": title, "severity": severity,
        "category": "linux_baseline", "component": "linux", "description": description,
        "evidence": evidence, "applicability": "仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。",
        "impact": description, "recommendation": recommendation, "rollback": rollback,
        "verification_checkpoint": verification, "needs_human_review": True, "auto_fix": "否",
    }


def analyze_linux_baseline(text_by_name: dict[str, str]) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    gaps: list[str] = []
    accounts = next((v for k, v in text_by_name.items() if Path(k).name.casefold() == "accounts.txt"), "")
    security = next((v for k, v in text_by_name.items() if Path(k).name.casefold() == "security_status.txt"), "")
    if not accounts:
        gaps.append("LINUX_ACCOUNT_SUMMARY_MISSING")
    else:
        kv = _kv(accounts)
        if kv.get("COLLECTOR_STATUS", "").startswith("NOT_CHECKED"):
            gaps.append("LINUX_ACCOUNT_SUMMARY_NOT_CHECKED")
        else:
            try:
                uid0 = int(kv.get("UID0_COUNT", "-1"))
            except ValueError:
                uid0 = -1
                gaps.append("LINUX_UID0_COUNT_UNPARSED")
            if uid0 > 1:
                findings.append(_finding(
                    "LNX_MULTIPLE_UID0_ACCOUNTS", "存在多个 UID 0 账户", "Attention",
                    "采集摘要显示超过一个 UID 0 账户；不等于已确认后门，但需要核实。",
                    {"uid0_count": uid0, "source": "accounts.txt"},
                    "核对 /etc/passwd 中 UID 0 账户用途；非必要的 root 等价账户应在维护窗口按单位流程处理。",
                    "变更前备份 passwd/shadow 及相关授权；访问异常时按单位流程恢复。",
                    "复采账户摘要，确认 UID0_COUNT 与业务批准名单一致。",
                ))
            try:
                empty_pw = int(kv.get("EMPTY_PASSWORD_COUNT", "-1"))
            except ValueError:
                empty_pw = -1
                gaps.append("LINUX_EMPTY_PASSWORD_UNPARSED")
            if empty_pw > 0:
                findings.append(_finding(
                    "LNX_EMPTY_PASSWORD_ACCOUNTS", "存在空口令账户摘要线索", "Attention",
                    "在可读 shadow 的前提下，摘要显示空口令字段数量大于 0；需人工核实账户与锁定状态。",
                    {"empty_password_count": empty_pw, "shadow_readable": kv.get("SHADOW_READABLE", "unknown"),
                     "source": "accounts.txt"},
                    "以 root 核对空口令账户，确认是否锁定/禁用；按单位策略设置口令或锁定，禁止在未批准窗口批量改密。",
                    "变更前备份 shadow；登录异常时按单位流程恢复。",
                    "复采账户摘要，EMPTY_PASSWORD_COUNT 应为 0 或已解释的例外。",
                ))
            elif kv.get("SHADOW_READABLE", "").casefold() == "no":
                gaps.append("LINUX_SHADOW_NOT_READABLE")
    if not security:
        gaps.append("LINUX_SECURITY_SUMMARY_MISSING")
    else:
        kv = _kv(security)
        if kv.get("COLLECTOR_STATUS", "").startswith("NOT_CHECKED"):
            gaps.append("LINUX_SECURITY_SUMMARY_NOT_CHECKED")
        root_login = kv.get("SSH_PERMIT_ROOT_LOGIN", "").casefold()
        if root_login in {"yes", "without-password", "prohibit-password"}:
            findings.append(_finding(
                "LNX_SSH_ROOT_LOGIN_PERMITTED", "SSH 允许 root 相关登录", "Attention",
                f"sshd_config 摘要显示 PermitRootLogin={kv.get('SSH_PERMIT_ROOT_LOGIN')}。",
                {"permit_root_login": kv.get("SSH_PERMIT_ROOT_LOGIN"), "source": "security_status.txt"},
                "确认已有可用的普通运维账户与 sudo；审批后在维护窗口将 PermitRootLogin 设为 no，执行 sshd -t 后 reload，不断开现有会话直到验证完成。",
                "恢复 sshd_config 备份并 reload；验证管理通道。",
                "复采 security_status，确认 SSH_PERMIT_ROOT_LOGIN=no，并用普通账户验证登录。",
            ))
        elif "SSH_PERMIT_ROOT_LOGIN" not in kv and kv.get("SSHD_CONFIG_SOURCE") == "present":
            gaps.append("LINUX_SSH_PERMIT_ROOT_LOGIN_DEFAULT_UNCONFIRMED")
        elif kv.get("SSHD_CONFIG_SOURCE") == "not_readable":
            gaps.append("LINUX_SSHD_CONFIG_NOT_READABLE")
        if kv.get("SSH_PERMIT_EMPTY_PASSWORDS", "").casefold() in {"yes"}:
            findings.append(_finding(
                "LNX_SSH_EMPTY_PASSWORDS_PERMITTED", "SSH 允许空口令", "Attention",
                "sshd_config 摘要显示 PermitEmptyPasswords=yes。",
                {"permit_empty_passwords": kv.get("SSH_PERMIT_EMPTY_PASSWORDS"), "source": "security_status.txt"},
                "审批后改为 no，语法检查并 reload；同步检查账户空口令情况。",
                "恢复原配置并 reload。",
                "复采确认 SSH_PERMIT_EMPTY_PASSWORDS=no。",
            ))
        try:
            max_days = int(kv.get("PASS_MAX_DAYS", "-1"))
        except ValueError:
            max_days = -1
        if max_days == 99999 or (max_days > 365):
            findings.append(_finding(
                "LNX_PASSWORD_MAX_DAYS_WEAK", "口令最长有效期过长或未实质限制", "Warning",
                f"login.defs 摘要 PASS_MAX_DAYS={kv.get('PASS_MAX_DAYS')}。",
                {"pass_max_days": kv.get("PASS_MAX_DAYS"), "source": "security_status.txt"},
                "按单位口令策略评估；审批后调整 PASS_MAX_DAYS 并明确现有账户生效方式，避免未通知用户导致批量锁定。",
                "恢复 login.defs 备份；确认现有账户策略未意外收紧。",
                "复采 security_status 并抽查代表性账户的口令老化设置。",
            ))
        try:
            min_len = int(kv.get("PASS_MIN_LEN", "-1"))
        except ValueError:
            min_len = -1
        if 0 <= min_len < 8:
            findings.append(_finding(
                "LNX_PASSWORD_MIN_LEN_WEAK", "口令最小长度偏短", "Info",
                f"login.defs 摘要 PASS_MIN_LEN={kv.get('PASS_MIN_LEN')}；PAM 实际策略可能更严或更松。",
                {"pass_min_len": kv.get("PASS_MIN_LEN"), "source": "security_status.txt"},
                "核对 PAM/密码质量模块实际生效策略后再调整；不要只改 login.defs。",
                "恢复原配置。",
                "复采并与 PAM 配置交叉核实。",
            ))
    return findings, list(dict.fromkeys(gaps))

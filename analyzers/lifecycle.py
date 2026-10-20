from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "rules" / "os_lifecycle.example.json"
_REQUIRED_RECORD_KEYS = {
    "identity", "product", "version", "support_status", "normal_support_ended",
    "extended_support_ended", "sources",
}


def analyze_lifecycle(
    target: dict[str, Any],
    evidence_texts: dict[str, str],
    rules_path: Path = DEFAULT_POLICY,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Assess only lifecycle identities established by collected OS evidence."""
    policy, error = _load_policy(rules_path)
    if error:
        return [], [error]

    observations = _identify_os(evidence_texts)
    identities = {item[0] for item in observations}
    if len(identities) > 1:
        return [_gap_finding(
            "Collected OS evidence contains conflicting recognized product/version identities.",
            {"observations": [{"identity": i, "source": s, "product": p, "version": v}
                              for i, s, p, v in observations[:8]]},
        )], ["OS_LIFECYCLE_EVIDENCE_CONTRADICTION"]
    observed, source, observed_product, observed_version = observations[0] if observations else ("", "", "", "")
    if not observed:
        return [_gap_finding(
            "OS lifecycle coverage is unsupported or the collected OS identity is unrecognized.",
            {"source": source, "observed_product": observed_product, "observed_version": observed_version},
        )], ["OS_LIFECYCLE_COVERAGE_UNSUPPORTED"]

    declared_product = _bounded(target.get("product")) if isinstance(target, dict) else ""
    declared_version = _bounded(target.get("version")) if isinstance(target, dict) else ""
    declared_family = str(target.get("os_family") or "").strip().casefold() if isinstance(target, dict) else ""
    observed_family = "windows" if observed.startswith("windows-") else "linux"
    if ((declared_family in {"windows", "linux", "macos"} and declared_family != observed_family)
            or (_known(declared_product) and not _product_agrees(declared_product, observed_product))
            or (_known(declared_version) and not _version_agrees(declared_version, observed_version))):
        return [_gap_finding(
            "Declared target metadata conflicts with collected OS identity; lifecycle applicability is unresolved.",
            {"source": source, "observed_product": observed_product, "observed_version": observed_version,
             "declared_product": declared_product[:100], "declared_version": declared_version[:100]},
        )], ["OS_LIFECYCLE_IDENTITY_CONTRADICTION"]

    record = next((r for r in policy["records"] if r["identity"] == observed), None)
    if record is None:
        return [_gap_finding(
            "Collected OS identity has no lifecycle record in the validated policy; support is unknown.",
            {"source": source, "observed_product": observed_product, "observed_version": observed_version},
        )], ["OS_LIFECYCLE_RECORD_UNAVAILABLE"]
    if record["support_status"] != "ended":
        return [_gap_finding(
            "Lifecycle record is not classified as ended; this module makes no support-safety claim.",
            {"source": source, "observed_product": observed_product, "observed_version": observed_version},
        )], ["OS_LIFECYCLE_STATUS_UNSUPPORTED"]

    evidence = {
        "source": source,
        "observed_product": observed_product,
        "observed_version": observed_version,
        "policy_identity": record["identity"],
        "support_status": record["support_status"],
        "normal_support_ended": record["normal_support_ended"],
        "extended_support_ended": record["extended_support_ended"],
        "paid_extended_entitlement": "unknown; not collected or verified",
        "policy_as_of": policy["as_of"],
        "sources": record["sources"],
    }
    return [{
        "finding_id": f"OS_LIFECYCLE_{record['identity'].upper().replace('-', '_')}",
        "rule_id": "OS_LIFECYCLE_REVIEW",
        "title": f"{record['product']} {record['version']} 生命周期支持已结束",
        "severity": "Warning",
        "category": "Operating System Lifecycle",
        "component": "operating_system",
        "description": "Collected OS identity matches a lifecycle record whose normal support has ended. This is a version-support and migration-planning review, not a security finding or proof of exposure.",
        "evidence": evidence,
        "applicability": "仅依据所列采集事实和策略快照；付费扩展支持资格、合同和当前覆盖范围均未核实。",
        "impact": "常规支持结束意味着后续更新与支持范围可能受限；本结果不判断该设备是否存在漏洞或合规违规。",
        "recommendation": "人工盘点应用架构、驱动、外设、业务依赖和数据迁移；核对厂商/组织支持计划与备份恢复方案，在试点环境验证迁移，再安排维护窗口并复查业务、驱动及安全更新状态。国内合规要求应依据组织适用标准及实际国产操作系统测试确认，本工具不自动判定。",
        "rollback": "本发现不执行变更。迁移前形成经审批的备份和回退方案；试点或正式切换失败时按批准方案恢复原环境并复核业务。",
        "verification_checkpoint": "由资产负责人核对操作系统版本、扩展支持合同、目标平台兼容性、备份恢复演练和迁移后更新状态。",
        "needs_human_review": True,
        "auto_fix": "否",
    }], []


def _load_policy(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        policy = json.loads(raw.decode("utf-8"))
        if not isinstance(policy, dict) or set(policy) != {"schema_version", "rules_version", "as_of", "records"}:
            raise ValueError("root fields")
        if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
            raise ValueError("schema")
        if not isinstance(policy["rules_version"], str) or not policy["rules_version"].strip():
            raise ValueError("rules_version")
        if not isinstance(policy["as_of"], str) or date.fromisoformat(policy["as_of"]).isoformat() != policy["as_of"] or not isinstance(policy["records"], list) or not policy["records"]:
            raise ValueError("as_of or records")
        ids: set[str] = set()
        for record in policy["records"]:
            if not isinstance(record, dict) or set(record) != _REQUIRED_RECORD_KEYS:
                raise ValueError("record fields")
            identity = record["identity"]
            if not isinstance(identity, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity) or identity in ids:
                raise ValueError("identity")
            ids.add(identity)
            for key in ("product", "version", "support_status"):
                if not isinstance(record[key], str) or not record[key].strip():
                    raise ValueError(key)
            if record["support_status"] not in {"ended", "supported", "unknown"}:
                raise ValueError("support_status")
            for key in ("normal_support_ended", "extended_support_ended"):
                value = record[key]
                if value is not None and (not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value)):
                    raise ValueError(key)
            sources = record["sources"]
            if not isinstance(sources, list) or not sources or any(
                not isinstance(url, str) or urlparse(url).scheme != "https" or not urlparse(url).netloc
                for url in sources
            ) or len(sources) != len(set(sources)):
                raise ValueError("sources")
        return policy, ""
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
        return {}, "OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE"


def _identify_os(evidence: dict[str, str]) -> list[tuple[str, str, str, str]]:
    if not isinstance(evidence, dict):
        return []
    by_name = {Path(str(name).replace("\\", "/")).name.casefold(): text
               for name, text in evidence.items() if isinstance(text, str)}
    release = by_name.get("os_release.txt", "")
    fields = _parse_os_release(release)
    recognized: list[tuple[str, str, str, str]] = []
    if fields:
        os_id = fields.get("ID", "").strip('"\'').casefold()
        version = fields.get("VERSION_ID", "").strip('"\'')
        major = version.split(".", 1)[0]
        if os_id == "centos" and major == "7":
            recognized.append(("centos-linux-7", "os_release.txt", "CentOS Linux", version))
        if os_id == "rhel" and major in {"5", "6"}:
            recognized.append((f"rhel-{major}", "os_release.txt", "Red Hat Enterprise Linux Server", version))
    # The release banner is accepted only when its product and major version are explicit.
    for file_name, content in by_name.items():
        if file_name not in {"os.txt", "os_release.txt"}:
            continue
        match = re.search(r"(?im)^\s*(Red Hat Enterprise Linux Server|CentOS Linux)\s+release\s+(5|6|7)(?:\.(\d+))?\b", content)
        if match:
            product, major = match.group(1), match.group(2)
            identity = (f"rhel-{major}" if product.startswith("Red Hat") and major in {"5", "6"}
                        else "centos-linux-7" if product == "CentOS Linux" and major == "7" else "")
            if identity:
                recognized.append((identity, file_name, product, major))

    detail = by_name.get("os_detail.txt", "")
    caption = _field(detail, "Caption")
    version = _field(detail, "Version")
    version_match = re.fullmatch(r"(6\.[01])(?:\.\d+)*", version)
    if caption and "windows server 2008" in caption.casefold() and version_match:
        r2 = version_match.group(1) == "6.1"
        caption_r2 = bool(re.search(r"\bR2\b", caption, re.IGNORECASE))
        if r2 != caption_r2:
            return recognized
        product = "Windows Server 2008 R2" if r2 else "Windows Server 2008"
        identity = "windows-server-2008-r2" if r2 else "windows-server-2008"
        recognized.append((identity, "os_detail.txt", product, version))
    return recognized


def _parse_os_release(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*(ID|VERSION_ID)\s*=\s*(.*?)\s*$", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result


def _field(text: str, name: str) -> str:
    match = re.search(rf"(?im)^\s*{name}\s*[:=]\s*(.*?)\s*$", text)
    return match.group(1).strip().strip('"')[:160] if match else ""


def _known(value: str) -> bool:
    return value.strip().casefold() not in {"", "unknown", "not provided", "not_confirmed", "未确认", "未知"}


def _version_agrees(declared: str, observed: str) -> bool:
    value = declared.strip()
    return value == observed or value.startswith(observed + ".") or value.startswith(observed + " ")


def _product_agrees(declared: str, observed: str) -> bool:
    def normalize(value: str) -> str:
        folded = re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()
        aliases = {
            "centos": "centos linux",
            "rhel": "red hat enterprise linux server",
            "red hat enterprise linux": "red hat enterprise linux server",
        }
        folded = aliases.get(folded, folded)
        folded = re.sub(r"\bmicrosoft\b", "", folded)
        return " ".join(folded.split())
    return normalize(declared) == normalize(observed)


def _bounded(value: Any) -> str:
    return str(value or "")[:160]


def _gap_finding(description: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": "OS_LIFECYCLE_COVERAGE_GAP", "rule_id": "OS_LIFECYCLE_COVERAGE",
        "title": "操作系统生命周期覆盖未确认", "severity": "Warning",
        "category": "Operating System Lifecycle", "component": "operating_system",
        "description": description, "evidence": evidence,
        "applicability": "无法依据当前采集事实确认受支持或已结束支持；这不是安全通过结论。",
        "impact": "生命周期覆盖未知时，不能据此推断仍受支持或无风险。",
        "recommendation": "从可信采集结果核实操作系统产品与版本，并补充经审核的生命周期策略记录后重新分析。",
        "rollback": "本发现不执行变更。", "verification_checkpoint": "复核 OS 采集来源、产品和版本，并确认策略快照覆盖该身份。",
        "needs_human_review": True, "auto_fix": "否",
    }

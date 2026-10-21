from __future__ import annotations

import http.client
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from i18n import normalize_language

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
MAX_FINDINGS = 16


class LocalAIError(ValueError):
    pass


def _endpoint(raw: str) -> tuple[str, int, str, bool]:
    parts = urlsplit(raw)
    if parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment:
        raise LocalAIError("AI endpoint must be plain HTTP with no credentials, query, or fragment.")
    if not parts.hostname or parts.path not in {"", "/"}:
        raise LocalAIError("AI endpoint must be an origin URL without a path.")
    if "%" in parts.hostname:
        raise LocalAIError("Scoped IPv6 addresses are not allowed.")
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError as exc:
        raise LocalAIError("AI endpoint host must be a literal IP; hostnames and DNS are not allowed.") from exc
    ipv4_private = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
    ipv6_ula = ipaddress.ip_network("fc00::/7")
    in_private_range = (address.version == 4 and any(address in network for network in ipv4_private)) or (address.version == 6 and address in ipv6_ula)
    if not address.is_loopback and not in_private_range:
        raise LocalAIError("AI endpoint must be loopback or an RFC1918/IPv6 ULA private address.")
    return address.compressed, parts.port or 80, parts.netloc, address.is_loopback


def _request(host: str, port: int, method: str, path: str, payload: dict[str, Any] | None, timeout: float) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") if payload is not None else None
    if body is not None and len(body) > MAX_REQUEST_BYTES:
        raise LocalAIError("AI request exceeds size limit.")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "application/json", "Accept": "application/json", "Connection": "close"})
        response = conn.getresponse()
        if response.status != 200:
            raise LocalAIError(f"AI endpoint returned HTTP {response.status}; redirects and non-200 replies are rejected.")
        length = response.getheader("Content-Length")
        if length and int(length) > MAX_RESPONSE_BYTES:
            raise LocalAIError("AI response exceeds size limit.")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LocalAIError("AI response exceeds size limit.")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise LocalAIError("AI endpoint returned invalid JSON.") from exc
        if not isinstance(value, dict):
            raise LocalAIError("AI endpoint JSON root must be an object.")
        return value
    finally:
        conn.close()


def _safe_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    safe: list[dict[str, str]] = []
    for item in findings[:MAX_FINDINGS]:
        identity = str(item.get("finding_id", ""))[:100]
        title = str(item.get("title", ""))[:240]
        severity = str(item.get("severity", ""))[:30]
        category = str(item.get("category", ""))[:60]
        # No evidence values, paths, host/user data, configuration, raw bundle, or credentials.
        safe.append({"finding_id": identity, "title": _redact(title), "severity": severity, "category": category})
    return {"findings": safe, "instruction": "Explain findings as optional suggestions only. Return JSON object {suggestions:[{text,evidence_refs}]}. Do not invent facts, alter severity, or provide executable commands."}


def _suggestion_schema(finding_ids: list[str]) -> dict[str, Any]:
    allowed_ids = list(dict.fromkeys(finding_ids))
    refs_schema: dict[str, Any] = {"type": "string"}
    if allowed_ids:
        refs_schema["enum"] = allowed_ids
    return {
        "type": "object",
        "properties": {
            "suggestions": {
                "type": "array",
                "minItems": 1 if allowed_ids else 0,
                "maxItems": MAX_FINDINGS,
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "minLength": 1, "maxLength": 1000},
                        "evidence_refs": {"type": "array", "items": refs_schema,
                                          "minItems": 1 if allowed_ids else 0, "maxItems": len(allowed_ids)},
                    },
                    "required": ["text", "evidence_refs"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["suggestions"],
        "additionalProperties": False,
    }


def _redact(text: str) -> str:
    patterns = [r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+",
                r"(?i)(?:[A-Z]:\\Users\\|/home/|/Users/)[^\s]+",
                r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b"]
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def request_suggestions(*, provider: str, endpoint: str, model: str, findings: list[dict[str, Any]], cloud_disabled_acknowledged: bool = False, timeout: float = 15.0, language: str | None = None) -> dict[str, Any]:
    """Request an isolated, non-authoritative advisory. Never mutates findings or status."""
    locale = normalize_language(language)
    if provider != "ollama" or not model or len(model) > 128:
        raise LocalAIError("Provider/model selection is invalid.")
    if not cloud_disabled_acknowledged:
        raise LocalAIError("Confirm the Ollama cloud-disabled setting before sending any advisory request.")
    host, port, _netloc, loopback = _endpoint(endpoint)
    if provider == "ollama":
        version = _request(host, port, "GET", "/api/version", None, timeout)
        if not isinstance(version.get("version"), str) or not version["version"]:
            raise LocalAIError("Ollama version API is unsupported or malformed.")
        tags = _request(host, port, "GET", "/api/tags", None, timeout)
        models = tags.get("models")
        if not isinstance(models, list):
            raise LocalAIError("Ollama model list is unsupported or malformed.")
        selected = next((item for item in models if isinstance(item, dict) and item.get("name") == model and (item.get("model") == model or item.get("name") == model)), None)
        if selected is None:
            raise LocalAIError("Selected model is not present in Ollama's model list.")
        if selected.get("remote_host") or selected.get("remote_model"):
            raise LocalAIError("Ollama reports a remote model; AI request refused.")
        digest = selected.get("digest")
        details = selected.get("details")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest) or not isinstance(selected.get("size"), int) or selected["size"] <= 0 or not isinstance(details, dict) or not details.get("format"):
            raise LocalAIError("Ollama model metadata is insufficient to establish a local model record; AI request refused.")
        shown = _request(host, port, "POST", "/api/show", {"model": model}, timeout)
        if shown.get("remote_host") or shown.get("remote_model"):
            raise LocalAIError("Ollama model details report a remote model; AI request refused.")
        if not isinstance(shown.get("details"), dict) or not shown["details"].get("format"):
            raise LocalAIError("Ollama /api/show model metadata is missing or unsupported.")
        summary = _safe_summary(findings[:MAX_FINDINGS])
        allowed_refs = list(dict.fromkeys(item["finding_id"] for item in summary["findings"] if item["finding_id"]))
        if summary["findings"] and not allowed_refs:
            raise LocalAIError("AI advisory requires stable IDs for every sent Finding.")
        schema = _suggestion_schema(allowed_refs)
        example_text = ("Please manually verify applicability and remediation prerequisites."
                        if locale == "en-US" else "请人工核对该发现适用条件和整改前提。")
        example = ({"suggestions": [{"text": example_text, "evidence_refs": [allowed_refs[0]]}]}
                   if allowed_refs else {"suggestions": []})
        instruction = (
            "Respond in English with optional, non-authoritative review suggestions. Point out items for a person to verify, such as applicable versions, evidence sufficiency, and prerequisites. Output only a JSON object matching this JSON Schema: "
            if locale == "en-US" else
            "请用简体中文提供可选、非权威的人工复核建议，指出适用版本、证据充分性或实施前提等应由人工核对的方向。只输出符合此 JSON Schema 的 JSON 对象："
        )
        prompt = (instruction
                  + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
                  + (" Do not invent evidence, commands, severity, or risk status. Example: " if locale == "en-US" else "。不得编造证据、命令、严重等级或风险状态。格式示例：")
                  + json.dumps(example, ensure_ascii=False, separators=(",", ":")))
        payload = {"model": model, "stream": False,
                   "messages": [{"role": "system", "content": prompt},
                                {"role": "user", "content": json.dumps(summary, ensure_ascii=False)}],
                   "format": schema}
        reply = _request(host, port, "POST", "/api/chat", payload, timeout)
        content = reply.get("message", {}).get("content") if isinstance(reply.get("message"), dict) else None
    if not isinstance(content, str) or len(content) > MAX_RESPONSE_BYTES:
        raise LocalAIError("AI response content is missing or malformed.")
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LocalAIError("AI content is not the required JSON object.") from exc
    allowed_refs = {item["finding_id"] for item in summary["findings"] if item["finding_id"]}
    if (not isinstance(parsed, dict) or set(parsed) != {"suggestions"}
            or not isinstance(parsed["suggestions"], list) or len(parsed["suggestions"]) > MAX_FINDINGS
            or (allowed_refs and not parsed["suggestions"])):
        raise LocalAIError("AI suggestion schema is invalid.")
    safe_suggestions = []
    for item in parsed["suggestions"]:
        if not isinstance(item, dict) or set(item) != {"text", "evidence_refs"} or not isinstance(item["text"], str) or not isinstance(item["evidence_refs"], list):
            raise LocalAIError("AI suggestion item has invalid fields.")
        if any(not isinstance(ref, str) or len(ref) > 120 or ref not in allowed_refs for ref in item["evidence_refs"]):
            raise LocalAIError("AI referenced an unknown Finding.")
        if not item["text"].strip() or (allowed_refs and not item["evidence_refs"]):
            raise LocalAIError("AI suggestion must contain text and cite a sent Finding.")
        safe_suggestions.append({"text": _redact(item["text"][:1000]), "evidence_refs": item["evidence_refs"]})
    label = "AI 辅助建议（非正式分析；推理本地性未独立认证；正式事实和风险等级以确定性规则及证据为准）"
    return {"status": "AI_ASSISTED_LOCALITY_UNVERIFIED", "label": label,
            "provider": provider, "model": model, "endpoint_scope": "loopback" if loopback else "private_network",
            "inference_locality": "UNVERIFIED; Ollama endpoint reported a local model record, cloud-disabled state was user-asserted and server identity was not authenticated",
            "suggestions": safe_suggestions}

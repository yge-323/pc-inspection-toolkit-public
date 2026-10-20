from __future__ import annotations

import json
import ipaddress
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 2 * 1024 * 1024
PRODUCT_FILES = {
    "nginx": {"nginx.conf", "default.conf"},
    "tomcat": {"server.xml"},
    "redis": {"redis.conf"},
    "mysql": {"my.cnf", "mysqld.cnf"},
    "oracle": {"listener.ora", "sqlnet.ora"},
    "was": {"serverindex.xml", "security.xml", "soap.client.props"},
}
SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|credential|private[_-]?key|keystorepassword|truststorepassword|url|connection|string)")
ALLOW = {
    "nginx": {"listen", "ssl_protocols", "ssl_prefer_server_ciphers", "ssl_session_tickets", "client_max_body_size"},
    "redis": {"bind", "port", "protected-mode", "tls-port", "tls-auth-clients", "tls-cert-file", "tls-ca-cert-file", "requirepass", "aclfile", "rename-command", "include"},
    "mysql": {"bind-address", "port", "skip-networking", "local-infile", "require_secure_transport", "ssl-ca", "ssl-cert", "ssl-key", "secure-file-priv", "skip_name_resolve"},
    "oracle": {"tcp.validnode_checking", "tcp.invited_nodes", "tcp.excluded_nodes", "sqlnet.authentication_services", "sqlnet.encryption_server", "sqlnet.crypto_checksum_server", "admin_restrictions"},
}
XML_TAGS = {"tomcat": {"Connector": {"port", "protocol", "SSLEnabled", "scheme", "secure", "sslEnabledProtocols", "maxThreads", "redirectPort"}},
            "was": {"transportChannels": {"type"}, "channel": {"type"}, "sslConfig": {"name"}, "authDataEntries": set(), "security": {"enabled"}, "SecurityConfig": {"enabled"}}}


class ConfigSanitizationError(ValueError):
    pass


def sanitize_config(product: str, source: Path, output_dir: Path, *, instance_id: str = "instance-1", version: str = "unknown") -> Path:
    key = product.casefold()
    if key not in PRODUCT_FILES or source.name.casefold() not in {name.casefold() for name in PRODUCT_FILES[key]}:
        raise ConfigSanitizationError("Only one explicitly allow-listed configuration file may be processed.")
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigSanitizationError("Configuration must be a regular bounded file; links are refused.")
    if (not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", instance_id) or not isinstance(version, str)
            or not re.fullmatch(r"[A-Za-z0-9.+ _-]{1,100}", version or "unknown")):
        raise ConfigSanitizationError("Instance alias or version metadata is invalid.")
    raw = source.read_bytes()
    if b"\x00" in raw or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ConfigSanitizationError("Binary/XML entity configurations are refused.")
    text = raw.decode("utf-8", errors="strict")
    facts = _sanitize_xml(key, text) if key in {"tomcat", "was"} else _sanitize_directives(key, text)
    record = {"schema_version": 1, "product": key, "instance_id": instance_id, "version": version.strip() or "unknown", "config_basename": source.name,
              "status": "sanitized", "facts": facts,
              "limitations": ["One explicitly selected file only; includes are not followed.",
                              "Secret-like values are omitted or replaced; review field coverage before transfer.",
                              "Configuration findings require exact product version and human validation."]}
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{key}-{instance_id}-config.json"
    with output.open("x", encoding="utf-8", newline="") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    with output.with_name(output.stem + ".exit-code.txt").open("x", encoding="ascii", newline="") as stream:
        stream.write("0\n")
    return output


def _sanitize_directives(product: str, text: str) -> list[dict[str, Any]]:
    allowed = ALLOW[product]
    facts: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:=|\s)\s*(.*?)\s*;?$", stripped)
        if not match:
            continue
        name, value = match.groups()
        name_key = name.casefold()
        if name_key not in allowed:
            continue
        # Never follow include paths, preserve a Boolean only.
        if name_key in {"include", "aclfile", "requirepass", "rename-command", "ssl-cert", "ssl-key", "ssl-ca", "tls-cert-file", "tls-ca-cert-file"} or SECRET_KEY.search(name):
            facts.append({"key": name, "value": "configured_redacted", "line": number, "source": "selected_file"})
            continue
        raw_value = value.split("#", 1)[0].strip()
        safe_value = _typed_value(product, name_key, raw_value)
        facts.append({"key": name, "value": safe_value, "line": number, "source": "selected_file"})
    return facts[:1000]


def _sanitize_xml(product: str, text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ConfigSanitizationError("Selected XML could not be safely parsed.") from exc
    allowed_tags = XML_TAGS[product]
    facts: list[dict[str, Any]] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        allowed_attrs = allowed_tags.get(tag)
        if allowed_attrs is None:
            continue
        if not allowed_attrs:
            facts.append({"element": tag, "value": "present_redacted", "source": "selected_file"})
            continue
        for name, value in element.attrib.items():
            if name not in allowed_attrs:
                continue
            safe_value = _xml_typed_value(product, tag, name, value)
            facts.append({"element": tag, "key": name, "value": safe_value, "source": "selected_file"})
    return facts[:1000]


def _typed_value(product: str, key: str, value: str) -> str:
    if len(value) > 200 or any(ord(c) < 32 for c in value) or re.search(r"(?:/|\\)|\$|\{|;", value):
        return "configured_redacted"
    if key in {"port", "tls-port", "redirectport"}:
        return value if value.isdigit() and 1 <= int(value) <= 65535 else "invalid_or_unparsed"
    if key in {"bind", "bind-address"}:
        parts = value.split()
        try:
            if not parts or len(parts) > 8:
                return "invalid_or_unparsed"
            return " ".join("*" if item == "*" else ipaddress.ip_address(item.split("%", 1)[0]).compressed for item in parts)
        except ValueError:
            return "invalid_or_unparsed"
    if key in {"protected-mode", "tls-auth-clients", "skip-networking", "local-infile", "require_secure_transport", "skip_name_resolve", "ssl_prefer_server_ciphers", "ssl_session_tickets", "admin_restrictions", "tcp.validnode_checking"}:
        folded = value.casefold()
        return folded if folded in {"yes", "no", "on", "off", "true", "false", "0", "1", "required", "requested", "accepted", "rejected", "desired"} else "configured_unparsed"
    if key == "ssl_protocols":
        tokens = value.split()
        allowed = {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
        return " ".join(tokens) if tokens and all(token in allowed for token in tokens) else "configured_unparsed"
    if key == "listen":
        token = value.split()[0] if value.split() else ""
        if re.fullmatch(r"[0-9]{1,5}(?:\s+ssl)?", token):
            return token
        if token.startswith("[") and re.fullmatch(r"\[[0-9A-Fa-f:]+\]:[0-9]{1,5}", token):
            return "ipv6_listener_configured"
        return "listener_configured_unparsed"
    if key in {"client_max_body_size", "maxthreads"}:
        return value if re.fullmatch(r"[0-9]{1,6}(?:[kKmMgG])?", value) else "configured_unparsed"
    return "configured_redacted"


def _xml_typed_value(product: str, tag: str, key: str, value: str) -> str:
    if key.casefold() in {"port", "redirectport", "maxthreads"}:
        return value if value.isdigit() and int(value) <= 65535 else "invalid_or_unparsed"
    if key.casefold() in {"sslenabled", "secure", "enabled"}:
        return value.casefold() if value.casefold() in {"true", "false"} else "configured_unparsed"
    if key.casefold() == "sslenabledprotocols":
        tokens = value.replace(",", " ").split()
        allowed = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv3"}
        return " ".join(tokens) if tokens and all(token in allowed for token in tokens) else "configured_unparsed"
    if key.casefold() == "protocol":
        allowed_protocols = {
            "HTTP/1.1", "AJP/1.3",
            "org.apache.coyote.http11.Http11Protocol", "org.apache.coyote.http11.Http11NioProtocol",
            "org.apache.coyote.http11.Http11Nio2Protocol", "org.apache.coyote.http11.Http11AprProtocol",
            "org.apache.coyote.ajp.AjpProtocol", "org.apache.coyote.ajp.AjpNioProtocol",
            "org.apache.coyote.ajp.AjpNio2Protocol", "org.apache.coyote.ajp.AjpAprProtocol",
        }
        return value if value in allowed_protocols else "configured_redacted"
    return "configured_redacted"

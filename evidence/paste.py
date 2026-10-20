from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import re
import tarfile
from pathlib import Path
from typing import Any


BEGIN = "-----BEGIN PC-INSPECTION-PASTE-----"
END = "-----END PC-INSPECTION-PASTE-----"
CHUNK_RE = re.compile(r"^-----CHUNK\s+(\d+)/(\d+)-----\s*$")
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_FILES = 512
MAX_FILE_BYTES = 8 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".json", ".csv", ".xml", ".log"}


class PasteError(ValueError):
    pass


def decode_paste_text(text: str) -> bytes:
    if not isinstance(text, str) or BEGIN not in text or END not in text:
        raise PasteError("PASTE_MARKERS_MISSING")
    body = text.split(BEGIN, 1)[1].split(END, 1)[0]
    headers: dict[str, str] = {}
    chunks: dict[int, list[str]] = {}
    total: int | None = None
    mode = "header"
    current: int | None = None
    for raw in body.splitlines():
        line = raw.strip("\r")
        if mode == "header":
            if not line.strip():
                continue
            match = CHUNK_RE.match(line.strip())
            if match:
                mode = "chunk"
                current = int(match.group(1))
                total = int(match.group(2))
                if current < 1 or total < 1 or current > total:
                    raise PasteError("PASTE_CHUNK_INDEX_INVALID")
                chunks.setdefault(current, [])
                continue
            if "=" not in line:
                raise PasteError("PASTE_HEADER_INVALID")
            key, value = line.split("=", 1)
            headers[key.strip()] = value.strip()
            continue
        match = CHUNK_RE.match(line.strip())
        if match:
            current = int(match.group(1))
            declared = int(match.group(2))
            if total is None:
                total = declared
            elif declared != total:
                raise PasteError("PASTE_CHUNK_TOTAL_MISMATCH")
            if current < 1 or current > total:
                raise PasteError("PASTE_CHUNK_INDEX_INVALID")
            chunks.setdefault(current, [])
            continue
        if current is None:
            raise PasteError("PASTE_CHUNK_MISSING")
        if line.strip():
            chunks[current].append(line.strip())
    if headers.get("format") != "1":
        raise PasteError("PASTE_FORMAT_UNSUPPORTED")
    if headers.get("encoding") != "gzip-tar-base64":
        raise PasteError("PASTE_ENCODING_UNSUPPORTED")
    if total is None or sorted(chunks.keys()) != list(range(1, total + 1)):
        raise PasteError("PASTE_CHUNKS_INCOMPLETE")
    payload_b64 = "".join("".join(chunks[i]) for i in range(1, total + 1))
    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PasteError("PASTE_BASE64_INVALID") from exc
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise PasteError("PASTE_PAYLOAD_TOO_LARGE")
    digest = hashlib.sha256(raw).hexdigest()
    expected = headers.get("payload_sha256", "")
    if expected not in {"", "unavailable"} and digest != expected.casefold():
        raise PasteError("PASTE_PAYLOAD_HASH_MISMATCH")
    declared_bytes = headers.get("payload_bytes")
    if declared_bytes and declared_bytes.isdigit() and int(declared_bytes) != len(raw):
        raise PasteError("PASTE_PAYLOAD_SIZE_MISMATCH")
    return raw


def materialize_paste_payload(raw_gz: bytes, destination: Path) -> Path:
    if destination.exists():
        raise PasteError("PASTE_DESTINATION_EXISTS")
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw_gz)) as gz:
            tar_bytes = gz.read(MAX_PAYLOAD_BYTES + 1)
        if len(tar_bytes) > MAX_PAYLOAD_BYTES:
            raise PasteError("PASTE_PAYLOAD_TOO_LARGE")
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_FILES:
                raise PasteError("PASTE_TOO_MANY_FILES")
            written = 0
            for member in members:
                name = member.name
                if name.startswith("./"):
                    name = name[2:]
                if not name or name in {".", ".."} or name.endswith("/"):
                    continue
                if member.isdir():
                    continue
                if member.issym() or member.islnk() or not member.isfile():
                    raise PasteError("PASTE_UNSAFE_MEMBER")
                parts = Path(name).parts
                if not parts or ".." in parts or Path(name).is_absolute() or len(parts) != 1:
                    raise PasteError("PASTE_PATH_TRAVERSAL")
                basename = parts[0]
                if basename in {".", ".."}:
                    raise PasteError("PASTE_PATH_TRAVERSAL")
                suffix = Path(basename).suffix.casefold()
                if suffix not in ALLOWED_SUFFIXES and not basename.endswith(".exit-code.txt"):
                    if basename != "manifest.json":
                        raise PasteError("PASTE_UNSUPPORTED_FILE_TYPE")
                if member.size > MAX_FILE_BYTES:
                    raise PasteError("PASTE_FILE_TOO_LARGE")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise PasteError("PASTE_MEMBER_UNREADABLE")
                data = extracted.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise PasteError("PASTE_FILE_TOO_LARGE")
                target = destination / basename
                target.write_bytes(data)
                written += 1
            if written == 0:
                raise PasteError("PASTE_EMPTY_ARCHIVE")
    except PasteError:
        _safe_rmtree(destination)
        raise
    except (OSError, EOFError, tarfile.TarError, gzip.BadGzipFile) as exc:
        _safe_rmtree(destination)
        raise PasteError("PASTE_ARCHIVE_INVALID") from exc
    return destination


def import_paste_text(text: str, staging_parent: Path) -> Path:
    staging_parent.mkdir(parents=True, exist_ok=True)
    destination = staging_parent / ("paste-" + hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16])
    raw = decode_paste_text(text)
    return materialize_paste_payload(raw, destination)


def _safe_rmtree(path: Path) -> None:
    import shutil
    try:
        shutil.rmtree(path)
    except OSError:
        pass

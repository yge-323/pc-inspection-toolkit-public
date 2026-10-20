from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator


VALID_ANALYSIS_STATUSES = {"OK", "PARTIAL", "FAILED"}


@dataclass(slots=True)
class AnalysisResult:
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    config_evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in VALID_ANALYSIS_STATUSES:
            raise ValueError(f"Invalid analysis status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": self.findings,
            "config_evidence": self.config_evidence,
            "warnings": self.warnings,
            "errors": self.errors,
        }

    # Sequence compatibility keeps existing read-only consumers working while
    # callers migrate from a bare finding list to the explicit result contract.
    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __bool__(self) -> bool:
        raise TypeError(
            "AnalysisResult truthiness is ambiguous; check status or findings explicitly"
        )

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.findings[index]

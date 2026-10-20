from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str = "Info"
    category: str = "general"
    component: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    recommendation: str = ""
    verification_checkpoint: str = ""
    needs_human_review: bool = True
    precheck: str = ""
    applicability: str = ""
    rollback: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

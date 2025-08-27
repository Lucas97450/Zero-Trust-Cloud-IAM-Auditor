from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import List, Dict, Any, Optional, Tuple


class Cloud(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class Effect(Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Permission:
    service: str
    action: str
    scope: str = "*"
    conditions : Dict[str, Any] = field(default_factory=dict)

    def wildcard_action(self) -> bool:
        return self.action == "*" or self.action.endswith("*")

    def wildcard_scope(self) -> bool:
        s = str(self.scope)
        if s == "*":
            return True

        if s.endswith(":*"):
            return True

        # Exception S3: arn:aws:s3:::bucket/* est considéré "ciblé à un bucket"
        if s.startswith("arn:aws:s3:::") and s.endswith("/*"):
            parts = s.split(":::")
            if len(parts) == 2 and parts[1].count("/") == 1 and not parts[1].startswith("*"):
                return False

        # Un '/*' est traité comme wildcard large
        if s.endswith("/*"):
            return True

        return False

    

@dataclass
class Statement:
    """Statement normalisé + permissions expansées."""
    effect: Effect
    permissions: List[Permission]
    principal: Optional[Any] = None
    sid: Optional[str] = None
    raw_provider_obj: Optional[Dict[str, Any]] = None


@dataclass
class Policy:
    """Unité analysée par l'engine."""
    cloud: Cloud
    name: str
    statements: List[Statement]
    source_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def all_permissions(self) -> List[Permission]:
        out: List[Permission] = []
        for st in self.statements:
            out.extend(st.permissions)
        return out


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    policy_name: str
    statement_index: Optional[int] = None
    permission: Optional[Permission] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class ScanSummary:
    cloud: Cloud
    scanned_policies: int
    total_findings: int
    score: int
    counts_by_severity: Dict[Severity, int] = field(default_factory=dict)

@dataclass
class ScanResult:
    policies: List[Policy]
    findings: List[Finding]
    summary: ScanSummary
    generator: Dict[str, Any] = field(default_factory=dict)


SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 10,
    Severity.HIGH: 20,
    Severity.CRITICAL: 30,
}


def compute_score(findings: List[Finding], cap: int = 100) -> Tuple[int, Dict[Severity, int]]:
    """Calcule un score agrégé (0→100) + histogramme par sévérité."""
    counts: Dict[Severity, int] = {s: 0 for s in Severity}
    total = 0
    for f in findings:
        counts[f.severity] += 1
        total += SEVERITY_WEIGHTS.get(f.severity, 0)
    return (min(total, cap), counts)
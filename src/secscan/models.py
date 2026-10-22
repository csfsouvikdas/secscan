"""Core data models shared across the scanner."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Pattern, Tuple

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Rule:
    """A detection rule. ``kind`` is ``regex`` (line based), ``ast`` or ``entropy``."""

    id: str
    title: str
    severity: str
    cwe: str
    description: str
    fix: str
    category: str = "code"          # secrets | injection | crypto | config | deserialization
    kind: str = "regex"
    pattern: str = ""
    langs: Tuple[str, ...] = ()     # file extensions without dot; empty = every scanned file
    context: str = ""               # optional regex the *same line* must also match
    redact: bool = False
    secret_group: int = 0           # regex group holding the secret (for redaction)
    compiled: Optional[Pattern[str]] = field(default=None, repr=False, compare=False)
    context_compiled: Optional[Pattern[str]] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.severity not in SEV_RANK:
            raise ValueError(f"{self.id}: bad severity {self.severity!r}")
        if self.pattern:
            self.compiled = re.compile(self.pattern)
        if self.context:
            self.context_compiled = re.compile(self.context)

    def applies_to(self, ext: str) -> bool:
        return not self.langs or ext in self.langs


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    file: str
    line: int
    column: int
    snippet: str
    description: str
    fix: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0

    def counts(self) -> dict:
        out = {s: 0 for s in reversed(SEVERITIES)}
        for f in self.findings:
            out[f.severity] += 1
        return out

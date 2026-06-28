"""Findings: the output types of the scanner and their serializers.

Supports three output formats:
  * ``json``  - machine-readable, stable schema for pipelines
  * ``sarif`` - SARIF 2.1.0 for CI security dashboards (Cloud Build, code scanning)
  * ``table`` - a compact human-readable console table (no third-party deps)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import IntEnum

from .techniques import is_step_logged, technique_dict


class Severity(IntEnum):
    """Ordered severity levels (higher is worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


# SARIF expresses severity as a level + a numeric security-severity score.
_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
_SARIF_SCORE = {
    Severity.INFO: "0.0",
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


@dataclass(frozen=True)
class EscalationStep:
    """One hop in an escalation chain."""

    rule_id: str
    title: str
    detail: str


@dataclass(frozen=True)
class Enabler:
    """A remediable IAM grant that enables part of an escalation chain.

    Enablers are the unit of *remediation*: each corresponds to a specific
    binding (role -> member on a resource, optionally conditional) that, if
    removed or tightened, severs the step it underpins. Choke-point analysis
    aggregates findings by their enablers to rank what to fix first.
    """

    kind: str  # "binding" | "conditional-binding" | "impersonation"
    role: str
    member: str
    resource: str
    condition_title: str = ""

    @property
    def key(self) -> str:
        return "|".join(
            (self.kind, self.role, self.member, self.resource, self.condition_title)
        )

    def describe(self) -> str:
        base = f"{self.role} -> {self.member} on {self.resource}"
        if self.condition_title:
            base += f" [condition: {self.condition_title}]"
        return base


@dataclass
class Finding:
    """A single principal's escalation finding."""

    principal: str
    severity: Severity
    summary: str
    reaches: str
    path: list[EscalationStep] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    # Remediable grants on the chain (populated by the engine).
    enablers: list[Enabler] = field(default_factory=list)
    # Set by posture analysis: the untrusted source this principal is reachable
    # from (e.g. "allUsers"), or None if not externally exposed.
    exposure: str | None = None
    # Temporal annotations: whether any active step is a short-lived (JIT) grant,
    # and the soonest expiry among active time-bound steps (ISO-8601).
    jit: bool = False
    expires_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["severity"] = self.severity.label
        # Annotate each step with its ATT&CK technique and audit visibility.
        for step in data["path"]:
            technique = technique_dict(step["rule_id"])
            step["attack_technique"] = technique
            step["logged_by_default"] = is_step_logged(
                step["rule_id"], step["detail"]
            )
        return data


def to_json(findings: list[Finding]) -> str:
    payload = {
        "tool": "condor-scan",
        "schema_version": "1.0",
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_sarif(findings: list[Finding], *, version: str = "0.1.0") -> str:
    """Render findings as a SARIF 2.1.0 log."""
    step_index: dict[str, EscalationStep] = {}
    for f in findings:
        for step in f.path:
            step_index.setdefault(step.rule_id, step)

    rules = [
        {
            "id": step.rule_id,
            "name": step.title.replace(" ", ""),
            "shortDescription": {"text": step.title},
        }
        for step in step_index.values()
    ]

    results = []
    for f in findings:
        primary_rule = f.path[-1].rule_id if f.path else "CONDOR-GENERIC"
        results.append(
            {
                "ruleId": primary_rule,
                "level": _SARIF_LEVEL[f.severity],
                "message": {
                    "text": f"{f.summary} Reaches: {f.reaches}."
                },
                "properties": {
                    "security-severity": _SARIF_SCORE[f.severity],
                    "principal": f.principal,
                    "path": [s.detail for s in f.path],
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "condor-scan",
                        "version": version,
                        "informationUri": "https://example.org/condor-scan",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def to_table(findings: list[Finding]) -> str:
    """Render a compact console table without external dependencies."""
    if not findings:
        return "No privilege-escalation findings."

    rows = [
        (f.severity.label, f.principal, f.reaches, str(len(f.path)))
        for f in sorted(findings, key=lambda f: f.severity, reverse=True)
    ]
    headers = ("SEVERITY", "PRINCIPAL", "REACHES", "STEPS")
    widths = [
        max(len(headers[i]), max((len(r[i]) for r in rows), default=0))
        for i in range(len(headers))
    ]

    def fmt(cells: tuple[str, ...]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    lines = [fmt(headers), fmt(tuple("-" * w for w in widths))]
    lines.extend(fmt(r) for r in rows)
    lines.append("")
    lines.append(f"{len(findings)} finding(s).")
    return "\n".join(lines)


def render(findings: list[Finding], fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(findings)
    if fmt == "sarif":
        return to_sarif(findings)
    if fmt == "table":
        return to_table(findings)
    raise ValueError(f"unknown output format: {fmt!r}")

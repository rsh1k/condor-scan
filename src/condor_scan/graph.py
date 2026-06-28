"""Attack-path intelligence: turn a list of findings into a decision.

A flat list of escalation findings answers "what is wrong" but not the three
questions a defender actually has to answer:

  1. *Reachability* - which of these can an untrusted source actually reach?
     (exposure-aware origin analysis)
  2. *Prioritisation* - of everything wrong, what do we fix first to collapse
     the most attack paths? (choke-point analysis)
  3. *Detectability* - if this were exploited, would we even see it?
     (audit-log visibility / blind-spot analysis)

This module computes all three over the escalation closure and renders a
:class:`PostureReport`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .analysis import AnalysisContext
from .findings import Enabler, EscalationStep, Finding, Severity
from .rules import EscalationEngine
from .techniques import is_step_logged
from .temporal import TemporalStatus


@dataclass
class ChokePoint:
    """A single remediable grant and the escalating principals it underpins."""

    enabler: Enabler
    covers: list[str] = field(default_factory=list)


@dataclass
class BlindSpot:
    """An escalation step that produces no default audit-log signal."""

    principal: str
    step: EscalationStep


@dataclass
class ScheduledEscalation:
    """A conditional escalatory grant that is not active yet but will be."""

    member: str
    role: str
    resource: str
    condition_title: str
    becomes_active: str | None


@dataclass
class PostureReport:
    """Organisation-level attack-path summary derived from the findings."""

    total_principals: int
    findings: list[Finding]
    untrusted_sources: list[str]
    tier_zero_principals: list[str]
    exposed_tier_zero: list[str]
    choke_points: list[ChokePoint]
    blind_spots: list[BlindSpot]
    jit_escalations: list[str] = field(default_factory=list)
    scheduled_escalations: list[ScheduledEscalation] = field(
        default_factory=list
    )
    evaluated_at: str | None = None

    # -- derived headline metrics ---------------------------------------
    @property
    def remediation_budget(self) -> int:
        """Number of grants to remove to break every modelled Tier-Zero path."""
        return len(self.choke_points)

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": "condor-scan",
            "report": "attack-path-posture",
            "evaluated_at": self.evaluated_at,
            "metrics": {
                "principals_analyzed": self.total_principals,
                "findings": len(self.findings),
                "can_reach_tier_zero": len(self.tier_zero_principals),
                "externally_exposed_to_tier_zero": len(self.exposed_tier_zero),
                "remediation_budget": self.remediation_budget,
                "detection_blind_spots": len(self.blind_spots),
                "active_jit_escalations": len(self.jit_escalations),
                "scheduled_escalations": len(self.scheduled_escalations),
            },
            "untrusted_sources": self.untrusted_sources,
            "exposed_tier_zero_principals": self.exposed_tier_zero,
            "choke_points": [
                {
                    "grant": cp.enabler.describe(),
                    "kind": cp.enabler.kind,
                    "addresses_principals": cp.covers,
                }
                for cp in self.choke_points
            ],
            "blind_spots": [
                {
                    "principal": bs.principal,
                    "rule_id": bs.step.rule_id,
                    "detail": bs.step.detail,
                }
                for bs in self.blind_spots
            ],
            "active_jit_escalations": self.jit_escalations,
            "scheduled_escalations": [
                {
                    "member": se.member,
                    "role": se.role,
                    "resource": se.resource,
                    "condition": se.condition_title,
                    "becomes_active": se.becomes_active,
                }
                for se in self.scheduled_escalations
            ],
        }

    def to_text(self) -> str:
        lines: list[str] = []
        add = lines.append
        add("condor-scan - attack-path posture report")
        add("=" * 48)
        add(f"Principals analyzed .............. {self.total_principals}")
        add(f"Escalation findings .............. {len(self.findings)}")
        add(f"Can reach Tier Zero .............. {len(self.tier_zero_principals)}")
        add(
            "Externally exposed -> Tier Zero .. "
            f"{len(self.exposed_tier_zero)}"
        )
        add(f"Remediation budget (choke points)  {self.remediation_budget}")
        add(f"Detection blind spots ............ {len(self.blind_spots)}")
        add(f"Active JIT escalations ........... {len(self.jit_escalations)}")
        add(f"Scheduled (future) escalations ... {len(self.scheduled_escalations)}")
        if self.evaluated_at:
            add(f"Evaluated as of .................. {self.evaluated_at}")
        add("")

        if self.jit_escalations:
            add("ACTIVE JIT ESCALATION (live now, short-lived window):")
            for principal in self.jit_escalations:
                expiry = next(
                    (
                        f.expires_at
                        for f in self.findings
                        if f.principal == principal and f.expires_at
                    ),
                    None,
                )
                suffix = f" (expires {expiry})" if expiry else ""
                add(f"  * {principal}{suffix}")
            add("")

        if self.exposed_tier_zero:
            add("EXTERNALLY EXPOSED PATHS TO TIER ZERO (fix first):")
            for principal in self.exposed_tier_zero:
                add(f"  ! {principal}")
            add("")

        if self.choke_points:
            add("PRIORITISED REMEDIATION PLAN (greedy choke-point cover):")
            for i, cp in enumerate(self.choke_points, 1):
                add(f"  {i}. remove/scope: {cp.enabler.describe()}")
                add(
                    f"     -> eliminates escalation for {len(cp.covers)} "
                    f"principal(s): {', '.join(cp.covers)}"
                )
            add("")

        if self.scheduled_escalations:
            add("SCHEDULED / DORMANT ESCALATION (not exploitable yet):")
            for se in self.scheduled_escalations:
                when = f" at {se.becomes_active}" if se.becomes_active else ""
                add(f"  > {se.member} -> {se.role} on {se.resource}{when}")
            add("")

        if self.blind_spots:
            add("DETECTION BLIND SPOTS (escalation with no default audit signal):")
            seen: set[str] = set()
            for bs in self.blind_spots:
                marker = f"{bs.step.rule_id}:{bs.principal}"
                if marker in seen:
                    continue
                seen.add(marker)
                add(f"  ~ [{bs.step.rule_id}] {bs.principal}: {bs.step.detail}")
            add("")

        if not (
            self.exposed_tier_zero
            or self.choke_points
            or self.blind_spots
            or self.jit_escalations
            or self.scheduled_escalations
        ):
            add("No Tier-Zero escalation, external exposure, or blind spots found.")
        return "\n".join(lines)


def _exposure_map(ctx: AnalysisContext, engine: EscalationEngine) -> dict[str, str]:
    """Map each reachable principal -> the untrusted source that reaches it."""
    reachable: dict[str, str] = {}
    for source in sorted(ctx.untrusted_sources()):
        for identity in engine.reachable_identities(source):
            reachable.setdefault(identity, source)
    return reachable


def _greedy_choke_points(tier_zero: list[Finding]) -> list[ChokePoint]:
    """Greedy set-cover over Tier-Zero findings by their enabling grants.

    We want the smallest set of remediable grants that, removed, addresses every
    principal able to reach Tier Zero. Minimum set cover is NP-hard; the classic
    greedy algorithm (repeatedly take the grant covering the most still-
    uncovered principals) gives the standard ln(n)-approximation and, in
    practice, surfaces the highest-leverage fixes first.

    This is a first-order prioritisation: a principal may retain an alternate
    path after one grant is removed, so re-running the scan after remediation is
    recommended. The ranking is still the right order to work in.
    """
    uncovered = {f.principal for f in tier_zero}
    enablers: dict[str, Enabler] = {}
    covers: dict[str, set[str]] = {}
    for finding in tier_zero:
        for enabler in finding.enablers:
            enablers[enabler.key] = enabler
            covers.setdefault(enabler.key, set()).add(finding.principal)

    plan: list[ChokePoint] = []
    while uncovered:
        best_key = max(
            covers,
            key=lambda k: len(covers[k] & uncovered),
            default=None,
        )
        if best_key is None:
            break
        newly = covers[best_key] & uncovered
        if not newly:
            break
        plan.append(
            ChokePoint(enabler=enablers[best_key], covers=sorted(newly))
        )
        uncovered -= newly
    return plan


def _blind_spots(findings: list[Finding]) -> list[BlindSpot]:
    spots: list[BlindSpot] = []
    for finding in findings:
        for step in finding.path:
            if step.rule_id == "CONDOR-SEED":
                continue  # a pre-existing grant is a state, not an action
            if not is_step_logged(step.rule_id, step.detail):
                spots.append(BlindSpot(principal=finding.principal, step=step))
    return spots


def _scheduled_escalations(
    ctx: AnalysisContext, engine: EscalationEngine
) -> list[ScheduledEscalation]:
    """Conditional escalatory grants that are not active yet but will be.

    These are latent risk: dormant today, exploitable once their window opens.
    We surface them so they can be reviewed before they go live.
    """
    out: list[ScheduledEscalation] = []
    for idx in ctx.principals.values():
        for grant in idx.conditional_grants:
            if grant.temporal.status(engine.now) is not TemporalStatus.FUTURE:
                continue
            if not engine._grant_is_escalatory(grant):
                continue
            nb = grant.temporal.not_before
            out.append(
                ScheduledEscalation(
                    member=idx.member,
                    role=grant.role,
                    resource=grant.resource,
                    condition_title=grant.condition_title,
                    becomes_active=nb.isoformat() if nb else None,
                )
            )
    return sorted(out, key=lambda s: (s.becomes_active or "", s.member))


def analyze_posture(
    ctx: AnalysisContext, engine: EscalationEngine | None = None
) -> PostureReport:
    """Compute the full attack-path posture for an indexed environment."""
    engine = engine or EscalationEngine(ctx)
    findings = engine.analyze_all()

    exposure = _exposure_map(ctx, engine)
    for finding in findings:
        finding.exposure = exposure.get(finding.principal)

    tier_zero = [f for f in findings if f.severity >= Severity.CRITICAL]
    exposed_tier_zero = sorted(f.principal for f in tier_zero if f.exposure)
    jit_escalations = sorted(f.principal for f in findings if f.jit)

    return PostureReport(
        total_principals=len(ctx.principals),
        findings=findings,
        untrusted_sources=sorted(ctx.untrusted_sources()),
        tier_zero_principals=sorted(f.principal for f in tier_zero),
        exposed_tier_zero=exposed_tier_zero,
        choke_points=_greedy_choke_points(tier_zero),
        blind_spots=_blind_spots(findings),
        jit_escalations=jit_escalations,
        scheduled_escalations=_scheduled_escalations(ctx, engine),
        evaluated_at=engine.now.isoformat(),
    )

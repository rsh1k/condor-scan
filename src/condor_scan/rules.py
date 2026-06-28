"""The escalation engine.

Models privilege escalation as a *capability closure*: starting from a
principal's initial permissions and identities, repeatedly apply escalation
rules until no rule adds anything new. Every applied rule records a step, so the
result is a full attack *chain*, not just a single finding -- matching how GCP
escalation works in practice (a leaked key -> a default SA -> actAs on a
privileged SA -> an org-level binding).

Each step is also attributed to the remediable IAM grant ("enabler") that made
it possible, so downstream choke-point analysis can rank what to fix first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import knowledge as kb
from .analysis import (
    AnalysisContext,
    ConditionalGrant,
    ImpersonationGrant,
    ServiceAccountIndex,
)
from .cel import is_tag_based
from .findings import Enabler, EscalationStep, Finding, Severity
from .temporal import TemporalWindow, now_utc

_DEFAULT_JIT_THRESHOLD = timedelta(hours=24)

_REFS = [
    "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/",
    "https://www.praetorian.com/blog/google-cloud-platform-gcp-service-account-based-privilege-escalation-paths/",
    "https://www.mitiga.io/blog/tag-your-way-in-new-privilege-escalation-technique-in-gcp",
]


@dataclass
class _State:
    """Mutable state accumulated during the closure."""

    root_member: str
    permissions: set[str]
    identities: set[str]
    roles_held: set[str]
    steps: list[EscalationStep] = field(default_factory=list)
    consumed_grants: set[int] = field(default_factory=set)
    impersonated: set[str] = field(default_factory=set)
    enablers: dict[str, Enabler] = field(default_factory=dict)
    active_windows: list[TemporalWindow] = field(default_factory=list)

    @property
    def can_attach_tags(self) -> bool:
        return bool(self.permissions & kb.TAG_ATTACH_PERMISSIONS)

    def add_enabler(self, enabler: Enabler) -> None:
        self.enablers.setdefault(enabler.key, enabler)


class EscalationEngine:
    """Computes escalation findings for principals in an indexed environment."""

    def __init__(
        self,
        ctx: AnalysisContext,
        *,
        now: datetime | None = None,
        jit_threshold: timedelta = _DEFAULT_JIT_THRESHOLD,
    ) -> None:
        self.ctx = ctx
        self.now = now if now is not None else now_utc()
        self.jit_threshold = jit_threshold

    # -- public API ------------------------------------------------------
    def analyze_all(self) -> list[Finding]:
        findings: list[Finding] = []
        for member in self.ctx.principals:
            finding = self.analyze(member)
            if finding is not None:
                findings.append(finding)
        return findings

    def analyze(self, member: str) -> Finding | None:
        state = self._compute_state(member)
        if state is None:
            return None
        return self._build_finding(member, state)

    def reachable_identities(self, member: str) -> set[str]:
        """Return every identity ``member`` can come to control (incl. itself).

        Used by exposure analysis to decide which principals an untrusted source
        can ultimately drive.
        """
        state = self._compute_state(member)
        return set(state.identities) if state is not None else {member}

    # -- core closure ----------------------------------------------------
    def _compute_state(self, member: str) -> _State | None:
        idx = self.ctx.principals.get(member)
        if idx is None:
            return None
        state = _State(
            root_member=member,
            permissions=set(idx.permissions),
            identities={member},
            roles_held=set(idx.roles),
        )
        self._seed_initial(state)
        self._run_closure(state)
        return state

    def _run_closure(self, state: _State) -> None:
        rules = (
            self._rule_self_grant,
            self._rule_role_update,
            self._rule_impersonate_service_account,
            self._rule_tag_conditional,
            self._rule_temporal_direct,
        )
        changed = True
        # The closure is monotonic (state only grows) and bounded by the finite
        # number of permissions/identities, so it always terminates.
        while changed:
            changed = False
            for rule in rules:
                if rule(state):
                    changed = True

    def _seed_initial(self, state: _State) -> None:
        """Record dangerous primitives the principal already holds directly.

        Consolidated into a single step so a role that confers several related
        permissions (e.g. Token Creator) does not produce a wall of near-
        identical entries.
        """
        dangerous = sorted(
            perm
            for perm in state.permissions
            if kb.severity_for_permission(perm) >= Severity.HIGH
        )
        if dangerous:
            shown = ", ".join(dangerous[:5])
            extra = "" if len(dangerous) <= 5 else f" (+{len(dangerous) - 5} more)"
            state.steps.append(
                EscalationStep(
                    rule_id="CONDOR-SEED",
                    title="Initial dangerous permissions",
                    detail=f"principal already holds: {shown}{extra}",
                )
            )
            self._attribute_grants(state, set(dangerous))

    # -- enabler attribution --------------------------------------------
    def _attribute_grants(self, state: _State, target_perms: set[str]) -> None:
        """Attribute a set of permissions to the root principal's bindings."""
        idx = self.ctx.principals.get(state.root_member)
        if idx is None:
            return
        for grant in idx.grants:
            if grant.permissions & target_perms:
                state.add_enabler(
                    Enabler(
                        kind="binding",
                        role=grant.role,
                        member=state.root_member,
                        resource=grant.resource,
                    )
                )

    # -- rules (each returns True if it changed state) -------------------
    def _rule_self_grant(self, state: _State) -> bool:
        held = state.permissions & set(kb.SELF_GRANT_PERMISSIONS)
        if held and "roles/owner" not in state.roles_held:
            perm = sorted(held)[0]
            state.roles_held.add("roles/owner")
            state.permissions.update(kb.PREDEFINED_ROLE_PERMISSIONS["roles/owner"])
            state.steps.append(
                EscalationStep(
                    rule_id="CONDOR-SETIAMPOLICY",
                    title="Self-grant via setIamPolicy",
                    detail=(
                        f"'{perm}' allows binding roles/owner to self -> "
                        "full takeover"
                    ),
                )
            )
            self._attribute_grants(state, set(kb.SELF_GRANT_PERMISSIONS))
            return True
        return False

    def _rule_role_update(self, state: _State) -> bool:
        if (state.permissions & set(kb.ROLE_UPDATE_PERMISSIONS)) and (
            "CONDOR-ROLEUPDATE" not in {s.rule_id for s in state.steps}
        ):
            # Updating a role the principal holds lets them add any permission.
            updatable = state.roles_held & set(self.ctx.custom_roles)
            if updatable:
                state.permissions.update(kb.SELF_GRANT_PERMISSIONS)
                role = sorted(updatable)[0]
                state.steps.append(
                    EscalationStep(
                        rule_id="CONDOR-ROLEUPDATE",
                        title="Self-grant via role update",
                        detail=(
                            "iam.roles.update on a held custom role "
                            f"({role}) allows adding arbitrary permissions"
                        ),
                    )
                )
                self._attribute_grants(state, set(kb.ROLE_UPDATE_PERMISSIONS))
                return True
        return False

    def _rule_impersonate_service_account(self, state: _State) -> bool:
        changed = False
        for email, sa in self.ctx.service_accounts.items():
            if email in state.impersonated:
                continue
            method = self._impersonation_method(state, sa)
            if method is None:
                continue
            description, grant, holder = method
            state.impersonated.add(email)
            state.identities.add(f"serviceAccount:{email}")
            state.permissions.update(sa.permissions)
            state.roles_held.update(sa.roles)
            state.steps.append(
                EscalationStep(
                    rule_id="CONDOR-IMPERSONATE",
                    title="Service-account impersonation",
                    detail=f"impersonate '{email}' via {description}",
                )
            )
            state.add_enabler(
                Enabler(
                    kind="impersonation",
                    role=grant.role,
                    member=holder,
                    resource=grant.resource,
                )
            )
            changed = True
        return changed

    def _impersonation_method(
        self, state: _State, sa: ServiceAccountIndex
    ) -> tuple[str, ImpersonationGrant, str] | None:
        token_or_key = kb.TOKEN_CREATE_PERMISSIONS | kb.KEY_CREATE_PERMISSIONS
        for member in state.identities:
            for grant in sa.impersonators.get(member, []):
                # 1. Direct token / key creation by any controlled identity.
                direct = grant.permissions & token_or_key
                if direct:
                    primitive = sorted(direct)[0]
                    return f"'{primitive}'", grant, member
                # 2. actAs combined with a deploy permission in current state.
                if (grant.permissions & kb.ACT_AS_PERMISSIONS) and (
                    state.permissions & kb.DEPLOY_WITH_SA_PERMISSIONS
                ):
                    deploy = sorted(
                        state.permissions & kb.DEPLOY_WITH_SA_PERMISSIONS
                    )[0]
                    return f"actAs + deploy ('{deploy}')", grant, member
        return None

    def _rule_tag_conditional(self, state: _State) -> bool:
        """The Mitiga 'Tag Your Way In' path.

        If a controlled identity holds a *conditional* grant of an escalation or
        tier-zero role, the condition is tag-based, and the principal can attach
        tags, then the principal can satisfy the condition and obtain the role.
        """
        if not state.can_attach_tags:
            return False

        changed = False
        controlled: set[str] = set()
        for member in state.identities:
            controlled |= self.ctx.members_including_groups(member)

        for member in controlled:
            idx = self.ctx.principals.get(member)
            if idx is None:
                continue
            for i, grant in enumerate(idx.conditional_grants):
                key = hash((member, i))
                if key in state.consumed_grants:
                    continue
                if not is_tag_based(grant.condition_expression):
                    continue
                if not self._grant_is_escalatory(grant):
                    continue
                # Temporal gate: an expired or not-yet-active conditional grant
                # is not exploitable now, so it must not count as a live path.
                if not grant.temporal.is_active(self.now):
                    continue
                state.consumed_grants.add(key)
                state.permissions.update(grant.permissions)
                state.roles_held.add(grant.role)
                state.active_windows.append(grant.temporal)
                state.steps.append(
                    EscalationStep(
                        rule_id="CONDOR-TAGCONDITION",
                        title="Tag-based conditional escalation",
                        detail=(
                            f"attach tag to satisfy condition "
                            f"'{grant.condition_title}' and obtain "
                            f"'{grant.role}' on {grant.resource}"
                            f"{self._window_note(grant.temporal)}"
                        ),
                    )
                )
                state.add_enabler(
                    Enabler(
                        kind="conditional-binding",
                        role=grant.role,
                        member=member,
                        resource=grant.resource,
                        condition_title=grant.condition_title,
                    )
                )
                changed = True
        return changed

    def _grant_is_escalatory(self, grant: ConditionalGrant) -> bool:
        if grant.role in kb.TIER_ZERO_ROLES:
            return True
        dangerous = (
            set(kb.SELF_GRANT_PERMISSIONS)
            | set(kb.ROLE_UPDATE_PERMISSIONS)
            | kb.TOKEN_CREATE_PERMISSIONS
            | kb.KEY_CREATE_PERMISSIONS
            | kb.ACT_AS_PERMISSIONS
            | kb.DEPLOY_WITH_SA_PERMISSIONS
        )
        return bool(grant.permissions & dangerous)

    def _rule_temporal_direct(self, state: _State) -> bool:
        """Active, time-bound *direct* grants of an escalatory role.

        This is the break-glass / JIT case: a principal holds Owner (or another
        escalatory role) directly, but only inside a ``request.time`` window. If
        that window is open right now, the principal currently has the role -
        worth surfacing, often as a short-lived "hot" finding. Restricting to
        time-bound conditions keeps us away from legitimately resource-scoped
        conditional grants, which we deliberately do not flag.
        """
        changed = False
        controlled: set[str] = set()
        for member in state.identities:
            controlled |= self.ctx.members_including_groups(member)

        for member in controlled:
            idx = self.ctx.principals.get(member)
            if idx is None:
                continue
            for i, grant in enumerate(idx.conditional_grants):
                key = hash(("temporal", member, i))
                if key in state.consumed_grants:
                    continue
                if is_tag_based(grant.condition_expression):
                    continue  # handled by the tag-conditional rule
                if not grant.temporal.is_bounded:
                    continue  # not a time-bound grant; out of scope here
                if not self._grant_is_escalatory(grant):
                    continue
                if not grant.temporal.is_active(self.now):
                    continue
                state.consumed_grants.add(key)
                state.permissions.update(grant.permissions)
                state.roles_held.add(grant.role)
                state.active_windows.append(grant.temporal)
                state.steps.append(
                    EscalationStep(
                        rule_id="CONDOR-JITGRANT",
                        title="Active time-bound (JIT) escalatory grant",
                        detail=(
                            f"holds '{grant.role}' on {grant.resource} via "
                            f"time-bound condition '{grant.condition_title}'"
                            f"{self._window_note(grant.temporal)}"
                        ),
                    )
                )
                state.add_enabler(
                    Enabler(
                        kind="conditional-binding",
                        role=grant.role,
                        member=member,
                        resource=grant.resource,
                        condition_title=grant.condition_title,
                    )
                )
                changed = True
        return changed

    def _window_note(self, window: TemporalWindow) -> str:
        """Human-readable temporal annotation for a step detail."""
        if not window.is_bounded:
            return ""
        bits: list[str] = []
        if window.not_after is not None:
            bits.append(f"expires {window.not_after.isoformat()}")
        if window.is_jit(self.jit_threshold):
            duration = window.duration()
            assert duration is not None
            hours = duration.total_seconds() / 3600
            bits.append(f"JIT window ~{hours:.0f}h")
        return f" [{'; '.join(bits)}]" if bits else ""

    # -- finding construction -------------------------------------------
    def _build_finding(self, member: str, state: _State) -> Finding | None:
        escalation_steps = [s for s in state.steps if s.rule_id != "CONDOR-SEED"]
        seed_steps = [s for s in state.steps if s.rule_id == "CONDOR-SEED"]

        reaches, severity = self._assess(state)
        if severity < Severity.LOW:
            return None
        # Require either a real escalation step or a directly-held dangerous
        # primitive, so we never emit a finding for a benign principal.
        if not escalation_steps and not seed_steps:
            return None

        summary = (
            f"Principal '{member}' can escalate privileges "
            f"through {len(escalation_steps)} step(s)."
            if escalation_steps
            else f"Principal '{member}' directly holds a dangerous permission."
        )
        jit, expires_at = self._temporal_summary(state)
        return Finding(
            principal=member,
            severity=severity,
            summary=summary,
            reaches=reaches,
            path=state.steps,
            references=list(_REFS),
            remediation=(
                "Remove the escalation-enabling role/permission, scope tag "
                "permissions tightly, and review conditional IAM bindings keyed "
                "on tags. Prefer least-privilege custom roles over Editor/Owner."
            ),
            enablers=list(state.enablers.values()),
            jit=jit,
            expires_at=expires_at,
        )

    def _temporal_summary(self, state: _State) -> tuple[bool, str | None]:
        """Derive the JIT flag and soonest expiry from active windows."""
        jit = any(w.is_jit(self.jit_threshold) for w in state.active_windows)
        expiries = [
            w.not_after for w in state.active_windows if w.not_after is not None
        ]
        expires_at = min(expiries).isoformat() if expiries else None
        return jit, expires_at

    def _assess(self, state: _State) -> tuple[str, Severity]:
        if state.roles_held & kb.TIER_ZERO_ROLES:
            role = sorted(state.roles_held & kb.TIER_ZERO_ROLES)[0]
            return f"{role} (full control)", Severity.CRITICAL
        if state.permissions & set(kb.SELF_GRANT_PERMISSIONS):
            return "project/org IAM policy control", Severity.CRITICAL
        if state.impersonated:
            return (
                f"impersonation of {len(state.impersonated)} service account(s)",
                Severity.HIGH,
            )
        # Severity from the strongest standalone primitive held.
        best = max(
            (kb.severity_for_permission(p) for p in state.permissions),
            default=Severity.INFO,
        )
        if best >= Severity.HIGH:
            return "elevated permissions", best
        if best == Severity.LOW:
            return "tag-attachment capability", Severity.LOW
        return "no escalation", Severity.INFO

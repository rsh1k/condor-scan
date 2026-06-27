"""MITRE ATT&CK technique mapping and audit-log visibility model.

For each escalation primitive the engine can use, we record:

  * the MITRE ATT&CK (Cloud) technique it corresponds to, and
  * whether performing it produces a Cloud Audit Log entry *by default*.

The visibility dimension is the point. GCP splits audit logs into:

  * **Admin Activity** logs - always on, free, cannot be disabled. Cover
    "write" / configuration-changing calls (SetIamPolicy, CreateServiceAccountKey,
    role updates, resource deploys, CreateTagBinding).
  * **Data Access** logs - *disabled by default* (except BigQuery), must be
    explicitly enabled, and are billable. They cover most "read" calls -
    including ``GenerateAccessToken`` / ``GenerateIdToken`` / ``SignJwt`` on the
    IAM Service Account Credentials API.

So service-account *token* impersonation is frequently invisible, and tag-based
conditional escalation is invisible in a subtler way: the conditional binding
already exists, so satisfying it by attaching a tag produces only a
``CreateTagBinding`` event - never an IAM *policy-change* event - and most SIEM
content keys on policy changes, not tag bindings. This module lets the report
flag those silent paths so a SOC knows where its blind spots are.

This module has no internal dependencies so any layer can import it freely.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackTechnique:
    """A MITRE ATT&CK technique plus its default GCP log visibility."""

    id: str
    name: str
    tactic: str
    logged_by_default: bool
    log_source: str
    note: str = ""


# Per-rule mapping. Visibility here is the *typical* case; some rules
# (impersonation) are method-dependent and refined by :func:`is_step_logged`.
TECHNIQUE_BY_RULE: dict[str, AttackTechnique] = {
    "CONDOR-SEED": AttackTechnique(
        id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        tactic="Privilege Escalation",
        logged_by_default=True,
        log_source="n/a (pre-existing grant, not an action)",
        note="Holding the permission is a state, not an event; only its use is logged.",
    ),
    "CONDOR-SETIAMPOLICY": AttackTechnique(
        id="T1098.003",
        name="Account Manipulation: Additional Cloud Roles",
        tactic="Privilege Escalation",
        logged_by_default=True,
        log_source="Admin Activity audit logs",
        note="SetIamPolicy is always recorded in Admin Activity logs.",
    ),
    "CONDOR-ROLEUPDATE": AttackTechnique(
        id="T1098",
        name="Account Manipulation",
        tactic="Privilege Escalation",
        logged_by_default=True,
        log_source="Admin Activity audit logs",
        note=(
            "The UpdateRole call is logged, but the broadened access it confers "
            "is not separately flagged, so the impact is easy to miss."
        ),
    ),
    "CONDOR-IMPERSONATE": AttackTechnique(
        id="T1550.001",
        name="Use Alternate Authentication Material: Application Access Token",
        tactic="Privilege Escalation / Lateral Movement",
        logged_by_default=False,
        log_source="Data Access audit logs (usually disabled)",
        note=(
            "Token minting (GenerateAccessToken/SignJwt) is a Data Access event, "
            "off by default. Key creation (T1098.001) IS in Admin Activity logs."
        ),
    ),
    "CONDOR-TAGCONDITION": AttackTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        logged_by_default=False,
        log_source="no distinct IAM policy-change event",
        note=(
            "The conditional binding pre-exists; attaching a tag to satisfy it "
            "emits only a CreateTagBinding event, never an IAM policy change, so "
            "SIEM content keyed on policy changes will not fire."
        ),
    ),
}

# Token-minting primitives that land in (off-by-default) Data Access logs.
_SILENT_IMPERSONATION_MARKERS = (
    "getAccessToken",
    "getOpenIdToken",
    "signJwt",
    "signBlob",
    "implicitDelegation",
)


def is_step_logged(rule_id: str, detail: str) -> bool:
    """Return whether an escalation step is captured by default audit logging.

    Most steps inherit their rule's ``logged_by_default``. Impersonation is
    refined: key creation is logged (Admin Activity) while token minting is not
    (Data Access, off by default).
    """
    if rule_id == "CONDOR-IMPERSONATE":
        if "serviceAccountKeys.create" in detail:
            return True
        return not any(m in detail for m in _SILENT_IMPERSONATION_MARKERS)
    technique = TECHNIQUE_BY_RULE.get(rule_id)
    return technique.logged_by_default if technique else True


def technique_dict(rule_id: str) -> dict[str, object] | None:
    """Return a JSON-serialisable view of the technique for a rule, if known."""
    t = TECHNIQUE_BY_RULE.get(rule_id)
    if t is None:
        return None
    return {
        "id": t.id,
        "name": t.name,
        "tactic": t.tactic,
        "logged_by_default": t.logged_by_default,
        "log_source": t.log_source,
        "note": t.note,
    }

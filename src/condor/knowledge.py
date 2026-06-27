"""Curated GCP IAM knowledge base used by the escalation engine.

This module encodes a deliberately *curated* subset of GCP's permission and
role model: only the permissions and predefined roles that are relevant to
privilege escalation. It is not a complete mirror of GCP IAM (which has tens of
thousands of permissions). Keeping it curated makes the analysis auditable and
keeps false positives low.

Sources for the modelled escalation primitives:
  - Rhino Security Labs, "Privilege Escalation in Google Cloud Platform" (IAM vectors)
  - Praetorian, "GCP Service Account-based Privilege Escalation paths"
  - Mitiga, "Tag Your Way In: New Privilege Escalation Technique in GCP" (2026)
  - Red Canary, "The dark cloud around GCP service accounts" (2025)
"""

from __future__ import annotations

from .findings import Severity

# --- Permissions that let a principal directly grant itself more access ------
# Holding any of these is, by itself, a path to organization/project takeover.
SELF_GRANT_PERMISSIONS: dict[str, Severity] = {
    "resourcemanager.organizations.setIamPolicy": Severity.CRITICAL,
    "resourcemanager.folders.setIamPolicy": Severity.CRITICAL,
    "resourcemanager.projects.setIamPolicy": Severity.CRITICAL,
}

# Updating a role you already hold lets you add arbitrary permissions to it.
ROLE_UPDATE_PERMISSIONS: dict[str, Severity] = {
    "iam.roles.update": Severity.HIGH,
    "iam.roles.create": Severity.HIGH,
}

# --- Service-account impersonation primitives --------------------------------
# Permissions on a *service account resource* that let a principal act as it.
TOKEN_CREATE_PERMISSIONS: frozenset[str] = frozenset(
    {
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
    }
)
KEY_CREATE_PERMISSIONS: frozenset[str] = frozenset(
    {"iam.serviceAccountKeys.create"}
)
ACT_AS_PERMISSIONS: frozenset[str] = frozenset({"iam.serviceAccounts.actAs"})

# --- Deploy permissions that run code under an attached service account ------
# Combined with actAs on a privileged SA, any of these yields code execution as
# that SA (see Praetorian / r3dbuck3t Cloud Functions takeover write-ups).
DEPLOY_WITH_SA_PERMISSIONS: frozenset[str] = frozenset(
    {
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.update",
        "run.services.create",
        "run.services.update",
        "compute.instances.create",
        "compute.instances.setMetadata",
        "deploymentmanager.deployments.create",
        "dataflow.jobs.create",
        "composer.environments.create",
    }
)

# --- Tag attachment primitives (the Mitiga "Tag Your Way In" path) -----------
# A principal able to attach tag values can satisfy tag-keyed IAM Conditions.
TAG_ATTACH_PERMISSIONS: frozenset[str] = frozenset(
    {
        "resourcemanager.tagValueBindings.create",
        "resourcemanager.hierarchyNodes.createTagBinding",
    }
)

# --- Roles whose mere possession constitutes full control ("tier zero") ------
TIER_ZERO_ROLES: frozenset[str] = frozenset(
    {
        "roles/owner",
        "roles/resourcemanager.organizationAdmin",
        "roles/resourcemanager.folderAdmin",
        "roles/iam.organizationRoleAdmin",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
    }
)

# --- Curated predefined-role -> escalation-relevant permission subsets --------
# We only list permissions that matter to escalation analysis. ``roles/owner``
# is additionally flagged tier-zero above.
PREDEFINED_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "roles/owner": frozenset(
        {
            "resourcemanager.projects.setIamPolicy",
            "iam.serviceAccounts.actAs",
            "iam.serviceAccountKeys.create",
            "resourcemanager.tagValueBindings.create",
            "iam.roles.update",
        }
    ),
    "roles/editor": frozenset(
        {
            "iam.serviceAccounts.actAs",
            "iam.serviceAccountKeys.create",
            "cloudfunctions.functions.create",
            "cloudfunctions.functions.update",
            "run.services.create",
            "run.services.update",
            "compute.instances.create",
            "compute.instances.setMetadata",
            "deploymentmanager.deployments.create",
            "resourcemanager.tagValueBindings.create",
        }
    ),
    "roles/viewer": frozenset(),
    "roles/iam.serviceAccountTokenCreator": TOKEN_CREATE_PERMISSIONS,
    "roles/iam.serviceAccountUser": frozenset({"iam.serviceAccounts.actAs"}),
    "roles/iam.serviceAccountKeyAdmin": KEY_CREATE_PERMISSIONS
    | frozenset({"iam.serviceAccountKeys.delete"}),
    "roles/iam.roleAdmin": frozenset({"iam.roles.update", "iam.roles.create"}),
    "roles/iam.organizationRoleAdmin": frozenset(
        {"iam.roles.update", "iam.roles.create"}
    ),
    "roles/resourcemanager.tagUser": frozenset(
        {
            "resourcemanager.tagValueBindings.create",
            "resourcemanager.tagValueBindings.delete",
            "resourcemanager.tagValues.list",
            "resourcemanager.tagValues.get",
        }
    ),
    "roles/resourcemanager.tagAdmin": frozenset(
        {
            "resourcemanager.tagValueBindings.create",
            "resourcemanager.tagValues.create",
        }
    ),
    "roles/cloudfunctions.admin": frozenset(
        {"cloudfunctions.functions.create", "cloudfunctions.functions.update"}
    ),
    "roles/cloudfunctions.developer": frozenset(
        {"cloudfunctions.functions.create", "cloudfunctions.functions.update"}
    ),
    "roles/run.admin": frozenset(
        {"run.services.create", "run.services.update"}
    ),
    "roles/run.developer": frozenset(
        {"run.services.create", "run.services.update"}
    ),
    "roles/compute.admin": frozenset(
        {"compute.instances.create", "compute.instances.setMetadata"}
    ),
    "roles/compute.instanceAdmin.v1": frozenset(
        {"compute.instances.create", "compute.instances.setMetadata"}
    ),
    "roles/resourcemanager.projectIamAdmin": frozenset(
        {"resourcemanager.projects.setIamPolicy"}
    ),
}


def severity_for_permission(permission: str) -> Severity:
    """Return the standalone severity of holding ``permission`` (INFO if benign)."""
    if permission in SELF_GRANT_PERMISSIONS:
        return SELF_GRANT_PERMISSIONS[permission]
    if permission in ROLE_UPDATE_PERMISSIONS:
        return ROLE_UPDATE_PERMISSIONS[permission]
    if permission in TOKEN_CREATE_PERMISSIONS or permission in KEY_CREATE_PERMISSIONS:
        return Severity.HIGH
    if permission in TAG_ATTACH_PERMISSIONS:
        return Severity.LOW
    return Severity.INFO


def role_permissions(
    role: str, custom_roles: dict[str, frozenset[str]]
) -> frozenset[str]:
    """Resolve a role name to its (escalation-relevant) permission set.

    Custom roles supplied by the environment take precedence; otherwise the
    curated predefined map is used. Unknown roles resolve to an empty set but
    the role *name* is still tracked elsewhere for tier-zero detection.
    """
    if role in custom_roles:
        return custom_roles[role]
    return PREDEFINED_ROLE_PERMISSIONS.get(role, frozenset())

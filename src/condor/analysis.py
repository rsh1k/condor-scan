"""Pre-computation layer: turn an Environment into queryable index structures.

This separates the (pure, cacheable) work of expanding roles and bindings from
the escalation engine that walks them. Keeping it separate makes both halves
straightforward to unit-test.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .knowledge import (
    ACT_AS_PERMISSIONS,
    KEY_CREATE_PERMISSIONS,
    TOKEN_CREATE_PERMISSIONS,
    role_permissions,
)
from .model import Binding, Environment


@dataclass
class ConditionalGrant:
    """A role granted to a member only when an IAM Condition holds."""

    role: str
    permissions: frozenset[str]
    condition_title: str
    condition_expression: str
    resource: str


@dataclass(frozen=True)
class GrantRecord:
    """An unconditional binding that granted a role to a principal.

    Retained so escalation steps can be attributed back to the specific,
    remediable binding that enabled them (used by choke-point analysis).
    """

    role: str
    resource: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class ImpersonationGrant:
    """A binding on a service-account resource that lets a member act as it."""

    role: str
    resource: str
    permissions: frozenset[str]


@dataclass
class PrincipalIndex:
    """Everything we need to know about one principal's starting position."""

    member: str
    permissions: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    conditional_grants: list[ConditionalGrant] = field(default_factory=list)
    grants: list[GrantRecord] = field(default_factory=list)


@dataclass
class ServiceAccountIndex:
    """A service account's own privileges and who can impersonate it."""

    email: str
    permissions: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    # member -> impersonation grants that member holds on this SA
    impersonators: dict[str, list[ImpersonationGrant]] = field(
        default_factory=dict
    )


@dataclass
class AnalysisContext:
    """The fully indexed environment passed to the escalation engine."""

    principals: dict[str, PrincipalIndex]
    service_accounts: dict[str, ServiceAccountIndex]
    custom_roles: dict[str, frozenset[str]]
    group_members: dict[str, tuple[str, ...]]
    exposed_principals: tuple[str, ...] = ()

    def members_including_groups(self, member: str) -> set[str]:
        """Resolve a member to itself plus any groups that contain it.

        Used so that a conditional binding granted to a *group* is recognised
        as applying to its members.
        """
        result = {member}
        for group, members in self.group_members.items():
            if member in members:
                result.add(group)
        return result

    def untrusted_sources(self) -> set[str]:
        """Members that an attacker can act as without prior access.

        These are the "initial access" footholds: the public IAM members
        ``allUsers`` / ``allAuthenticatedUsers`` (when actually bound to
        something), plus any principals declared internet-exposed in the export
        (e.g. service accounts attached to a public Cloud Run service).
        """
        sources = set(self.exposed_principals)
        for special in ("allUsers", "allAuthenticatedUsers"):
            if special in self.principals:
                sources.add(special)
        return sources


_SA_RESOURCE_MARKER = "serviceAccounts/"


def _sa_email_from_resource(resource: str) -> str | None:
    if _SA_RESOURCE_MARKER not in resource:
        return None
    return resource.rsplit("/", 1)[-1]


def build_context(env: Environment) -> AnalysisContext:
    """Index an :class:`Environment` for escalation analysis."""
    custom_roles = {name: role.permissions for name, role in env.roles.items()}

    principals: dict[str, PrincipalIndex] = {}
    service_accounts: dict[str, ServiceAccountIndex] = {}

    def principal(member: str) -> PrincipalIndex:
        return principals.setdefault(member, PrincipalIndex(member=member))

    def service_account(email: str) -> ServiceAccountIndex:
        return service_accounts.setdefault(
            email, ServiceAccountIndex(email=email)
        )

    for policy in env.iam_policies:
        sa_email = _sa_email_from_resource(policy.resource)
        for binding in policy.bindings:
            perms = role_permissions(binding.role, custom_roles)
            for member in binding.members:
                _apply_binding(
                    member=member,
                    binding=binding,
                    perms=perms,
                    resource=policy.resource,
                    principal=principal,
                )
                # If this policy is attached to a service account, the binding
                # describes who may impersonate that SA.
                if sa_email is not None:
                    _record_impersonation(
                        sa=service_account(sa_email),
                        member=member,
                        role=binding.role,
                        resource=policy.resource,
                        perms=perms,
                    )
            # A service account that is itself a *member* gains those perms.
            for member in binding.members:
                if member.startswith("serviceAccount:"):
                    email = member.split(":", 1)[1]
                    sa = service_account(email)
                    sa.permissions.update(perms)
                    sa.roles.add(binding.role)

    return AnalysisContext(
        principals=principals,
        service_accounts=service_accounts,
        custom_roles=custom_roles,
        group_members=dict(env.group_members),
        exposed_principals=tuple(env.exposed_principals),
    )


def _apply_binding(
    *,
    member: str,
    binding: Binding,
    perms: frozenset[str],
    resource: str,
    principal: Callable[[str], PrincipalIndex],
) -> None:
    idx = principal(member)
    if binding.is_conditional:
        assert binding.condition is not None
        idx.conditional_grants.append(
            ConditionalGrant(
                role=binding.role,
                permissions=perms,
                condition_title=binding.condition.title,
                condition_expression=binding.condition.expression,
                resource=resource,
            )
        )
    else:
        idx.permissions.update(perms)
        idx.roles.add(binding.role)
        idx.grants.append(
            GrantRecord(role=binding.role, resource=resource, permissions=perms)
        )


def _record_impersonation(
    *,
    sa: ServiceAccountIndex,
    member: str,
    role: str,
    resource: str,
    perms: frozenset[str],
) -> None:
    relevant = perms & (
        TOKEN_CREATE_PERMISSIONS | KEY_CREATE_PERMISSIONS | ACT_AS_PERMISSIONS
    )
    if relevant:
        sa.impersonators.setdefault(member, []).append(
            ImpersonationGrant(role=role, resource=resource, permissions=relevant)
        )

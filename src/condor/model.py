"""Domain model for GCP IAM analysis.

These dataclasses mirror the shape of data returned by Cloud Asset Inventory
(`gcloud asset` exports) while staying small enough to reason about and test
offline. Everything here is pure data with no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PrincipalType(str, Enum):
    """The kind of IAM member, parsed from the member-string prefix."""

    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "serviceAccount"
    DOMAIN = "domain"
    ALL_USERS = "allUsers"
    ALL_AUTHENTICATED = "allAuthenticatedUsers"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Principal:
    """An IAM member such as ``user:alice@example.com``.

    The ``member`` string is the canonical IAM representation. ``allUsers`` and
    ``allAuthenticatedUsers`` are special members that carry no colon.
    """

    member: str

    @property
    def type(self) -> PrincipalType:
        if self.member in ("allUsers", "allAuthenticatedUsers"):
            return (
                PrincipalType.ALL_USERS
                if self.member == "allUsers"
                else PrincipalType.ALL_AUTHENTICATED
            )
        prefix = self.member.split(":", 1)[0] if ":" in self.member else ""
        try:
            return PrincipalType(prefix)
        except ValueError:
            return PrincipalType.UNKNOWN

    @property
    def identifier(self) -> str:
        """The portion after the type prefix (e.g. the email address)."""
        return self.member.split(":", 1)[1] if ":" in self.member else self.member

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.member


@dataclass(frozen=True)
class Condition:
    """A CEL condition attached to an IAM binding (IAM Conditions)."""

    title: str
    expression: str
    description: str = ""


@dataclass(frozen=True)
class Binding:
    """A single role-to-members binding, optionally conditional."""

    role: str
    members: tuple[str, ...]
    condition: Condition | None = None

    @property
    def is_conditional(self) -> bool:
        return self.condition is not None


@dataclass
class IamPolicy:
    """The IAM policy attached to one resource (project, folder, org, or SA)."""

    resource: str
    bindings: list[Binding] = field(default_factory=list)


@dataclass(frozen=True)
class Role:
    """A role and the set of permissions it grants."""

    name: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class TagBinding:
    """A namespaced tag value bound to a resource (e.g. ``123/env/prod``)."""

    resource: str
    tag_value: str


@dataclass
class Environment:
    """A complete snapshot of the IAM-relevant state of a GCP organization.

    ``roles`` contains custom-role definitions discovered in the export. Known
    predefined roles are supplied by :mod:`condor.knowledge` and merged at
    analysis time, so callers only need to populate custom roles here.
    """

    iam_policies: list[IamPolicy] = field(default_factory=list)
    roles: dict[str, Role] = field(default_factory=dict)
    tag_bindings: list[TagBinding] = field(default_factory=list)
    # Optional group -> member mapping for transitive membership resolution.
    group_members: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # Principals known to be reachable from untrusted networks (e.g. a service
    # account attached to a public Cloud Run service). Used for exposure-aware
    # attack-path analysis.
    exposed_principals: tuple[str, ...] = ()

    def service_account_resources(self) -> set[str]:
        """Return the IAM-policy resource paths that refer to service accounts."""
        return {
            p.resource
            for p in self.iam_policies
            if "serviceAccounts/" in p.resource
        }

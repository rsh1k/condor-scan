"""Tests for the domain model."""

from __future__ import annotations

from condor_scan.model import Binding, Condition, Principal, PrincipalType


def test_principal_type_parsing():
    assert Principal("user:a@x.com").type is PrincipalType.USER
    assert Principal("group:g@x.com").type is PrincipalType.GROUP
    assert (
        Principal("serviceAccount:s@p.iam.gserviceaccount.com").type
        is PrincipalType.SERVICE_ACCOUNT
    )
    assert Principal("allUsers").type is PrincipalType.ALL_USERS
    assert Principal("allAuthenticatedUsers").type is PrincipalType.ALL_AUTHENTICATED


def test_principal_identifier():
    assert Principal("user:a@x.com").identifier == "a@x.com"
    assert Principal("allUsers").identifier == "allUsers"


def test_unknown_principal_type():
    assert Principal("weird:thing").type is PrincipalType.UNKNOWN


def test_binding_conditional_flag():
    plain = Binding(role="roles/viewer", members=("user:a@x.com",))
    assert not plain.is_conditional
    conditional = Binding(
        role="roles/editor",
        members=("user:a@x.com",),
        condition=Condition(title="t", expression="resource.matchTag('k','v')"),
    )
    assert conditional.is_conditional

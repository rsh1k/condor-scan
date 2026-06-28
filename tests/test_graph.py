"""Tests for the attack-path intelligence layer (graph.py)."""

from __future__ import annotations

from condor_scan import analyze_posture, build_context, load_from_dict
from condor_scan.graph import _greedy_choke_points
from condor_scan.techniques import TECHNIQUE_BY_RULE, is_step_logged


def _posture(data: dict):
    return analyze_posture(build_context(load_from_dict(data)))


# --- exposure analysis ---------------------------------------------------
def test_exposed_principal_reaching_tier_zero_is_flagged():
    report = _posture(
        {
            "exposed_principals": [
                "serviceAccount:front@p.iam.gserviceaccount.com"
            ],
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [
                                "serviceAccount:priv@p.iam.gserviceaccount.com"
                            ],
                        }
                    ],
                },
                {
                    "resource": "//iam/projects/p/serviceAccounts/priv@p.iam.gserviceaccount.com",
                    "bindings": [
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": [
                                "serviceAccount:front@p.iam.gserviceaccount.com"
                            ],
                        }
                    ],
                },
            ],
        }
    )
    # The exposed front SA reaches the owner SA -> both are exposed Tier Zero.
    assert "serviceAccount:front@p.iam.gserviceaccount.com" in report.exposed_tier_zero
    assert "serviceAccount:priv@p.iam.gserviceaccount.com" in report.exposed_tier_zero


def test_all_users_is_an_untrusted_source():
    report = _posture(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.projectIamAdmin",
                            "members": ["allUsers"],
                        }
                    ],
                }
            ]
        }
    )
    assert "allUsers" in report.untrusted_sources
    assert "allUsers" in report.exposed_tier_zero


def test_internal_only_escalation_is_not_exposed():
    report = _posture(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.projectIamAdmin",
                            "members": ["user:carol@x.com"],
                        }
                    ],
                }
            ]
        }
    )
    assert report.tier_zero_principals == ["user:carol@x.com"]
    assert report.exposed_tier_zero == []


# --- choke-point analysis ------------------------------------------------
def test_shared_grant_is_a_single_choke_point():
    # Two members of one group share a conditional Owner grant; both can tag.
    report = _posture(
        {
            "group_members": {
                "group:plat@x.com": ["user:a@x.com", "user:b@x.com"]
            },
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.tagUser",
                            "members": ["user:a@x.com", "user:b@x.com"],
                        },
                        {
                            "role": "roles/owner",
                            "members": ["group:plat@x.com"],
                            "condition": {
                                "title": "prod",
                                "expression": "resource.matchTag('123/env','prod')",
                            },
                        },
                    ],
                }
            ],
        }
    )
    # Both a and b reach Tier Zero, but through ONE shared group binding.
    assert set(report.tier_zero_principals) == {"user:a@x.com", "user:b@x.com"}
    assert report.remediation_budget == 1
    assert report.choke_points[0].enabler.member == "group:plat@x.com"
    assert set(report.choke_points[0].covers) == {"user:a@x.com", "user:b@x.com"}


def test_greedy_cover_picks_highest_leverage_first():
    from condor_scan.findings import Enabler, Finding, Severity

    shared = Enabler(kind="binding", role="roles/owner", member="g", resource="r")
    solo = Enabler(kind="binding", role="roles/x", member="u3", resource="r2")
    findings = [
        Finding("u1", Severity.CRITICAL, "", "", enablers=[shared]),
        Finding("u2", Severity.CRITICAL, "", "", enablers=[shared]),
        Finding("u3", Severity.CRITICAL, "", "", enablers=[shared, solo]),
    ]
    plan = _greedy_choke_points(findings)
    # First pick must be the shared enabler (covers all three).
    assert plan[0].enabler.key == shared.key
    assert set(plan[0].covers) == {"u1", "u2", "u3"}
    assert len(plan) == 1  # one grant covers everyone


# --- detection blind spots ----------------------------------------------
def test_tag_condition_is_a_blind_spot():
    report = _posture(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.tagUser",
                            "members": ["user:a@x.com"],
                        },
                        {
                            "role": "roles/owner",
                            "members": ["user:a@x.com"],
                            "condition": {
                                "title": "prod",
                                "expression": "resource.matchTag('123/env','prod')",
                            },
                        },
                    ],
                }
            ]
        }
    )
    rule_ids = {bs.step.rule_id for bs in report.blind_spots}
    assert "CONDOR-TAGCONDITION" in rule_ids


def test_set_iam_policy_is_not_a_blind_spot():
    report = _posture(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.projectIamAdmin",
                            "members": ["user:carol@x.com"],
                        }
                    ],
                }
            ]
        }
    )
    # setIamPolicy is in Admin Activity logs (always on) -> not a blind spot.
    assert report.blind_spots == []


def test_token_impersonation_silent_but_key_creation_logged():
    assert not is_step_logged(
        "CONDOR-IMPERSONATE", "impersonate 'x' via 'iam.serviceAccounts.getAccessToken'"
    )
    assert is_step_logged(
        "CONDOR-IMPERSONATE", "impersonate 'x' via 'iam.serviceAccountKeys.create'"
    )


def test_every_rule_has_a_technique_mapping():
    for rule_id in (
        "CONDOR-SEED",
        "CONDOR-SETIAMPOLICY",
        "CONDOR-ROLEUPDATE",
        "CONDOR-IMPERSONATE",
        "CONDOR-TAGCONDITION",
    ):
        assert rule_id in TECHNIQUE_BY_RULE
        assert TECHNIQUE_BY_RULE[rule_id].id.startswith("T")


# --- report serialization ------------------------------------------------
def test_posture_report_serializes():
    report = _posture(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.projectIamAdmin",
                            "members": ["user:carol@x.com"],
                        }
                    ],
                }
            ]
        }
    )
    data = report.to_dict()
    assert data["metrics"]["can_reach_tier_zero"] == 1
    assert "PRIORITISED REMEDIATION PLAN" in report.to_text()


def test_empty_environment_has_clean_posture():
    report = _posture({"iam_policies": []})
    assert report.tier_zero_principals == []
    assert "No Tier-Zero escalation" in report.to_text()

"""Tests for the escalation engine -- the heart of the tool.

Each test constructs a focused environment that isolates one escalation path,
asserts the finding, severity, and that the attack chain is captured.
"""

from __future__ import annotations

from condor_scan import EscalationEngine, Severity, build_context, load_from_dict


def _engine(data: dict) -> EscalationEngine:
    return EscalationEngine(build_context(load_from_dict(data)))


def _finding_for(engine: EscalationEngine, member: str):
    return engine.analyze(member)


# --- benign negative case ------------------------------------------------
def test_viewer_has_no_finding():
    engine = _engine(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {"role": "roles/viewer", "members": ["user:dave@x.com"]}
                    ],
                }
            ]
        }
    )
    assert _finding_for(engine, "user:dave@x.com") is None


# --- self-grant via setIamPolicy ----------------------------------------
def test_set_iam_policy_is_critical():
    engine = _engine(
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
    finding = _finding_for(engine, "user:carol@x.com")
    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert any(s.rule_id == "CONDOR-SETIAMPOLICY" for s in finding.path)


# --- service-account impersonation via token creator --------------------
def test_token_creator_reaches_owner_sa():
    engine = _engine(
        {
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
                            "members": ["user:bob@x.com"],
                        }
                    ],
                },
            ]
        }
    )
    finding = _finding_for(engine, "user:bob@x.com")
    assert finding is not None
    assert finding.severity is Severity.CRITICAL  # SA holds owner
    assert any(s.rule_id == "CONDOR-IMPERSONATE" for s in finding.path)


# --- actAs + deploy permission chain ------------------------------------
def test_actas_plus_deploy_reaches_sa():
    engine = _engine(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        # eve can deploy Cloud Functions ...
                        {
                            "role": "roles/cloudfunctions.developer",
                            "members": ["user:eve@x.com"],
                        },
                        # ... and the target SA holds owner.
                        {
                            "role": "roles/owner",
                            "members": [
                                "serviceAccount:priv@p.iam.gserviceaccount.com"
                            ],
                        },
                    ],
                },
                {
                    "resource": "//iam/projects/p/serviceAccounts/priv@p.iam.gserviceaccount.com",
                    "bindings": [
                        # ... and eve can actAs it (serviceAccountUser).
                        {
                            "role": "roles/iam.serviceAccountUser",
                            "members": ["user:eve@x.com"],
                        }
                    ],
                },
            ]
        }
    )
    finding = _finding_for(engine, "user:eve@x.com")
    assert finding is not None
    assert any("actAs" in s.detail for s in finding.path)


# --- tag-based conditional escalation (the novel path) ------------------
def test_tag_conditional_escalation():
    engine = _engine(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.tagUser",
                            "members": ["user:alice@x.com"],
                        },
                        {
                            "role": "roles/owner",
                            "members": ["user:alice@x.com"],
                            "condition": {
                                "title": "prod-only",
                                "expression": "resource.matchTag('123/env','prod')",
                            },
                        },
                    ],
                }
            ]
        }
    )
    finding = _finding_for(engine, "user:alice@x.com")
    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert any(s.rule_id == "CONDOR-TAGCONDITION" for s in finding.path)


def test_tag_conditional_requires_tag_attach_permission():
    # Same conditional owner grant, but alice cannot attach tags -> no escalation.
    engine = _engine(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {"role": "roles/viewer", "members": ["user:alice@x.com"]},
                        {
                            "role": "roles/owner",
                            "members": ["user:alice@x.com"],
                            "condition": {
                                "title": "prod-only",
                                "expression": "resource.matchTag('123/env','prod')",
                            },
                        },
                    ],
                }
            ]
        }
    )
    assert _finding_for(engine, "user:alice@x.com") is None


def test_tag_conditional_via_group_membership():
    # The conditional grant is to a group; alice is a member and can tag.
    engine = _engine(
        {
            "group_members": {"group:plat@x.com": ["user:alice@x.com"]},
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.tagUser",
                            "members": ["user:alice@x.com"],
                        },
                        {
                            "role": "roles/owner",
                            "members": ["group:plat@x.com"],
                            "condition": {
                                "title": "prod-only",
                                "expression": "resource.matchTag('123/env','prod')",
                            },
                        },
                    ],
                }
            ],
        }
    )
    finding = _finding_for(engine, "user:alice@x.com")
    assert finding is not None
    assert finding.severity is Severity.CRITICAL


def test_non_escalatory_tag_condition_ignored():
    # Conditional grant of a harmless role under a tag condition: not a finding.
    engine = _engine(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/resourcemanager.tagUser",
                            "members": ["user:alice@x.com"],
                        },
                        {
                            "role": "roles/viewer",
                            "members": ["user:alice@x.com"],
                            "condition": {
                                "title": "prod-only",
                                "expression": "resource.matchTag('123/env','prod')",
                            },
                        },
                    ],
                }
            ]
        }
    )
    finding = _finding_for(engine, "user:alice@x.com")
    # tagUser alone is only LOW; no escalation step should be present.
    assert finding is None or all(
        s.rule_id != "CONDOR-TAGCONDITION" for s in finding.path
    )


# --- role update self-grant ---------------------------------------------
def test_role_update_self_grant():
    engine = _engine(
        {
            "roles": {"roles/custom.cicd": ["iam.roles.update"]},
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/custom.cicd",
                            "members": ["user:frank@x.com"],
                        }
                    ],
                }
            ],
        }
    )
    finding = _finding_for(engine, "user:frank@x.com")
    assert finding is not None
    assert any(s.rule_id == "CONDOR-ROLEUPDATE" for s in finding.path)


# --- analyze_all aggregates ---------------------------------------------
def test_analyze_all_only_returns_real_findings():
    engine = _engine(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {"role": "roles/viewer", "members": ["user:dave@x.com"]},
                        {
                            "role": "roles/resourcemanager.projectIamAdmin",
                            "members": ["user:carol@x.com"],
                        },
                    ],
                }
            ]
        }
    )
    findings = engine.analyze_all()
    principals = {f.principal for f in findings}
    assert "user:carol@x.com" in principals
    assert "user:dave@x.com" not in principals

"""Tests for output serialization and constraint generation."""

from __future__ import annotations

import json

from condor.constraints import generate_constraint_yaml, generate_rego
from condor.findings import (
    EscalationStep,
    Finding,
    Severity,
    render,
    to_json,
    to_sarif,
    to_table,
)


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            principal="user:carol@x.com",
            severity=Severity.CRITICAL,
            summary="escalates",
            reaches="roles/owner (full control)",
            path=[
                EscalationStep("CONDOR-SETIAMPOLICY", "Self-grant", "setIamPolicy")
            ],
            references=["https://example.org"],
            remediation="remove permission",
        )
    ]


def test_severity_ordering_and_labels():
    assert Severity.CRITICAL > Severity.HIGH > Severity.LOW
    assert Severity.HIGH.label == "High"
    assert Severity.from_name("critical") is Severity.CRITICAL


def test_json_output_is_valid_and_structured():
    payload = json.loads(to_json(_sample_findings()))
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["severity"] == "Critical"
    assert payload["findings"][0]["path"][0]["rule_id"] == "CONDOR-SETIAMPOLICY"


def test_sarif_output_is_valid_2_1_0():
    sarif = json.loads(to_sarif(_sample_findings()))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "condor-scan"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["properties"]["security-severity"] == "9.5"


def test_table_output_contains_principal():
    table = to_table(_sample_findings())
    assert "carol@x.com" in table
    assert "Critical" in table


def test_empty_table():
    assert "No privilege-escalation findings." in to_table([])


def test_render_dispatch_and_unknown_format():
    assert render([], "json")
    try:
        render([], "yaml")
    except ValueError as exc:
        assert "unknown output format" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_generate_rego_flags_escalation_roles():
    rego = generate_rego()
    assert "resource.matchTag(" in rego
    assert "roles/owner" in rego
    assert "deny[" in rego


def test_generate_constraint_yaml():
    yaml = generate_constraint_yaml("my-constraint")
    assert "my-constraint" in yaml
    assert "GCPIAMTagConditionEscalationConstraintV1" in yaml

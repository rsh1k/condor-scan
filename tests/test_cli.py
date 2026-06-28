"""End-to-end tests for the CLI."""

from __future__ import annotations

import json
from pathlib import Path

from condor_scan.cli import main

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_export.json"


def test_scan_example_table(capsys):
    rc = main(["scan", str(EXAMPLE), "--format", "table"])
    out = capsys.readouterr().out
    assert rc == 0
    # alice (tag), bob (impersonation), carol (setIamPolicy), eve, frank expected.
    assert "alice@example.com" in out
    assert "carol@example.com" in out
    assert "dave@example.com" not in out  # viewer only


def test_scan_example_json(capsys):
    rc = main(["scan", str(EXAMPLE), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["finding_count"] >= 4
    principals = {f["principal"] for f in payload["findings"]}
    assert "user:alice@example.com" in principals


def test_scan_fail_on_critical_exits_nonzero(capsys):
    rc = main(["scan", str(EXAMPLE), "--format", "json", "--fail-on", "critical"])
    capsys.readouterr()
    assert rc == 1  # carol/bob reach CRITICAL


def test_scan_missing_file_is_usage_error(capsys):
    rc = main(["scan", "/nonexistent/path.json"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error:" in err


def test_gen_constraints_to_stdout(capsys):
    rc = main(["gen-constraints"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "resource.matchTag(" in out
    assert "GCPIAMTagConditionEscalationConstraintV1" in out


def test_gen_constraints_to_dir(tmp_path, capsys):
    rc = main(["gen-constraints", "--out-dir", str(tmp_path)])
    capsys.readouterr()
    assert rc == 0
    assert (tmp_path / "tag_condition_escalation.rego").exists()
    assert (tmp_path / "tag_condition_escalation.yaml").exists()


def test_posture_text_report(capsys):
    rc = main(["posture", str(EXAMPLE), "--format", "text"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "attack-path posture report" in out
    assert "PRIORITISED REMEDIATION PLAN" in out
    assert "EXTERNALLY EXPOSED PATHS TO TIER ZERO" in out


def test_posture_json_report(capsys):
    rc = main(["posture", str(EXAMPLE), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["report"] == "attack-path-posture"
    assert payload["metrics"]["externally_exposed_to_tier_zero"] >= 1


def test_posture_fail_on_exposed_exits_nonzero(capsys):
    rc = main(["posture", str(EXAMPLE), "--fail-on-exposed"])
    capsys.readouterr()
    assert rc == 1  # the example contains an exposed Tier-Zero path


def test_posture_as_of_inside_break_glass_window(capsys):
    # The example's oncall break-glass window is open at this instant.
    rc = main(
        ["posture", str(EXAMPLE), "--format", "json", "--as-of", "2027-03-01T09:00:00Z"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert "user:oncall@example.com" in payload["active_jit_escalations"]


def test_posture_default_time_shows_oncall_as_scheduled(capsys):
    # As of 2026 (well before the 2027 window) the grant is dormant, not live.
    rc = main(
        ["posture", str(EXAMPLE), "--format", "json", "--as-of", "2026-06-28T00:00:00Z"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    members = {s["member"] for s in payload["scheduled_escalations"]}
    assert "user:oncall@example.com" in members
    # The expired contractor grant is neither live nor scheduled.
    assert "user:contractor@example.com" not in payload["active_jit_escalations"]


def test_scan_invalid_as_of_is_usage_error(capsys):
    rc = main(["scan", str(EXAMPLE), "--as-of", "not-a-timestamp"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error:" in err

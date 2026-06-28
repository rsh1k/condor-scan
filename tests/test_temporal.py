"""Tests for the temporal / JIT dimension."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from condor_scan import EscalationEngine, analyze_posture, build_context, load_from_dict
from condor_scan.temporal import (
    TemporalStatus,
    parse_temporal_window,
    parse_timestamp,
)

# A fixed reference instant so tests never depend on the wall clock.
NOW = datetime(2026, 6, 28, 9, 0, tzinfo=timezone.utc)


# --- timestamp + window parsing -----------------------------------------
def test_parse_timestamp_normalises_z_suffix():
    dt = parse_timestamp("2026-06-28T09:00:00Z")
    assert dt == datetime(2026, 6, 28, 9, 0, tzinfo=timezone.utc)


def test_parse_naive_timestamp_assumed_utc():
    dt = parse_timestamp("2026-06-28T09:00:00")
    assert dt is not None and dt.tzinfo is timezone.utc


def test_window_expiry_only():
    w = parse_temporal_window("request.time < timestamp('2026-12-31T00:00:00Z')")
    assert w.not_after is not None and w.not_before is None
    assert w.status(NOW) is TemporalStatus.ACTIVE


def test_window_two_sided_and_status():
    expr = (
        "request.time > timestamp('2026-06-28T08:00:00Z') && "
        "request.time < timestamp('2026-06-28T12:00:00Z')"
    )
    w = parse_temporal_window(expr)
    assert w.status(NOW) is TemporalStatus.ACTIVE
    assert w.status(datetime(2026, 6, 28, 13, 0, tzinfo=timezone.utc)) is (
        TemporalStatus.EXPIRED
    )
    assert w.status(datetime(2026, 6, 28, 7, 0, tzinfo=timezone.utc)) is (
        TemporalStatus.FUTURE
    )


def test_window_reversed_operand_order():
    # timestamp(...) < request.time  is a lower bound.
    w = parse_temporal_window("timestamp('2026-06-28T08:00:00Z') < request.time")
    assert w.not_before is not None and w.not_after is None


def test_no_time_bound_is_always():
    w = parse_temporal_window("resource.matchTag('123/env','prod')")
    assert w.status(NOW) is TemporalStatus.ALWAYS
    assert not w.is_bounded


def test_jit_detection():
    short = parse_temporal_window(
        "request.time > timestamp('2026-06-28T08:00:00Z') && "
        "request.time < timestamp('2026-06-28T12:00:00Z')"
    )
    long = parse_temporal_window(
        "request.time > timestamp('2026-01-01T00:00:00Z') && "
        "request.time < timestamp('2026-12-31T00:00:00Z')"
    )
    assert short.is_jit(timedelta(hours=24))
    assert not long.is_jit(timedelta(hours=24))


# --- engine gating -------------------------------------------------------
def _engine(data: dict, now: datetime) -> EscalationEngine:
    return EscalationEngine(build_context(load_from_dict(data)), now=now)


_JIT_OWNER = {
    "iam_policies": [
        {
            "resource": "//x/projects/p",
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:oncall@x.com"],
                    "condition": {
                        "title": "break-glass",
                        "expression": (
                            "request.time > timestamp('2026-06-28T08:00:00Z') && "
                            "request.time < timestamp('2026-06-28T12:00:00Z')"
                        ),
                    },
                }
            ],
        }
    ]
}


def test_active_jit_grant_is_a_finding():
    engine = _engine(_JIT_OWNER, NOW)
    finding = engine.analyze("user:oncall@x.com")
    assert finding is not None
    assert finding.jit is True
    assert finding.expires_at == "2026-06-28T12:00:00+00:00"
    assert any(s.rule_id == "CONDOR-JITGRANT" for s in finding.path)


def test_expired_grant_is_not_a_finding():
    later = datetime(2026, 6, 28, 18, 0, tzinfo=timezone.utc)
    engine = _engine(_JIT_OWNER, later)
    assert engine.analyze("user:oncall@x.com") is None


def test_future_grant_is_not_a_live_finding():
    earlier = datetime(2026, 6, 28, 6, 0, tzinfo=timezone.utc)
    engine = _engine(_JIT_OWNER, earlier)
    assert engine.analyze("user:oncall@x.com") is None


def test_expired_tag_condition_is_suppressed():
    # A tag-based conditional Owner grant whose window has passed must NOT be
    # reported as a live escalation (this is the false-positive fix).
    data = {
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
                            "title": "expired-prod",
                            "expression": (
                                "resource.matchTag('123/env','prod') && "
                                "request.time < timestamp('2025-01-01T00:00:00Z')"
                            ),
                        },
                    },
                ],
            }
        ]
    }
    engine = _engine(data, NOW)
    assert engine.analyze("user:a@x.com") is None


def test_resource_scoped_condition_not_flagged():
    # A non-tag, non-time conditional grant (resource-scoped) is intentionally
    # NOT treated as escalation, to avoid false positives on legit scoping.
    data = {
        "iam_policies": [
            {
                "resource": "//x/projects/p",
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": ["user:a@x.com"],
                        "condition": {
                            "title": "one-project",
                            "expression": "resource.name.startsWith('projects/p')",
                        },
                    }
                ],
            }
        ]
    }
    engine = _engine(data, NOW)
    assert engine.analyze("user:a@x.com") is None


# --- posture integration -------------------------------------------------
def test_posture_lists_active_jit_and_future_dormant():
    data = {
        "iam_policies": [
            {
                "resource": "//x/projects/p",
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": ["user:oncall@x.com"],
                        "condition": {
                            "title": "break-glass",
                            "expression": (
                                "request.time > timestamp('2026-06-28T08:00:00Z') && "
                                "request.time < timestamp('2026-06-28T12:00:00Z')"
                            ),
                        },
                    },
                    {
                        "role": "roles/owner",
                        "members": ["user:intern@x.com"],
                        "condition": {
                            "title": "starts-later",
                            "expression": (
                                "request.time > timestamp('2030-01-01T00:00:00Z')"
                            ),
                        },
                    },
                ],
            }
        ]
    }
    ctx = build_context(load_from_dict(data))
    report = analyze_posture(ctx, EscalationEngine(ctx, now=NOW))
    assert "user:oncall@x.com" in report.jit_escalations
    scheduled_members = {s.member for s in report.scheduled_escalations}
    assert "user:intern@x.com" in scheduled_members
    assert report.evaluated_at == NOW.isoformat()
    text = report.to_text()
    assert "ACTIVE JIT ESCALATION" in text
    assert "SCHEDULED / DORMANT ESCALATION" in text

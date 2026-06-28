"""Temporal analysis of IAM Conditions.

IAM Conditions frequently carry time bounds expressed in CEL against
``request.time``::

    request.time < timestamp('2026-12-31T00:00:00Z')                  # expiry
    request.time > timestamp('2026-06-01T00:00:00Z') &&
        request.time < timestamp('2026-06-01T04:00:00Z')              # JIT window

These matter for escalation analysis in three ways:

  * An **expired** conditional grant is not exploitable now. Flagging it as a
    live escalation is a false positive that wastes responder time.
  * A **future** grant is latent risk - not exploitable yet, but it will be.
  * An **active short-lived (JIT)** grant is a live monitoring priority: it is
    exactly the window in which a break-glass grant is (mis)used, and a periodic
    scanner can easily miss a grant that only exists for a couple of hours.

This module parses ``request.time`` bounds into a :class:`TemporalWindow` and
classifies it relative to a supplied "now", so the engine can decide whether a
conditional escalation is live, dead, or dormant, and whether it is JIT.

The parser is conservative: only ``request.time`` compared against
``timestamp('...')`` literals is understood. Anything else leaves that side of
the window unbounded, which is the safe default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

# request.time <op> timestamp('ISO')   and the reversed operand order.
_TIME_LEFT = re.compile(
    r"request\.time\s*(<=|>=|<|>)\s*timestamp\(\s*['\"]([^'\"]+)['\"]\s*\)"
)
_TIME_RIGHT = re.compile(
    r"timestamp\(\s*['\"]([^'\"]+)['\"]\s*\)\s*(<=|>=|<|>)\s*request\.time"
)


class TemporalStatus(str, Enum):
    """A conditional grant's validity relative to a reference time."""

    ALWAYS = "always"  # no time bound at all
    ACTIVE = "active"  # currently within its validity window
    EXPIRED = "expired"  # window has passed
    FUTURE = "future"  # window has not started yet


def parse_timestamp(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, normalising to timezone-aware UTC."""
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass(frozen=True)
class TemporalWindow:
    """The time interval during which a condition can hold.

    ``not_before`` / ``not_after`` are ``None`` when that side is unbounded.
    A window with both sides ``None`` means the condition has no time bound.
    """

    not_before: datetime | None = None
    not_after: datetime | None = None

    @property
    def is_bounded(self) -> bool:
        return self.not_before is not None or self.not_after is not None

    def duration(self) -> timedelta | None:
        """Total validity length, if both ends are known."""
        if self.not_before is not None and self.not_after is not None:
            return self.not_after - self.not_before
        return None

    def status(self, now: datetime) -> TemporalStatus:
        if not self.is_bounded:
            return TemporalStatus.ALWAYS
        if self.not_after is not None and now > self.not_after:
            return TemporalStatus.EXPIRED
        if self.not_before is not None and now < self.not_before:
            return TemporalStatus.FUTURE
        return TemporalStatus.ACTIVE

    def is_active(self, now: datetime) -> bool:
        return self.status(now) in (TemporalStatus.ACTIVE, TemporalStatus.ALWAYS)

    def is_jit(self, threshold: timedelta) -> bool:
        """True if this is a short-lived grant (total lifetime <= threshold)."""
        duration = self.duration()
        return duration is not None and duration <= threshold

    def expires_within(self, now: datetime, threshold: timedelta) -> bool:
        if self.not_after is None:
            return False
        remaining = self.not_after - now
        return timedelta(0) <= remaining <= threshold

    def to_dict(self) -> dict[str, str | None]:
        return {
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
        }


# A window with no bounds: the temporal status of an unconditional-in-time grant.
UNBOUNDED = TemporalWindow()


def parse_temporal_window(expression: str) -> TemporalWindow:
    """Extract the ``request.time`` validity window from a CEL expression.

    Multiple bounds combine conservatively: the latest lower bound and the
    earliest upper bound win (the intersection of all stated constraints).
    """
    lowers: list[datetime] = []
    uppers: list[datetime] = []

    def record(op: str, ts: datetime) -> None:
        if op in ("<", "<="):
            uppers.append(ts)
        else:  # > or >=
            lowers.append(ts)

    for op, raw in _TIME_LEFT.findall(expression):
        ts = parse_timestamp(raw)
        if ts is not None:
            record(op, ts)
    # Reversed order flips the comparison direction.
    for raw, op in _TIME_RIGHT.findall(expression):
        ts = parse_timestamp(raw)
        if ts is None:
            continue
        flipped = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[op]
        record(flipped, ts)

    return TemporalWindow(
        not_before=max(lowers) if lowers else None,
        not_after=min(uppers) if uppers else None,
    )


def now_utc() -> datetime:
    """Current time as a timezone-aware UTC datetime (single source of truth)."""
    return datetime.now(timezone.utc)

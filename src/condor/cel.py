"""A conservative, well-scoped parser for IAM Condition (CEL) expressions.

We do not implement a full CEL evaluator. For escalation analysis we only need
to answer one question: *can a principal who is able to attach tags satisfy this
condition?* That requires recognising tag-based predicates:

    resource.matchTag('123456789/env', 'prod')
    resource.matchTagId('tagKeys/123', 'tagValues/456')

Anything we do not recognise is treated as **not** tag-satisfiable, which is the
safe (non-false-positive) default. Limitations are documented in the README.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# resource.matchTag('<namespaced key>', '<short value>')
_MATCH_TAG = re.compile(
    r"resource\.matchTag\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"
)
# resource.matchTagId('tagKeys/<id>', 'tagValues/<id>')
_MATCH_TAG_ID = re.compile(
    r"resource\.matchTagId\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"
)


@dataclass(frozen=True)
class TagPredicate:
    """A single tag requirement extracted from a condition."""

    key: str
    value: str
    by_id: bool


def extract_tag_predicates(expression: str) -> list[TagPredicate]:
    """Return all tag predicates found in a CEL expression."""
    predicates: list[TagPredicate] = []
    for key, value in _MATCH_TAG.findall(expression):
        predicates.append(TagPredicate(key=key, value=value, by_id=False))
    for key, value in _MATCH_TAG_ID.findall(expression):
        predicates.append(TagPredicate(key=key, value=value, by_id=True))
    return predicates


def is_tag_based(expression: str) -> bool:
    """True if the condition's satisfiability depends on resource tags."""
    return bool(extract_tag_predicates(expression))

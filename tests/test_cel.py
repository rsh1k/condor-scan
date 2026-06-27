"""Tests for the conservative CEL tag-condition parser."""

from __future__ import annotations

from condor.cel import extract_tag_predicates, is_tag_based


def test_match_tag_by_namespaced_name():
    preds = extract_tag_predicates("resource.matchTag('123/env', 'prod')")
    assert len(preds) == 1
    assert preds[0].key == "123/env"
    assert preds[0].value == "prod"
    assert preds[0].by_id is False


def test_match_tag_by_id():
    preds = extract_tag_predicates(
        "resource.matchTagId('tagKeys/1', 'tagValues/2')"
    )
    assert len(preds) == 1
    assert preds[0].by_id is True


def test_combined_expression_with_and():
    expr = (
        "request.time < timestamp('2030-01-01T00:00:00Z') && "
        "resource.matchTag('123/env', 'prod')"
    )
    assert is_tag_based(expr)


def test_non_tag_condition_is_ignored():
    assert not is_tag_based("request.time.getHours('UTC') < 17")


def test_double_quoted_arguments():
    preds = extract_tag_predicates('resource.matchTag("123/team", "core")')
    assert preds and preds[0].value == "core"

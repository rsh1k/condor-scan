"""Tests for the JSON/asset-export loaders."""

from __future__ import annotations

import json

import pytest

from condor_scan.loaders import (
    LoaderError,
    load_from_cloud_asset_inventory,
    load_from_dict,
    load_from_file,
)


def test_load_minimal_environment():
    env = load_from_dict(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {"role": "roles/viewer", "members": ["user:a@x.com"]}
                    ],
                }
            ]
        }
    )
    assert len(env.iam_policies) == 1
    assert env.iam_policies[0].bindings[0].role == "roles/viewer"


def test_load_conditional_binding():
    env = load_from_dict(
        {
            "iam_policies": [
                {
                    "resource": "//x/projects/p",
                    "bindings": [
                        {
                            "role": "roles/editor",
                            "members": ["user:a@x.com"],
                            "condition": {
                                "title": "t",
                                "expression": "resource.matchTag('k','v')",
                            },
                        }
                    ],
                }
            ]
        }
    )
    binding = env.iam_policies[0].bindings[0]
    assert binding.is_conditional
    assert binding.condition.title == "t"


def test_custom_roles_and_groups():
    env = load_from_dict(
        {
            "roles": {"roles/custom.x": ["a.b.c"]},
            "group_members": {"group:g@x.com": ["user:a@x.com"]},
        }
    )
    assert env.roles["roles/custom.x"].permissions == frozenset({"a.b.c"})
    assert env.group_members["group:g@x.com"] == ("user:a@x.com",)


def test_invalid_top_level_raises():
    with pytest.raises(LoaderError):
        load_from_dict([])  # type: ignore[arg-type]


def test_binding_without_role_raises():
    with pytest.raises(LoaderError):
        load_from_dict(
            {"iam_policies": [{"resource": "//x", "bindings": [{"members": []}]}]}
        )


def test_condition_without_expression_raises():
    with pytest.raises(LoaderError):
        load_from_dict(
            {
                "iam_policies": [
                    {
                        "resource": "//x",
                        "bindings": [
                            {
                                "role": "roles/editor",
                                "members": [],
                                "condition": {"title": "t"},
                            }
                        ],
                    }
                ]
            }
        )


def test_load_from_file(tmp_path):
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"iam_policies": []}), encoding="utf-8")
    env = load_from_file(path)
    assert env.iam_policies == []


def test_invalid_json_file_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(LoaderError):
        load_from_file(path)


def test_live_loader_is_documented_stub():
    with pytest.raises(NotImplementedError):
        load_from_cloud_asset_inventory()

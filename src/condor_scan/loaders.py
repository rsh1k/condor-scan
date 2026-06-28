"""Loaders that turn external data into an :class:`~condor.model.Environment`.

The offline JSON loader is fully implemented and is the primary, testable entry
point. It accepts a schema close to a ``gcloud asset`` export so that real
exports can be massaged into it with minimal glue. A live Cloud Asset Inventory
loader is provided as a documented stub: wiring it requires the
``google-cloud-asset`` client and credentials, which are out of scope for the
offline test suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import (
    Binding,
    Condition,
    Environment,
    IamPolicy,
    Role,
    TagBinding,
)


class LoaderError(ValueError):
    """Raised when input data does not match the expected schema."""


def load_from_dict(data: dict[str, Any]) -> Environment:
    """Build an Environment from an already-parsed dict.

    Expected shape::

        {
          "roles": {"roles/custom.x": ["perm.a", "perm.b"]},
          "iam_policies": [
            {"resource": "...", "bindings": [
              {"role": "roles/viewer", "members": ["user:a@x"],
               "condition": {"title": "t", "expression": "..."}}
            ]}
          ],
          "tag_bindings": [{"resource": "...", "tagValue": "123/env/prod"}],
          "group_members": {"group:eng@x": ["user:a@x"]}
        }
    """
    if not isinstance(data, dict):
        raise LoaderError("top-level export must be a JSON object")

    roles = _parse_roles(data.get("roles", {}))
    policies = _parse_policies(data.get("iam_policies", []))
    tag_bindings = _parse_tag_bindings(data.get("tag_bindings", []))
    group_members = _parse_group_members(data.get("group_members", {}))
    exposed = data.get("exposed_principals", [])
    if not isinstance(exposed, list):
        raise LoaderError("'exposed_principals' must be a list")

    return Environment(
        iam_policies=policies,
        roles=roles,
        tag_bindings=tag_bindings,
        group_members=group_members,
        exposed_principals=tuple(map(str, exposed)),
    )


def load_from_file(path: str | Path) -> Environment:
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"invalid JSON in {path}: {exc}") from exc
    return load_from_dict(data)


def _parse_roles(raw: Any) -> dict[str, Role]:
    if not isinstance(raw, dict):
        raise LoaderError("'roles' must be an object mapping role name -> [perms]")
    roles: dict[str, Role] = {}
    for name, perms in raw.items():
        if not isinstance(perms, list):
            raise LoaderError(f"permissions for role {name!r} must be a list")
        roles[name] = Role(name=name, permissions=frozenset(map(str, perms)))
    return roles


def _parse_policies(raw: Any) -> list[IamPolicy]:
    if not isinstance(raw, list):
        raise LoaderError("'iam_policies' must be a list")
    policies: list[IamPolicy] = []
    for entry in raw:
        if not isinstance(entry, dict) or "resource" not in entry:
            raise LoaderError("each iam_policy needs a 'resource' field")
        bindings = [_parse_binding(b) for b in entry.get("bindings", [])]
        policies.append(IamPolicy(resource=str(entry["resource"]), bindings=bindings))
    return policies


def _parse_binding(raw: Any) -> Binding:
    if not isinstance(raw, dict) or "role" not in raw:
        raise LoaderError("each binding needs a 'role' field")
    members = tuple(map(str, raw.get("members", [])))
    condition = None
    cond_raw = raw.get("condition")
    if cond_raw is not None:
        if "expression" not in cond_raw:
            raise LoaderError("condition requires an 'expression'")
        condition = Condition(
            title=str(cond_raw.get("title", "")),
            expression=str(cond_raw["expression"]),
            description=str(cond_raw.get("description", "")),
        )
    return Binding(role=str(raw["role"]), members=members, condition=condition)


def _parse_tag_bindings(raw: Any) -> list[TagBinding]:
    if not isinstance(raw, list):
        raise LoaderError("'tag_bindings' must be a list")
    out: list[TagBinding] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise LoaderError("each tag binding must be an object")
        out.append(
            TagBinding(
                resource=str(entry.get("resource", "")),
                tag_value=str(entry.get("tagValue", entry.get("tag_value", ""))),
            )
        )
    return out


def _parse_group_members(raw: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise LoaderError("'group_members' must be an object")
    return {str(g): tuple(map(str, m)) for g, m in raw.items()}


def load_from_cloud_asset_inventory(
    *_args: object, **_kwargs: object
) -> Environment:  # pragma: no cover
    """Live Cloud Asset Inventory loader (not implemented offline).

    Production wiring outline::

        from google.cloud import asset_v1
        client = asset_v1.AssetServiceClient()
        # 1. ExportAssets / ListAssets for IAM_POLICY content type.
        # 2. ListAssets for RESOURCE content to gather tag bindings.
        # 3. iam.roles().list() for custom role definitions.
        # Map the responses into load_from_dict()'s schema.

    Kept as a stub so the offline analysis core has zero cloud dependencies.
    """
    raise NotImplementedError(
        "Live Cloud Asset Inventory ingestion requires the google-cloud-asset "
        "client and credentials. Export with `gcloud asset` and use "
        "load_from_file() instead."
    )

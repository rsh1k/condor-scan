"""Command-line interface for condor-scan.

Uses only the standard library (argparse) to keep the supply-chain footprint of
a security tool minimal. Subcommands:

    condor-scan scan EXPORT.json [--format json|sarif|table] [--fail-on SEVERITY]
    condor-scan posture EXPORT.json [--format text|json] [--fail-on-exposed]
    condor-scan gen-constraints [--out-dir DIR]

``scan`` and ``posture`` exit non-zero on policy violations so they can gate a
CI pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .analysis import build_context
from .constraints import generate_constraint_yaml, generate_rego
from .findings import Severity, render
from .graph import analyze_posture
from .loaders import LoaderError, load_from_file
from .rules import EscalationEngine
from .temporal import parse_timestamp

_EXIT_OK = 0
_EXIT_FINDINGS = 1
_EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="condor-scan",
        description=(
            "Detect GCP IAM privilege-escalation chains, including tag-based "
            "and IAM-Conditions escalation paths."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an IAM/asset export for escalation")
    scan.add_argument("export", help="path to a JSON IAM/asset export")
    scan.add_argument(
        "--format",
        choices=["json", "sarif", "table"],
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity if s >= Severity.LOW],
        default=None,
        help="exit non-zero if any finding is at or above this severity",
    )
    scan.add_argument(
        "--as-of",
        default=None,
        metavar="ISO8601",
        help="evaluate time-bound conditions as of this instant (default: now)",
    )

    gen = sub.add_parser(
        "gen-constraints", help="emit Policy Library / OPA constraints"
    )
    gen.add_argument(
        "--out-dir",
        default=None,
        help="write constraint files to this directory instead of stdout",
    )

    posture = sub.add_parser(
        "posture",
        help="attack-path posture: exposure, choke points, detection blind spots",
    )
    posture.add_argument("export", help="path to a JSON IAM/asset export")
    posture.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    posture.add_argument(
        "--fail-on-exposed",
        action="store_true",
        help="exit non-zero if any externally-exposed Tier-Zero path exists",
    )
    posture.add_argument(
        "--as-of",
        default=None,
        metavar="ISO8601",
        help="evaluate time-bound conditions as of this instant (default: now)",
    )
    posture.add_argument(
        "--jit-threshold-hours",
        type=float,
        default=24.0,
        help="windows shorter than this count as JIT/short-lived (default: 24)",
    )
    return parser


def _parse_as_of(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError(f"invalid --as-of timestamp: {value!r}")
    return parsed


def _run_scan(args: argparse.Namespace) -> int:
    try:
        env = load_from_file(args.export)
        now = _parse_as_of(args.as_of)
    except (LoaderError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    ctx = build_context(env)
    findings = EscalationEngine(ctx, now=now).analyze_all()
    print(render(findings, args.format))

    if args.fail_on is not None:
        threshold = Severity.from_name(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return _EXIT_FINDINGS
    return _EXIT_OK


def _run_gen_constraints(args: argparse.Namespace) -> int:
    rego = generate_rego()
    yaml = generate_constraint_yaml()
    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "tag_condition_escalation.rego").write_text(rego, encoding="utf-8")
        (out / "tag_condition_escalation.yaml").write_text(yaml, encoding="utf-8")
        print(f"wrote constraint template and instance to {out}/")
    else:
        print(rego)
        print("---")
        print(yaml)
    return _EXIT_OK


def _run_posture(args: argparse.Namespace) -> int:
    try:
        env = load_from_file(args.export)
        now = _parse_as_of(args.as_of)
    except (LoaderError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    ctx = build_context(env)
    engine = EscalationEngine(
        ctx, now=now, jit_threshold=timedelta(hours=args.jit_threshold_hours)
    )
    report = analyze_posture(ctx, engine)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_text())

    if args.fail_on_exposed and report.exposed_tier_zero:
        return _EXIT_FINDINGS
    return _EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "gen-constraints":
        return _run_gen_constraints(args)
    if args.command == "posture":
        return _run_posture(args)
    parser.error("unknown command")  # pragma: no cover
    return _EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

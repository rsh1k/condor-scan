"""condor-scan: GCP conditional IAM & tag-based privilege-escalation scanner."""

from __future__ import annotations

from .analysis import build_context
from .findings import Finding, Severity
from .graph import PostureReport, analyze_posture
from .loaders import load_from_dict, load_from_file
from .rules import EscalationEngine

__version__ = "0.2.0"

__all__ = [
    "EscalationEngine",
    "Finding",
    "PostureReport",
    "Severity",
    "analyze_posture",
    "build_context",
    "load_from_dict",
    "load_from_file",
    "__version__",
]

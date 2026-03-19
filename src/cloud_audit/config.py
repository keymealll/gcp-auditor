"""Configuration management for gcp-auditor."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from cloud_audit.models import Severity


class CloudAuditConfig:
    """Configuration for cloud audit scans."""

    def __init__(
        self,
        provider: str = "gcp",
        project: str | None = None,
        service_account_key: str | None = None,
        regions: list[str] | None = None,
        min_severity: Severity | None = None,
        min_cvss: float | None = None,
        exclude_checks: list[str] | None = None,
        suppressions: list[dict[str, Any]] | None = None,
    ):
        self.provider = provider
        self.project = project
        self.service_account_key = service_account_key
        self.regions = regions or []
        self.min_severity = min_severity
        self.min_cvss = min_cvss
        self.exclude_checks = exclude_checks or []
        self.suppressions = suppressions or []


def _find_config_file(path: Path | None = None) -> Path | None:
    """Find configuration file.

    If path is provided, use it. Otherwise search for .gcp-auditor.yml
    in current directory and parent directories.

    Args:
        path: Explicit config file path

    Returns:
        Path to config file or None if not found
    """
    if path:
        return path if path.exists() else None

    # Search for .gcp-auditor.yml
    search_paths = [
        Path(".gcp-auditor.yml"),
        Path(".gcp-auditor.yml"),
        Path(".gcp-auditor.yaml"),
        Path.home() / ".gcp-auditor.yml",
    ]

    for p in search_paths:
        if p.exists():
            return p

    # Search up directory tree
    current = Path.cwd()
    for _ in range(10):  # Max 10 levels up
        for filename in [".gcp-auditor.yml"]:
            config_path = current / filename
            if config_path.exists():
                return config_path
        if current.parent == current:  # Reached root
            break
        current = current.parent

    return None


def _parse_severity(value: str | None) -> Severity | None:
    """Parse severity string to enum."""
    if not value:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        return None


def load_config(path: Path | None = None) -> CloudAuditConfig:
    """Load configuration from YAML file.

    Args:
        path: Explicit config file path, or None to auto-detect

    Returns:
        CloudAuditConfig instance (empty if no config found)
    """
    config_file = _find_config_file(path)

    if not config_file:
        return CloudAuditConfig()

    try:
        with open(config_file) as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return CloudAuditConfig()

    # Parse severity
    min_severity = _parse_severity(data.get("min_severity"))

    # Parse CVSS threshold
    min_cvss = data.get("min_cvss")
    min_cvss = float(min_cvss) if isinstance(min_cvss, (int, float)) else None

    # Parse regions
    regions = data.get("regions", [])
    if isinstance(regions, str):
        regions = [r.strip() for r in regions.split(",")]

    # Parse suppressions
    suppressions = data.get("suppressions", [])
    if not isinstance(suppressions, list):
        suppressions = []

    return CloudAuditConfig(
        provider=data.get("provider", "gcp"),
        project=data.get("project"),
        service_account_key=data.get("service_account_key"),
        regions=regions,
        min_severity=min_severity,
        min_cvss=min_cvss,
        exclude_checks=data.get("exclude_checks", []),
        suppressions=suppressions,
    )


def _resolve_env_min_severity() -> Severity | None:
    """Resolve minimum severity from environment variable."""
    value = os.environ.get("GCP_AUDITOR_MIN_SEVERITY")
    return _parse_severity(value)


def _resolve_env_exclude_checks() -> list[str] | None:
    """Resolve excluded checks from environment variable."""
    value = os.environ.get("GCP_AUDITOR_EXCLUDE_CHECKS")
    if not value:
        return None
    return [c.strip() for c in value.split(",")]

"""Shared test fixtures for gcp-auditor."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

    from cloud_audit.providers.gcp.provider import GCPProvider


@pytest.fixture()
def mock_gcp_provider() -> Generator[GCPProvider, None, None]:
    """Create a mock GCPProvider for unit tests."""
    from cloud_audit.providers.gcp.provider import GCPProvider

    provider = MagicMock(spec=GCPProvider)
    provider.project = "test-project"
    provider.regions = ["us-central1"]
    provider.credentials = MagicMock()

    # Mock service clients
    provider.compute_service = MagicMock()
    provider.iam_service = MagicMock()
    provider.crm_service = MagicMock()
    provider.storage_client = MagicMock()
    provider.logging_service = MagicMock()
    provider.sqladmin_service = MagicMock()
    provider.kms_service = MagicMock()
    provider.bigquery_service = MagicMock()
    provider.container_service = MagicMock()

    yield provider

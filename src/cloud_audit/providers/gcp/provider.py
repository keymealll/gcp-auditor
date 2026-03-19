"""Google Cloud Platform (GCP) Provider."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING, Any, Callable

from google.auth import default
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.discovery import build

from cloud_audit.providers.base import BaseProvider

if TYPE_CHECKING:
    from googleapiclient import discovery

    from cloud_audit.models import CheckResult


class GCPProvider(BaseProvider):
    """Provides GCP clients and discovers implemented GCP checks."""

    def __init__(
        self,
        project: str | None = None,
        regions: list[str] | None = None,
        service_account_key: str | None = None,
    ) -> None:
        """Initialize GCP provider with authentication."""
        if service_account_key:
            self._credentials = service_account.Credentials.from_service_account_file(  # type: ignore[no-untyped-call]
                service_account_key,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            # For service account, project must be provided explicitly
            self._project = project or ""
        else:
            self._credentials, self._default_project = default()
            self._project = project or self._default_project or ""

        if not self._project:
            msg = (
                "Could not determine GCP project. "
                "Set --project flag, GOOGLE_CLOUD_PROJECT env var, or use a service account key."
            )
            raise ValueError(msg)

        # Ensure credentials are valid
        if hasattr(self._credentials, "refresh"):
            self._credentials.refresh(Request())

        self._regions = regions or ["us-central1", "us-east1", "europe-west1"]

        # Build API clients (cached)
        self._crm_service = build("cloudresourcemanager", "v1", credentials=self._credentials)
        self._compute_service = build("compute", "v1", credentials=self._credentials)
        self._iam_service = build("iam", "v1", credentials=self._credentials)
        self._storage_client = None  # Lazy init (uses google-cloud-storage)
        self._logging_service = build("logging", "v2", credentials=self._credentials)
        self._sqladmin_service = build("sqladmin", "v1beta4", credentials=self._credentials)
        self._kms_service = build("cloudkms", "v1", credentials=self._credentials)
        self._bigquery_service = build("bigquery", "v2", credentials=self._credentials)
        self._container_service = build("container", "v1", credentials=self._credentials)

        # Legacy services dict for get_client method
        self.services: dict[str, object] = {}

    @property
    def project(self) -> str:
        """Get project ID."""
        return self._project

    @property
    def credentials(self) -> Any:
        """Get credentials."""
        return self._credentials

    @property
    def regions(self) -> list[str]:
        """Get regions."""
        return self._regions

    @property
    def compute_service(self) -> discovery.Resource:
        """Get Compute API service."""
        return self._compute_service

    @property
    def iam_service(self) -> discovery.Resource:
        """Get IAM API service."""
        return self._iam_service

    @property
    def crm_service(self) -> discovery.Resource:
        """Get Cloud Resource Manager API service."""
        return self._crm_service

    @property
    def storage_client(self) -> Any:
        """Lazy-init google.cloud.storage client."""
        if self._storage_client is None:
            from google.cloud import storage

            self._storage_client = storage.Client(project=self._project, credentials=self._credentials)
        return self._storage_client

    @property
    def logging_service(self) -> discovery.Resource:
        """Get Logging API service."""
        return self._logging_service

    @property
    def sqladmin_service(self) -> discovery.Resource:
        """Get Cloud SQL Admin API service."""
        return self._sqladmin_service

    @property
    def kms_service(self) -> discovery.Resource:
        """Get KMS API service."""
        return self._kms_service

    @property
    def bigquery_service(self) -> discovery.Resource:
        """Get BigQuery API service."""
        return self._bigquery_service

    @property
    def container_service(self) -> discovery.Resource:
        """Get Container (GKE) API service."""
        return self._container_service

    def get_account_id(self) -> str:
        """Get account ID (project)."""
        return self._project

    def get_provider_name(self) -> str:
        """Get provider name."""
        return "gcp"

    def get_client(self, service_name: str, version: str = "v1") -> Any:
        """Get or create a cached GCP API client."""
        key = f"{service_name}_{version}"
        if key not in self.services:
            self.services[key] = build(service_name, version, credentials=self.credentials, cache_discovery=False)
        return self.services[key]

    def get_checks(self, categories: list[str] | None = None) -> list[Callable[[], CheckResult]]:
        """Discover all check functions inside cloud_audit.providers.gcp.checks.*."""
        import cloud_audit.providers.gcp.checks as checks_pkg

        checks: list[Callable[[], CheckResult]] = []
        for _, module_name, _ in pkgutil.iter_modules(checks_pkg.__path__):
            module = importlib.import_module(f"cloud_audit.providers.gcp.checks.{module_name}")
            for name, obj in inspect.getmembers(module):
                if (
                    inspect.isfunction(obj)
                    and getattr(obj, "__module__", "") == module.__name__
                    and not name.startswith("_")
                ):
                    # If categories filter is applied
                    # We would filter by fn.category but right now keep simple
                    def wrapper(self: BaseProvider = self, fn: Any = obj) -> CheckResult:
                        return fn(self)  # type: ignore[no-any-return]

                    wrapper.__name__ = name
                    checks.append(wrapper)

        return checks

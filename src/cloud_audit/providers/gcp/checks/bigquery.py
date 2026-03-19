"""GCP BigQuery security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def check_dataset_public_access(provider: GCPProvider) -> CheckResult:
    """Check if BigQuery datasets are publicly accessible."""
    result = CheckResult(check_id="gcp-bq-001", check_name="BigQuery public datasets")

    try:
        datasets = provider.bigquery_service.datasets().list(projectId=provider.project).execute()

        for ds in datasets.get("datasets", []):
            dataset_id = ds["datasetReference"]["datasetId"]
            result.resources_scanned += 1

            try:
                dataset = (
                    provider.bigquery_service.datasets().get(projectId=provider.project, datasetId=dataset_id).execute()
                )

                for access_entry in dataset.get("access", []):
                    special_group = access_entry.get("specialGroup", "")
                    if special_group in ("allAuthenticatedUsers", "allUsers"):
                        result.findings.append(
                            Finding(
                                check_id="gcp-bq-001",
                                title=f"BigQuery dataset '{dataset_id}' is publicly accessible",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="bigquery.googleapis.com/Dataset",
                                resource_id=f"projects/{provider.project}/datasets/{dataset_id}",
                                description=(
                                    f"Dataset '{dataset_id}' grants access to '{special_group}'. "
                                    f"This exposes potentially sensitive data to the public."
                                ),
                                recommendation="Remove public access from the dataset. Grant access to specific users or groups only.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Remove public access:\n"
                                        f"bq show --format=json {provider.project}:{dataset_id} > /tmp/dataset.json\n"
                                        f"# Edit /tmp/dataset.json to remove allUsers/allAuthenticatedUsers\n"
                                        f"bq update --source=/tmp/dataset.json {provider.project}:{dataset_id}"
                                    ),
                                    terraform=(
                                        f'resource "google_bigquery_dataset" "{dataset_id}" {{\n'
                                        f'  dataset_id = "{dataset_id}"\n'
                                        f"  # Remove access blocks with special_group = allUsers/allAuthenticatedUsers\n"
                                        f"  access {{\n"
                                        f'    role          = "READER"\n'
                                        f'    user_by_email = "specific-user@example.com"\n'
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/bigquery/docs/dataset-access-controls",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.8.2.3",
                                    "ISO 27001 A.9.1.2",
                                    "SOC 2 CC6.1",
                                    "SOC 2 CC6.6",
                                    "CIS GCP 7.1",
                                ],
                            )
                        )
                        break
            except Exception:
                continue
    except Exception as e:
        result.error = str(e)

    return result


def check_dataset_cmek(provider: GCPProvider) -> CheckResult:
    """Check if BigQuery datasets use Customer-Managed Encryption Keys (CMEK)."""
    result = CheckResult(check_id="gcp-bq-002", check_name="BigQuery CMEK encryption")

    try:
        datasets = provider.bigquery_service.datasets().list(projectId=provider.project).execute()

        for ds in datasets.get("datasets", []):
            dataset_id = ds["datasetReference"]["datasetId"]
            result.resources_scanned += 1

            try:
                dataset = (
                    provider.bigquery_service.datasets().get(projectId=provider.project, datasetId=dataset_id).execute()
                )

                encryption = dataset.get("defaultEncryptionConfiguration", {})
                if not encryption.get("kmsKeyName"):
                    result.findings.append(
                        Finding(
                            check_id="gcp-bq-002",
                            title=f"BigQuery dataset '{dataset_id}' does not use CMEK",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="bigquery.googleapis.com/Dataset",
                            resource_id=f"projects/{provider.project}/datasets/{dataset_id}",
                            description=(
                                f"Dataset '{dataset_id}' uses Google-managed encryption. "
                                f"CMEK provides additional control over key lifecycle for sensitive data."
                            ),
                            recommendation="Configure CMEK for datasets containing sensitive data.",
                            remediation=Remediation(
                                cli=(
                                    f"bq update --default_kms_key \\\n"
                                    f"  projects/{provider.project}/locations/LOCATION/keyRings/RING/cryptoKeys/KEY \\\n"
                                    f"  {provider.project}:{dataset_id}"
                                ),
                                terraform=(
                                    f'resource "google_bigquery_dataset" "{dataset_id}" {{\n'
                                    f'  dataset_id = "{dataset_id}"\n'
                                    f"  default_encryption_configuration {{\n"
                                    f"    kms_key_name = google_kms_crypto_key.key.id\n"
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/bigquery/docs/customer-managed-encryption",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.10.1.1",
                                "ISO 27001 A.10.1.2",
                                "SOC 2 CC6.1",
                                "SOC 2 CC6.7",
                                "CIS GCP 7.2",
                            ],
                        )
                    )
            except Exception:
                continue
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all BigQuery checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_dataset_public_access, provider, check_id="gcp-bq-001", category=Category.SECURITY),
        make_check(check_dataset_cmek, provider, check_id="gcp-bq-002", category=Category.SECURITY),
    ]

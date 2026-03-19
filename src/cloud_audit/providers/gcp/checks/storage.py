"""GCP Storage checks."""

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.gcp.provider import GCPProvider


def gcp_storage_001(provider: "GCPProvider") -> CheckResult:
    """Storage bucket without Uniform Bucket-Level Access enabled."""
    client = provider.get_client("storage", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-storage-001",
        check_name="GCS Uniform Bucket-Level Access (UBLA)",
    )

    try:
        # Need to use storage API to list buckets.
        # However, listing buckets uses projects.buckets.list which has a peculiar syntax in the googleapiclient.
        request = client.buckets().list(project=project_id)
        while request is not None:
            response = request.execute()
            buckets = response.get("items", [])
            for bucket in buckets:
                result.resources_scanned += 1
                bucket_name = bucket.get("name")

                # Check for uniform bucket-level access
                iam_config = bucket.get("iamConfiguration", {})
                ubla = iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False)

                if not ubla:
                    cli = f"gcloud storage buckets update gs://{bucket_name} --uniform-bucket-level-access"
                    tf = f'resource "google_storage_bucket" "bucket" {{\n  name = "{bucket_name}"\n  uniform_bucket_level_access = true\n}}'
                    docs = "https://cloud.google.com/storage/docs/uniform-bucket-level-access"

                    result.findings.append(
                        Finding(
                            check_id="gcp-storage-001",
                            title="GCS bucket without Uniform Bucket-Level Access",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="google_storage_bucket",
                            resource_id=f"projects/{project_id}/buckets/{bucket_name}",
                            region=bucket.get("location", "global"),
                            description="Bucket allows ACLs instead of enforcing uniform IAM policies.",
                            recommendation="Enable Uniform Bucket-Level Access.",
                            remediation=Remediation(
                                cli=cli,
                                terraform=tf,
                                doc_url=docs,
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS GCP 5.2"],
                        )
                    )

            request = client.buckets().list_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to list GCS buckets: {str(e)}"

    return result

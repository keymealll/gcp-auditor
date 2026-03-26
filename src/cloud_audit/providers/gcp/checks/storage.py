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


def gcp_storage_002(provider: "GCPProvider") -> CheckResult:
    """Check for GCS buckets publicly accessible to allUsers or allAuthenticatedUsers."""
    client = provider.get_client("storage", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-storage-002",
        check_name="GCS Bucket Public Access",
    )

    public_members = {"allUsers", "allAuthenticatedUsers"}

    try:
        request = client.buckets().list(project=project_id)
        while request is not None:
            response = request.execute()
            for bucket in response.get("items", []):
                result.resources_scanned += 1
                bucket_name = bucket.get("name")

                try:
                    policy = client.buckets().getIamPolicy(bucket=bucket_name).execute()
                    for binding in policy.get("bindings", []):
                        exposed = public_members.intersection(set(binding.get("members", [])))
                        if not exposed:
                            continue

                        role = binding.get("role", "unknown")
                        result.findings.append(
                            Finding(
                                check_id="gcp-storage-002",
                                title=f"Bucket '{bucket_name}' is publicly accessible ({role})",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="google_storage_bucket",
                                resource_id=f"projects/{project_id}/buckets/{bucket_name}",
                                region=bucket.get("location", "global"),
                                description=(
                                    f"Bucket grants '{role}' to {', '.join(sorted(exposed))}. "
                                    "Any internet user can access this bucket's contents without authentication."
                                ),
                                recommendation="Remove public IAM bindings and enable Uniform Bucket-Level Access.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Remove public access:\n"
                                        f"gcloud storage buckets remove-iam-policy-binding gs://{bucket_name} \\\n"
                                        f"  --member=allUsers --role={role}\n"
                                        f"# Then enforce uniform access:\n"
                                        f"gcloud storage buckets update gs://{bucket_name} --uniform-bucket-level-access"
                                    ),
                                    terraform=(
                                        "# Remove the google_storage_bucket_iam_member with member = \"allUsers\"\n"
                                        f'resource "google_storage_bucket" "bucket" {{\n'
                                        f'  name                        = "{bucket_name}"\n'
                                        f"  uniform_bucket_level_access = true\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/storage/docs/access-control/making-data-public",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS GCP 5.1", "ISO 27001 A.13.1.3", "SOC 2 CC6.1"],
                            )
                        )
                        break  # one finding per bucket is enough
                except Exception:  # noqa: S110
                    # Skip buckets whose IAM policy we cannot read (likely a permissions issue)
                    pass

            request = client.buckets().list_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check bucket public access: {str(e)}"

    return result


def gcp_storage_003(provider: "GCPProvider") -> CheckResult:
    """Check for GCS buckets without object versioning enabled."""
    client = provider.get_client("storage", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-storage-003",
        check_name="GCS Bucket Versioning",
    )

    try:
        request = client.buckets().list(project=project_id)
        while request is not None:
            response = request.execute()
            for bucket in response.get("items", []):
                result.resources_scanned += 1
                bucket_name = bucket.get("name")
                versioning_enabled = bucket.get("versioning", {}).get("enabled", False)

                if not versioning_enabled:
                    result.findings.append(
                        Finding(
                            check_id="gcp-storage-003",
                            title=f"Bucket '{bucket_name}' does not have versioning enabled",
                            severity=Severity.LOW,
                            category=Category.SECURITY,
                            resource_type="google_storage_bucket",
                            resource_id=f"projects/{project_id}/buckets/{bucket_name}",
                            region=bucket.get("location", "global"),
                            description=(
                                "Without versioning, deleted or overwritten objects cannot be recovered. "
                                "Versioning protects against accidental deletion and ransomware overwrites."
                            ),
                            recommendation=(
                                "Enable object versioning and pair it with a lifecycle policy to "
                                "automatically delete old versions and control costs."
                            ),
                            remediation=Remediation(
                                cli=f"gcloud storage buckets update gs://{bucket_name} --versioning",
                                terraform=(
                                    f'resource "google_storage_bucket" "bucket" {{\n'
                                    f'  name = "{bucket_name}"\n'
                                    f"  versioning {{\n"
                                    f"    enabled = true\n"
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/storage/docs/object-versioning",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS GCP 5.3", "ISO 27001 A.12.3.1"],
                        )
                    )
            request = client.buckets().list_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check bucket versioning: {str(e)}"

    return result


def gcp_storage_004(provider: "GCPProvider") -> CheckResult:
    """Check for GCS buckets without access logging enabled."""
    client = provider.get_client("storage", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-storage-004",
        check_name="GCS Bucket Access Logging",
    )

    try:
        request = client.buckets().list(project=project_id)
        while request is not None:
            response = request.execute()
            for bucket in response.get("items", []):
                result.resources_scanned += 1
                bucket_name = bucket.get("name")
                logging_config = bucket.get("logging", {})

                if not logging_config.get("logBucket"):
                    result.findings.append(
                        Finding(
                            check_id="gcp-storage-004",
                            title=f"Bucket '{bucket_name}' does not have access logging enabled",
                            severity=Severity.LOW,
                            category=Category.SECURITY,
                            resource_type="google_storage_bucket",
                            resource_id=f"projects/{project_id}/buckets/{bucket_name}",
                            region=bucket.get("location", "global"),
                            description=(
                                "Access logs record who accessed the bucket and when. Without them, "
                                "unauthorized access or data exfiltration cannot be detected or investigated after the fact."
                            ),
                            recommendation="Enable access logging to a dedicated log bucket for audit and forensic purposes.",
                            remediation=Remediation(
                                cli=(
                                    f"gcloud storage buckets update gs://{bucket_name} \\\n"
                                    f"  --log-bucket=LOG_BUCKET_NAME \\\n"
                                    f"  --log-object-prefix={bucket_name}"
                                ),
                                terraform=(
                                    f'resource "google_storage_bucket" "bucket" {{\n'
                                    f'  name = "{bucket_name}"\n'
                                    f"  logging {{\n"
                                    f"    log_bucket        = google_storage_bucket.log_bucket.name\n"
                                    f'    log_object_prefix = "{bucket_name}"\n'
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/storage/docs/access-logs",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS GCP 5.4", "ISO 27001 A.12.4.1", "SOC 2 CC7.2"],
                        )
                    )
            request = client.buckets().list_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check bucket access logging: {str(e)}"

    return result


def gcp_storage_005(provider: "GCPProvider") -> CheckResult:
    """Check for GCS buckets without a retention policy."""
    client = provider.get_client("storage", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-storage-005",
        check_name="GCS Bucket Retention Policy",
    )

    try:
        request = client.buckets().list(project=project_id)
        while request is not None:
            response = request.execute()
            for bucket in response.get("items", []):
                result.resources_scanned += 1
                bucket_name = bucket.get("name")
                retention_policy = bucket.get("retentionPolicy", {})

                if not retention_policy.get("retentionPeriod"):
                    result.findings.append(
                        Finding(
                            check_id="gcp-storage-005",
                            title=f"Bucket '{bucket_name}' has no retention policy",
                            severity=Severity.LOW,
                            category=Category.COMPLIANCE,
                            resource_type="google_storage_bucket",
                            resource_id=f"projects/{project_id}/buckets/{bucket_name}",
                            region=bucket.get("location", "global"),
                            description=(
                                "Without a retention policy, objects can be deleted before compliance requirements "
                                "are satisfied. Retention policies prevent premature deletion of audit logs and records."
                            ),
                            recommendation=(
                                "Apply a retention period appropriate for your data classification and compliance "
                                "obligations (e.g., 365 days for audit logs under SOC 2 / ISO 27001)."
                            ),
                            remediation=Remediation(
                                cli=f"gcloud storage buckets update gs://{bucket_name} --retention-period=365d",
                                terraform=(
                                    f'resource "google_storage_bucket" "bucket" {{\n'
                                    f'  name = "{bucket_name}"\n'
                                    f"  retention_policy {{\n"
                                    f"    retention_period = 31536000  # 365 days\n"
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/storage/docs/bucket-lock",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS GCP 5.5", "ISO 27001 A.18.1.3", "SOC 2 CC6.5"],
                        )
                    )
            request = client.buckets().list_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check bucket retention policy: {str(e)}"

    return result

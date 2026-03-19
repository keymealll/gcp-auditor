"""GCP Cloud Logging / Audit Logging checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider

logger = logging.getLogger(__name__)


def check_audit_logging_enabled(provider: GCPProvider) -> CheckResult:
    """Check if Data Access audit logs are enabled for all services."""
    result = CheckResult(check_id="gcp-logging-001", check_name="Data Access audit logging")

    try:
        result.resources_scanned = 1
        policy = (
            provider.crm_service.projects()
            .getIamPolicy(resource=provider.project, body={"options": {"requestedPolicyVersion": 3}})
            .execute()
        )

        # Check audit configs
        audit_configs = policy.get("auditConfigs", [])

        # Look for allServices config
        has_all_services = False
        for ac in audit_configs:
            if ac.get("service") == "allServices":
                log_types = [entry.get("logType") for entry in ac.get("auditLogConfigs", [])]
                if "ADMIN_READ" in log_types and "DATA_READ" in log_types and "DATA_WRITE" in log_types:
                    has_all_services = True
                break

        if not has_all_services:
            result.findings.append(
                Finding(
                    check_id="gcp-logging-001",
                    title="Data Access audit logs are not fully enabled for all services",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="cloudresourcemanager.googleapis.com/Project",
                    resource_id=f"projects/{provider.project}",
                    description=(
                        "Data Access audit logs (ADMIN_READ, DATA_READ, DATA_WRITE) are not enabled "
                        "for all services. Without these logs, access to sensitive data cannot be audited."
                    ),
                    recommendation="Enable Data Access audit logs for all services to maintain a complete audit trail.",
                    remediation=Remediation(
                        cli=(
                            "# Enable all audit log types for all services:\n"
                            f"gcloud projects set-iam-policy {provider.project} policy.yaml\n"
                            "# Where policy.yaml includes:\n"
                            "# auditConfigs:\n"
                            "# - service: allServices\n"
                            "#   auditLogConfigs:\n"
                            "#   - logType: ADMIN_READ\n"
                            "#   - logType: DATA_READ\n"
                            "#   - logType: DATA_WRITE"
                        ),
                        terraform=(
                            'resource "google_project_iam_audit_config" "all_services" {\n'
                            f'  project = "{provider.project}"\n'
                            '  service = "allServices"\n'
                            "  audit_log_config {\n"
                            '    log_type = "ADMIN_READ"\n'
                            "  }\n"
                            "  audit_log_config {\n"
                            '    log_type = "DATA_READ"\n'
                            "  }\n"
                            "  audit_log_config {\n"
                            '    log_type = "DATA_WRITE"\n'
                            "  }\n"
                            "}"
                        ),
                        doc_url="https://cloud.google.com/logging/docs/audit/configure-data-access",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=[
                        "ISO 27001 A.12.4.1",
                        "ISO 27001 A.12.4.2",
                        "ISO 27001 A.12.4.3",
                        "SOC 2 CC7.2",
                        "SOC 2 CC7.3",
                        "CIS GCP 2.1",
                    ],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_log_sinks_configured(provider: GCPProvider) -> CheckResult:
    """Check if log sinks are configured for exporting logs."""
    result = CheckResult(check_id="gcp-logging-002", check_name="Log export sinks configured")

    try:
        result.resources_scanned = 1
        sinks = provider.logging_service.projects().sinks().list(parent=f"projects/{provider.project}").execute()

        # Filter out _Default and _Required sinks
        custom_sinks = [s for s in sinks.get("sinks", []) if not s["name"].startswith("_")]

        if not custom_sinks:
            result.findings.append(
                Finding(
                    check_id="gcp-logging-002",
                    title="No custom log export sinks configured",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="logging.googleapis.com/LogSink",
                    resource_id=f"projects/{provider.project}",
                    description=(
                        "No custom log sinks are configured. Logs are only retained in Cloud Logging "
                        "with default retention. For compliance, logs should be exported to durable storage."
                    ),
                    recommendation="Create log sinks to export audit logs to Cloud Storage, BigQuery, or Pub/Sub.",
                    remediation=Remediation(
                        cli=(
                            f"# Create a log sink to Cloud Storage:\n"
                            f"gcloud logging sinks create audit-logs-sink \\\n"
                            f"  storage.googleapis.com/{provider.project}-audit-logs \\\n"
                            f"  --log-filter='logName:\"cloudaudit.googleapis.com\"'"
                        ),
                        terraform=(
                            'resource "google_logging_project_sink" "audit_sink" {\n'
                            '  name        = "audit-logs-sink"\n'
                            f'  project     = "{provider.project}"\n'
                            '  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"\n'
                            '  filter      = "logName:\\"cloudaudit.googleapis.com\\""\n'
                            "}"
                        ),
                        doc_url="https://cloud.google.com/logging/docs/export",
                        effort=Effort.MEDIUM,
                    ),
                    compliance_refs=[
                        "ISO 27001 A.12.4.1",
                        "ISO 27001 A.12.4.4",
                        "SOC 2 CC7.2",
                        "SOC 2 CC7.4",
                        "CIS GCP 2.2",
                    ],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_log_retention(provider: GCPProvider) -> CheckResult:
    """Check if log buckets have adequate retention periods (>=365 days for compliance)."""
    result = CheckResult(check_id="gcp-logging-003", check_name="Log retention policy")

    try:
        result.resources_scanned = 1
        min_retention_days = 365

        # Check the _Default log bucket retention
        try:
            bucket = (
                provider.logging_service.projects()
                .locations()
                .buckets()
                .get(name=f"projects/{provider.project}/locations/global/buckets/_Default")
                .execute()
            )

            retention_days = bucket.get("retentionDays", 30)
            if retention_days < min_retention_days:
                result.findings.append(
                    Finding(
                        check_id="gcp-logging-003",
                        title=f"Default log bucket retention is {retention_days} days (< {min_retention_days})",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="logging.googleapis.com/LogBucket",
                        resource_id=f"projects/{provider.project}/locations/global/buckets/_Default",
                        description=(
                            f"The _Default log bucket retains logs for only {retention_days} days. "
                            f"ISO 27001 and SOC 2 recommend retaining audit logs for at least {min_retention_days} days."
                        ),
                        recommendation=f"Increase log retention to at least {min_retention_days} days for compliance.",
                        remediation=Remediation(
                            cli=(
                                f"gcloud logging buckets update _Default \\\n"
                                f"  --location=global \\\n"
                                f"  --retention-days={min_retention_days}"
                            ),
                            terraform=(
                                'resource "google_logging_project_bucket_config" "default" {\n'
                                f'  project        = "{provider.project}"\n'
                                '  location       = "global"\n'
                                '  bucket_id      = "_Default"\n'
                                f"  retention_days = {min_retention_days}\n"
                                "}"
                            ),
                            doc_url="https://cloud.google.com/logging/docs/buckets",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.12.4.1",
                            "ISO 27001 A.12.4.4",
                            "SOC 2 CC7.2",
                            "SOC 2 CC7.4",
                            "CIS GCP 2.3",
                        ],
                    )
                )
        except Exception as e:  # noqa: BLE001
            # Bucket might not be accessible, continue checking
            logger.debug(f"Failed to check Cloud Storage bucket: {e}")
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all Cloud Logging checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_audit_logging_enabled, provider, check_id="gcp-logging-001", category=Category.SECURITY),
        make_check(check_log_sinks_configured, provider, check_id="gcp-logging-002", category=Category.SECURITY),
        make_check(check_log_retention, provider, check_id="gcp-logging-003", category=Category.SECURITY),
    ]

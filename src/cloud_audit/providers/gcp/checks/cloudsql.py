"""GCP Cloud SQL security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def check_public_ip(provider: GCPProvider) -> CheckResult:
    """Check if Cloud SQL instances have public IP addresses."""
    result = CheckResult(check_id="gcp-sql-001", check_name="Cloud SQL public IP")

    try:
        response = provider.sqladmin_service.instances().list(project=provider.project).execute()
        for instance in response.get("items", []):
            result.resources_scanned += 1
            name = instance["name"]
            region = instance.get("region", "unknown")

            ip_addresses = instance.get("ipAddresses", [])
            for ip_info in ip_addresses:
                if ip_info.get("type") == "PRIMARY":
                    result.findings.append(
                        Finding(
                            check_id="gcp-sql-001",
                            title=f"Cloud SQL '{name}' has a public IP address",
                            severity=Severity.CRITICAL,
                            category=Category.SECURITY,
                            resource_type="sqladmin.googleapis.com/Instance",
                            resource_id=f"projects/{provider.project}/instances/{name}",
                            region=region,
                            description=(
                                f"Cloud SQL instance '{name}' has public IP {ip_info.get('ipAddress', 'N/A')}. "
                                f"Public SQL instances are directly exposed to brute-force and injection attacks."
                            ),
                            recommendation="Use private IP with VPC peering instead of public IP.",
                            remediation=Remediation(
                                cli=(
                                    f"# Configure private IP (requires VPC peering):\n"
                                    f"gcloud sql instances patch {name} \\\n"
                                    f"  --no-assign-ip \\\n"
                                    f"  --network=projects/{provider.project}/global/networks/default"
                                ),
                                terraform=(
                                    f'resource "google_sql_database_instance" "{name}" {{\n'
                                    f"  settings {{\n"
                                    f"    ip_configuration {{\n"
                                    f"      ipv4_enabled    = false\n"
                                    f"      private_network = google_compute_network.vpc.id\n"
                                    f"    }}\n"
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/sql/docs/mysql/configure-private-ip",
                                effort=Effort.HIGH,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.13.1.1",
                                "ISO 27001 A.13.1.3",
                                "SOC 2 CC6.1",
                                "SOC 2 CC6.6",
                                "CIS GCP 6.5",
                            ],
                        )
                    )
                    break
    except Exception as e:
        result.error = str(e)

    return result


def check_ssl_enforcement(provider: GCPProvider) -> CheckResult:
    """Check if Cloud SQL instances enforce SSL connections."""
    result = CheckResult(check_id="gcp-sql-002", check_name="Cloud SQL SSL enforcement")

    try:
        response = provider.sqladmin_service.instances().list(project=provider.project).execute()
        for instance in response.get("items", []):
            result.resources_scanned += 1
            name = instance["name"]
            region = instance.get("region", "unknown")

            settings = instance.get("settings", {})
            ip_config = settings.get("ipConfiguration", {})

            if not ip_config.get("requireSsl", False):
                result.findings.append(
                    Finding(
                        check_id="gcp-sql-002",
                        title=f"Cloud SQL '{name}' does not enforce SSL connections",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="sqladmin.googleapis.com/Instance",
                        resource_id=f"projects/{provider.project}/instances/{name}",
                        region=region,
                        description=(
                            f"Cloud SQL instance '{name}' allows unencrypted connections. "
                            f"Without SSL enforcement, database traffic can be intercepted."
                        ),
                        recommendation="Enable SSL enforcement to require all connections to use TLS.",
                        remediation=Remediation(
                            cli=(f"gcloud sql instances patch {name} \\\n  --require-ssl"),
                            terraform=(
                                f'resource "google_sql_database_instance" "{name}" {{\n'
                                f"  settings {{\n"
                                f"    ip_configuration {{\n"
                                f"      require_ssl = true\n"
                                f"    }}\n"
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.10.1.1",
                            "ISO 27001 A.13.1.1",
                            "SOC 2 CC6.1",
                            "SOC 2 CC6.7",
                            "CIS GCP 6.1",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_automated_backups(provider: GCPProvider) -> CheckResult:
    """Check if Cloud SQL instances have automated backups enabled."""
    result = CheckResult(check_id="gcp-sql-003", check_name="Cloud SQL automated backups")

    try:
        response = provider.sqladmin_service.instances().list(project=provider.project).execute()
        for instance in response.get("items", []):
            result.resources_scanned += 1
            name = instance["name"]
            region = instance.get("region", "unknown")

            settings = instance.get("settings", {})
            backup_config = settings.get("backupConfiguration", {})

            if not backup_config.get("enabled", False):
                result.findings.append(
                    Finding(
                        check_id="gcp-sql-003",
                        title=f"Cloud SQL '{name}' does not have automated backups enabled",
                        severity=Severity.HIGH,
                        category=Category.RELIABILITY,
                        resource_type="sqladmin.googleapis.com/Instance",
                        resource_id=f"projects/{provider.project}/instances/{name}",
                        region=region,
                        description=(
                            f"Cloud SQL instance '{name}' does not have automated backups enabled. "
                            f"Without backups, data loss from deletion or corruption is unrecoverable."
                        ),
                        recommendation="Enable automated backups with point-in-time recovery.",
                        remediation=Remediation(
                            cli=(
                                f"gcloud sql instances patch {name} \\\n"
                                f"  --backup-start-time=02:00 \\\n"
                                f"  --enable-bin-log"
                            ),
                            terraform=(
                                f'resource "google_sql_database_instance" "{name}" {{\n'
                                f"  settings {{\n"
                                f"    backup_configuration {{\n"
                                f"      enabled            = true\n"
                                f'      start_time         = "02:00"\n'
                                f"      binary_log_enabled = true\n"
                                f"    }}\n"
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.12.3.1",
                            "SOC 2 A1.2",
                            "SOC 2 CC7.5",
                            "CIS GCP 6.7",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all Cloud SQL checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_public_ip, provider, check_id="gcp-sql-001", category=Category.SECURITY),
        make_check(check_ssl_enforcement, provider, check_id="gcp-sql-002", category=Category.SECURITY),
        make_check(check_automated_backups, provider, check_id="gcp-sql-003", category=Category.RELIABILITY),
    ]

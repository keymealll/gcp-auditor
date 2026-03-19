"""GCP Cloud KMS security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def check_key_rotation(provider: GCPProvider) -> CheckResult:
    """Check if KMS keys have automatic rotation enabled (<=90 days)."""
    result = CheckResult(check_id="gcp-kms-001", check_name="KMS key rotation")

    try:
        max_rotation_days = 90
        max_rotation_seconds = max_rotation_days * 86400

        # List key rings across all locations
        locations = provider.kms_service.projects().locations().list(name=f"projects/{provider.project}").execute()

        for location in locations.get("locations", []):
            location_id = location["locationId"]
            parent = f"projects/{provider.project}/locations/{location_id}"

            try:
                key_rings = provider.kms_service.projects().locations().keyRings().list(parent=parent).execute()
            except Exception:
                continue

            for ring in key_rings.get("keyRings", []):
                ring_name = ring["name"]

                try:
                    keys = (
                        provider.kms_service.projects()
                        .locations()
                        .keyRings()
                        .cryptoKeys()
                        .list(parent=ring_name)
                        .execute()
                    )
                except Exception:
                    continue

                for key in keys.get("cryptoKeys", []):
                    result.resources_scanned += 1
                    key_name = key["name"]
                    short_name = key_name.split("/")[-1]

                    rotation_period = key.get("rotationPeriod")
                    if not rotation_period:
                        result.findings.append(
                            Finding(
                                check_id="gcp-kms-001",
                                title=f"KMS key '{short_name}' has no rotation period set",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                resource_type="cloudkms.googleapis.com/CryptoKey",
                                resource_id=key_name,
                                region=location_id,
                                description=(
                                    f"KMS key '{short_name}' does not have automatic rotation configured. "
                                    f"Without rotation, compromised keys remain active indefinitely."
                                ),
                                recommendation=f"Enable automatic key rotation with a period of {max_rotation_days} days or less.",
                                remediation=Remediation(
                                    cli=(
                                        f"gcloud kms keys update {short_name} \\\n"
                                        f"  --keyring={ring_name.split('/')[-1]} \\\n"
                                        f"  --location={location_id} \\\n"
                                        f"  --rotation-period=90d \\\n"
                                        f"  --next-rotation-time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                                    ),
                                    terraform=(
                                        f'resource "google_kms_crypto_key" "{short_name}" {{\n'
                                        f'  name     = "{short_name}"\n'
                                        f"  key_ring = google_kms_key_ring.ring.id\n"
                                        f'  rotation_period = "7776000s"  # 90 days\n'
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/kms/docs/key-rotation",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.10.1.2",
                                    "SOC 2 CC6.1",
                                    "SOC 2 CC6.7",
                                    "CIS GCP 1.10",
                                ],
                            )
                        )
                    else:
                        # Parse rotation period (format: "7776000s")
                        period_seconds = int(rotation_period.rstrip("s"))
                        if period_seconds > max_rotation_seconds:
                            period_days = period_seconds // 86400
                            result.findings.append(
                                Finding(
                                    check_id="gcp-kms-001",
                                    title=f"KMS key '{short_name}' rotation period is {period_days} days (>{max_rotation_days})",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="cloudkms.googleapis.com/CryptoKey",
                                    resource_id=key_name,
                                    region=location_id,
                                    description=(
                                        f"KMS key '{short_name}' rotates every {period_days} days, "
                                        f"exceeding the {max_rotation_days}-day recommended maximum."
                                    ),
                                    recommendation=f"Reduce rotation period to {max_rotation_days} days or less.",
                                    remediation=Remediation(
                                        cli=(
                                            f"gcloud kms keys update {short_name} \\\n"
                                            f"  --keyring={ring_name.split('/')[-1]} \\\n"
                                            f"  --location={location_id} \\\n"
                                            f"  --rotation-period=90d"
                                        ),
                                        terraform=(
                                            f'resource "google_kms_crypto_key" "{short_name}" {{\n'
                                            f'  rotation_period = "7776000s"  # 90 days\n'
                                            f"}}"
                                        ),
                                        doc_url="https://cloud.google.com/kms/docs/key-rotation",
                                        effort=Effort.LOW,
                                    ),
                                    compliance_refs=[
                                        "ISO 27001 A.10.1.2",
                                        "SOC 2 CC6.1",
                                        "CIS GCP 1.10",
                                    ],
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all KMS checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_key_rotation, provider, check_id="gcp-kms-001", category=Category.SECURITY),
    ]

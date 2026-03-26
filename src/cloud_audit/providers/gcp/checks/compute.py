"""GCP Compute checks."""

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.gcp.provider import GCPProvider


def gcp_compute_001(provider: "GCPProvider") -> CheckResult:
    """Check for instances with public IP addresses."""
    client = provider.get_client("compute", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-compute-001",
        check_name="Compute Instances Public IP",
    )

    try:
        # We need to iterate over all zones in the project
        # For simplicity, we use aggregatedList
        request = client.instances().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for zone, instances_scoped_list in response.get("items", {}).items():
                instances = instances_scoped_list.get("instances", [])
                for instance in instances:
                    result.resources_scanned += 1
                    instance_name = instance.get("name", "")
                    zone_name = zone.split("/")[-1]
                    network_interfaces = instance.get("networkInterfaces", [])

                    has_public_ip = False
                    for ni in network_interfaces:
                        access_configs = ni.get("accessConfigs", [])
                        for ac in access_configs:
                            if "natIP" in ac or ac.get("type") == "ONE_TO_ONE_NAT":
                                has_public_ip = True
                                break
                        if has_public_ip:
                            break

                    if has_public_ip:
                        cli = f'gcloud compute instances delete-access-config {instance_name} --zone={zone_name} --access-config-name="External NAT"'
                        tf = 'resource "google_compute_instance" "default" {\n  # Remove access_config block from network_interface\n}'
                        docs = "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address"

                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-001",
                                title="Compute instance has a public IP",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="google_compute_instance",
                                resource_id=f"projects/{project_id}/zones/{zone_name}/instances/{instance_name}",
                                region=zone_name,
                                description="Instances with public IPs are reachable from the internet, increasing attack surface.",
                                recommendation="Remove public IP and use Identity-Aware Proxy (IAP) or Cloud NAT.",
                                remediation=Remediation(
                                    cli=cli,
                                    terraform=tf,
                                    doc_url=docs,
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS GCP 4.8"],
                            )
                        )

            request = client.instances().aggregatedList_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check compute instances: {str(e)}"

    return result


def gcp_compute_002(provider: "GCPProvider") -> CheckResult:
    """Check for Compute Engine disks not encrypted with CMEK."""
    client = provider.get_client("compute", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-compute-002",
        check_name="Compute Disks Without CMEK Encryption",
    )

    try:
        request = client.disks().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for zone, disk_list in response.get("items", {}).items():
                for disk in disk_list.get("disks", []):
                    result.resources_scanned += 1
                    disk_name = disk.get("name", "")
                    zone_name = zone.split("/")[-1]
                    encryption_key = disk.get("diskEncryptionKey", {})

                    if not encryption_key.get("kmsKeyName"):
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-002",
                                title=f"Disk '{disk_name}' is not encrypted with CMEK",
                                severity=Severity.LOW,
                                category=Category.SECURITY,
                                resource_type="google_compute_disk",
                                resource_id=f"projects/{project_id}/zones/{zone_name}/disks/{disk_name}",
                                region=zone_name,
                                description=(
                                    "Disk uses Google-managed encryption keys. Customer-managed keys (CMEK) "
                                    "give you control over key lifecycle, rotation, and revocation."
                                ),
                                recommendation="Re-create the disk with a Cloud KMS key for full key lifecycle control.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Take a snapshot, then recreate with CMEK:\n"
                                        f"gcloud compute disks create {disk_name}-cmek \\\n"
                                        f"  --zone={zone_name} \\\n"
                                        f"  --kms-key=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY \\\n"
                                        f"  --source-disk={disk_name} --source-disk-zone={zone_name}"
                                    ),
                                    terraform=(
                                        f'resource "google_compute_disk" "disk" {{\n'
                                        f'  name = "{disk_name}"\n'
                                        f"  disk_encryption_key {{\n"
                                        f"    kms_key_self_link = google_kms_crypto_key.key.self_link\n"
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/compute/docs/disks/customer-managed-encryption",
                                    effort=Effort.HIGH,
                                ),
                                compliance_refs=["CIS GCP 4.7", "ISO 27001 A.10.1.1"],
                            )
                        )
            request = client.disks().aggregatedList_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check disk encryption: {str(e)}"

    return result


def gcp_compute_003(provider: "GCPProvider") -> CheckResult:
    """Check for instances with interactive serial port access enabled."""
    client = provider.get_client("compute", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-compute-003",
        check_name="Compute Instance Serial Port Access",
    )

    try:
        request = client.instances().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for zone, instances_scoped_list in response.get("items", {}).items():
                for instance in instances_scoped_list.get("instances", []):
                    result.resources_scanned += 1
                    instance_name = instance.get("name", "")
                    zone_name = zone.split("/")[-1]

                    metadata_items = instance.get("metadata", {}).get("items", [])
                    serial_enabled = any(
                        item.get("key") == "serial-port-enable" and item.get("value") in ("true", "1")
                        for item in metadata_items
                    )

                    if serial_enabled:
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-003",
                                title=f"Instance '{instance_name}' has serial port access enabled",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="google_compute_instance",
                                resource_id=f"projects/{project_id}/zones/{zone_name}/instances/{instance_name}",
                                region=zone_name,
                                description=(
                                    "Interactive serial port access allows direct console access to the instance, "
                                    "bypassing normal SSH controls and firewall rules. An attacker with project "
                                    "access could use this to gain a shell."
                                ),
                                recommendation="Disable serial port access. Use SSH or IAP for routine access.",
                                remediation=Remediation(
                                    cli=(
                                        f"gcloud compute instances remove-metadata {instance_name} \\\n"
                                        f"  --zone={zone_name} --keys=serial-port-enable"
                                    ),
                                    terraform=(
                                        'resource "google_compute_instance" "vm" {\n'
                                        "  metadata = {\n"
                                        '    serial-port-enable = false\n'
                                        "  }\n"
                                        "}"
                                    ),
                                    doc_url="https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS GCP 4.5", "ISO 27001 A.9.4.2"],
                            )
                        )
            request = client.instances().aggregatedList_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check serial port access: {str(e)}"

    return result


def gcp_compute_004(provider: "GCPProvider") -> CheckResult:
    """Check for instances without OS Login enabled."""
    client = provider.get_client("compute", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-compute-004",
        check_name="Compute Instance OS Login",
    )

    try:
        request = client.instances().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for zone, instances_scoped_list in response.get("items", {}).items():
                for instance in instances_scoped_list.get("instances", []):
                    result.resources_scanned += 1
                    instance_name = instance.get("name", "")
                    zone_name = zone.split("/")[-1]

                    metadata_items = instance.get("metadata", {}).get("items", [])
                    os_login_enabled = any(
                        item.get("key") == "enable-oslogin" and item.get("value", "").lower() == "true"
                        for item in metadata_items
                    )

                    if not os_login_enabled:
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-004",
                                title=f"Instance '{instance_name}' does not have OS Login enabled",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="google_compute_instance",
                                resource_id=f"projects/{project_id}/zones/{zone_name}/instances/{instance_name}",
                                region=zone_name,
                                description=(
                                    "Without OS Login, SSH keys are managed manually per-instance and are not "
                                    "centrally audited. OS Login ties SSH access to Google identities, supports "
                                    "2FA, and lets you revoke access instantly via IAM."
                                ),
                                recommendation="Enable OS Login via instance or project-level metadata to enforce IAM-based SSH access.",
                                remediation=Remediation(
                                    cli=(
                                        f"gcloud compute instances add-metadata {instance_name} \\\n"
                                        f"  --zone={zone_name} --metadata=enable-oslogin=TRUE"
                                    ),
                                    terraform=(
                                        'resource "google_compute_instance" "vm" {\n'
                                        "  metadata = {\n"
                                        '    enable-oslogin = "TRUE"\n'
                                        "  }\n"
                                        "}"
                                    ),
                                    doc_url="https://cloud.google.com/compute/docs/oslogin",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS GCP 4.4", "ISO 27001 A.9.4.2"],
                            )
                        )
            request = client.instances().aggregatedList_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check OS Login: {str(e)}"

    return result


def gcp_compute_005(provider: "GCPProvider") -> CheckResult:
    """Check for unattached persistent disks."""
    client = provider.get_client("compute", "v1")
    project_id = provider.project

    result = CheckResult(
        check_id="gcp-compute-005",
        check_name="Unattached Compute Disks",
    )

    try:
        request = client.disks().aggregatedList(project=project_id)
        while request is not None:
            response = request.execute()
            for zone, disk_list in response.get("items", {}).items():
                for disk in disk_list.get("disks", []):
                    result.resources_scanned += 1
                    disk_name = disk.get("name", "")
                    zone_name = zone.split("/")[-1]

                    # 'users' is absent or empty when a disk has no attached instances
                    if not disk.get("users"):
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-005",
                                title=f"Unattached disk '{disk_name}' in {zone_name}",
                                severity=Severity.LOW,
                                category=Category.COST,
                                resource_type="google_compute_disk",
                                resource_id=f"projects/{project_id}/zones/{zone_name}/disks/{disk_name}",
                                region=zone_name,
                                description=(
                                    "Persistent disk is not attached to any instance. Unattached disks incur "
                                    "ongoing storage costs and may contain sensitive data with no active access controls."
                                ),
                                recommendation="Snapshot the disk if needed, then delete it or re-attach to the intended instance.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Optional: take a snapshot first\n"
                                        f"gcloud compute disks snapshot {disk_name} --zone={zone_name}\n"
                                        f"# Then delete the unattached disk\n"
                                        f"gcloud compute disks delete {disk_name} --zone={zone_name}"
                                    ),
                                    terraform=f'# Remove the google_compute_disk resource for "{disk_name}" if no longer needed.',
                                    doc_url="https://cloud.google.com/compute/docs/disks/delete-a-disk",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS GCP 4.9"],
                            )
                        )
            request = client.disks().aggregatedList_next(previous_request=request, previous_response=response)

    except Exception as e:
        result.error = f"Failed to check unattached disks: {str(e)}"

    return result

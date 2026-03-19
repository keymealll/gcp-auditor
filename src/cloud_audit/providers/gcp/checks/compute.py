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

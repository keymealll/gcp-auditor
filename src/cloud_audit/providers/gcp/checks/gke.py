"""GCP GKE (Google Kubernetes Engine) security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def check_cluster_auth(provider: GCPProvider) -> CheckResult:
    """Check if GKE clusters have legacy ABAC disabled and RBAC enabled."""
    result = CheckResult(check_id="gcp-gke-001", check_name="GKE RBAC enforcement")

    try:
        for region in provider.regions:
            parent = f"projects/{provider.project}/locations/{region}"
            try:
                clusters = provider.container_service.projects().locations().clusters().list(parent=parent).execute()
            except Exception:
                continue

            for cluster in clusters.get("clusters", []):
                result.resources_scanned += 1
                name = cluster["name"]
                location = cluster.get("location", region)

                legacy_abac = cluster.get("legacyAbac", {})
                if legacy_abac.get("enabled", False):
                    result.findings.append(
                        Finding(
                            check_id="gcp-gke-001",
                            title=f"GKE cluster '{name}' has legacy ABAC enabled",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="container.googleapis.com/Cluster",
                            resource_id=f"projects/{provider.project}/locations/{location}/clusters/{name}",
                            region=location,
                            description=(
                                f"GKE cluster '{name}' has legacy Attribute-Based Access Control (ABAC) enabled. "
                                f"ABAC is deprecated and less secure than RBAC."
                            ),
                            recommendation="Disable legacy ABAC and use Kubernetes RBAC for access control.",
                            remediation=Remediation(
                                cli=(
                                    f"gcloud container clusters update {name} \\\n"
                                    f"  --zone={location} \\\n"
                                    f"  --no-enable-legacy-authorization"
                                ),
                                terraform=(
                                    f'resource "google_container_cluster" "{name}" {{\n  enable_legacy_abac = false\n}}'
                                ),
                                doc_url="https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.9.1.2",
                                "ISO 27001 A.9.4.1",
                                "SOC 2 CC6.1",
                                "SOC 2 CC6.3",
                                "CIS GKE 5.8.1",
                            ],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_private_cluster(provider: GCPProvider) -> CheckResult:
    """Check if GKE clusters use private nodes (no public IPs on nodes)."""
    result = CheckResult(check_id="gcp-gke-002", check_name="GKE private cluster")

    try:
        for region in provider.regions:
            parent = f"projects/{provider.project}/locations/{region}"
            try:
                clusters = provider.container_service.projects().locations().clusters().list(parent=parent).execute()
            except Exception:
                continue

            for cluster in clusters.get("clusters", []):
                result.resources_scanned += 1
                name = cluster["name"]
                location = cluster.get("location", region)

                private_config = cluster.get("privateClusterConfig", {})
                if not private_config.get("enablePrivateNodes", False):
                    result.findings.append(
                        Finding(
                            check_id="gcp-gke-002",
                            title=f"GKE cluster '{name}' does not use private nodes",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="container.googleapis.com/Cluster",
                            resource_id=f"projects/{provider.project}/locations/{location}/clusters/{name}",
                            region=location,
                            description=(
                                f"GKE cluster '{name}' nodes have public IP addresses. "
                                f"This exposes cluster nodes directly to the internet."
                            ),
                            recommendation="Enable private nodes to remove public IPs. Use Cloud NAT for outbound access.",
                            remediation=Remediation(
                                cli=(
                                    f"# Note: Cannot be changed on existing cluster without recreation.\n"
                                    f"gcloud container clusters create {name}-private \\\n"
                                    f"  --zone={location} \\\n"
                                    f"  --enable-private-nodes \\\n"
                                    f"  --master-ipv4-cidr=172.16.0.0/28 \\\n"
                                    f"  --enable-ip-alias"
                                ),
                                terraform=(
                                    f'resource "google_container_cluster" "{name}" {{\n'
                                    f"  private_cluster_config {{\n"
                                    f"    enable_private_nodes    = true\n"
                                    f'    master_ipv4_cidr_block  = "172.16.0.0/28"\n'
                                    f"    enable_private_endpoint = false\n"
                                    f"  }}\n"
                                    f"  ip_allocation_policy {{}}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters",
                                effort=Effort.HIGH,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.13.1.1",
                                "ISO 27001 A.13.1.3",
                                "SOC 2 CC6.1",
                                "SOC 2 CC6.6",
                                "CIS GKE 6.6.1",
                            ],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_workload_identity(provider: GCPProvider) -> CheckResult:
    """Check if GKE clusters have Workload Identity enabled."""
    result = CheckResult(check_id="gcp-gke-003", check_name="GKE Workload Identity")

    try:
        for region in provider.regions:
            parent = f"projects/{provider.project}/locations/{region}"
            try:
                clusters = provider.container_service.projects().locations().clusters().list(parent=parent).execute()
            except Exception:
                continue

            for cluster in clusters.get("clusters", []):
                result.resources_scanned += 1
                name = cluster["name"]
                location = cluster.get("location", region)

                wi_config = cluster.get("workloadIdentityConfig", {})
                if not wi_config.get("workloadPool"):
                    result.findings.append(
                        Finding(
                            check_id="gcp-gke-003",
                            title=f"GKE cluster '{name}' does not have Workload Identity enabled",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="container.googleapis.com/Cluster",
                            resource_id=f"projects/{provider.project}/locations/{location}/clusters/{name}",
                            region=location,
                            description=(
                                f"GKE cluster '{name}' does not use Workload Identity. Without it, pods "
                                f"use the node's service account, which is overly permissive."
                            ),
                            recommendation="Enable Workload Identity to bind Kubernetes SAs to GCP SAs with least-privilege.",
                            remediation=Remediation(
                                cli=(
                                    f"gcloud container clusters update {name} \\\n"
                                    f"  --zone={location} \\\n"
                                    f"  --workload-pool={provider.project}.svc.id.goog"
                                ),
                                terraform=(
                                    f'resource "google_container_cluster" "{name}" {{\n'
                                    f"  workload_identity_config {{\n"
                                    f'    workload_pool = "{provider.project}.svc.id.goog"\n'
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.9.2.1",
                                "ISO 27001 A.9.4.3",
                                "SOC 2 CC6.1",
                                "SOC 2 CC6.3",
                                "CIS GKE 5.2.1",
                            ],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all GKE checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_cluster_auth, provider, check_id="gcp-gke-001", category=Category.SECURITY),
        make_check(check_private_cluster, provider, check_id="gcp-gke-002", category=Category.SECURITY),
        make_check(check_workload_identity, provider, check_id="gcp-gke-003", category=Category.SECURITY),
    ]

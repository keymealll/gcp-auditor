"""CVSS v3.1 scoring implementation for cloud security findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AttackVector(str, Enum):
    """Attack Vector (AV) - How exploitable is the vulnerability?"""

    NETWORK = "N"  # Exploitable over the network (0.85)
    ADJACENT = "A"  # Exploitable from adjacent network (0.62)
    LOCAL = "L"  # Requires local access (0.55)
    PHYSICAL = "P"  # Requires physical access (0.20)


class AttackComplexity(str, Enum):
    """Attack Complexity (AC) - Complexity of conditions to exploit."""

    LOW = "L"  # Easy to exploit, no special conditions (0.77)
    HIGH = "H"  # Difficult conditions required (0.44)


class PrivilegesRequired(str, Enum):
    """Privileges Required (PR) - Level of privileges needed."""

    NONE = "N"  # No authentication required (0.85)
    LOW = "L"  # Basic user privileges (0.62, 0.68 if scope changed)
    HIGH = "H"  # Admin/root privileges required (0.27, 0.50 if scope changed)


class UserInteraction(str, Enum):
    """User Interaction (UI) - Does exploitation require user action?"""

    NONE = "N"  # No user interaction required (0.85)
    REQUIRED = "R"  # User action required (0.62)


class Scope(str, Enum):
    """Scope (S) - Can vulnerability affect resources beyond scope?"""

    UNCHANGED = "U"  # Only affects vulnerable component (0.0)
    CHANGED = "C"  # Can affect other components/resources (1.0)


class Impact(str, Enum):
    """Impact levels for Confidentiality, Integrity, Availability."""

    NONE = "N"  # No impact (0.0)
    LOW = "L"  # Partial impact (0.22)
    HIGH = "H"  # Complete impact (0.56)


@dataclass
class CVSSMetrics:
    """CVSS v3.1 Base Score Metrics.

    These metrics capture the inherent characteristics of a vulnerability
    that are constant over time and across user environments.

    Example:
        # Public SSH access
        metrics = CVSSMetrics(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        score = metrics.calculate_score()  # 9.8 (Critical)
    """

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    def calculate_score(self) -> float:
        """Calculate CVSS Base Score (0.0 - 10.0).

        Returns:
            Float between 0.0 and 10.0, rounded to 1 decimal place.
        """
        # Metric values from CVSS v3.1 specification
        av_values = {
            AttackVector.NETWORK: 0.85,
            AttackVector.ADJACENT: 0.62,
            AttackVector.LOCAL: 0.55,
            AttackVector.PHYSICAL: 0.20,
        }

        ac_values = {
            AttackComplexity.LOW: 0.77,
            AttackComplexity.HIGH: 0.44,
        }

        pr_values = {
            PrivilegesRequired.NONE: 0.85,
            PrivilegesRequired.LOW: 0.62,
            PrivilegesRequired.HIGH: 0.27,
        }

        pr_values_scope_changed = {
            PrivilegesRequired.NONE: 0.85,
            PrivilegesRequired.LOW: 0.68,
            PrivilegesRequired.HIGH: 0.50,
        }

        ui_values = {
            UserInteraction.NONE: 0.85,
            UserInteraction.REQUIRED: 0.62,
        }

        impact_values = {
            Impact.NONE: 0.0,
            Impact.LOW: 0.22,
            Impact.HIGH: 0.56,
        }

        # Get metric values
        av = av_values[self.attack_vector]
        ac = ac_values[self.attack_complexity]
        ui = ui_values[self.user_interaction]

        # PR depends on scope
        if self.scope == Scope.CHANGED:
            pr = pr_values_scope_changed[self.privileges_required]
        else:
            pr = pr_values[self.privileges_required]

        c = impact_values[self.confidentiality]
        i = impact_values[self.integrity]
        a = impact_values[self.availability]

        # Calculate Impact Sub-Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact based on Scope
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if self.scope == Scope.CHANGED else 6.42 * iss

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif self.scope == Scope.CHANGED:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        return round(base_score, 1)

    def get_severity(self) -> str:
        """Get severity rating based on CVSS score.

        Returns:
            One of: CRITICAL, HIGH, MEDIUM, LOW, NONE
        """
        score = self.calculate_score()
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        return "NONE"

    def get_severity_emoji(self) -> str:
        """Get emoji representation of severity."""
        score = self.calculate_score()
        if score >= 9.0:
            return "🔴"
        elif score >= 7.0:
            return "🟠"
        elif score >= 4.0:
            return "🟡"
        elif score >= 0.1:
            return "🟢"
        return "⚪"

    def to_vector_string(self) -> str:
        """Generate CVSS v3.1 vector string.

        Returns:
            CVSS vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        """
        return (
            f"CVSS:3.1/"
            f"AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.confidentiality.value}/"
            f"I:{self.integrity.value}/"
            f"A:{self.availability.value}"
        )

    @classmethod
    def from_vector_string(cls, vector: str) -> CVSSMetrics:
        """Parse CVSS vector string into metrics.

        Args:
            vector: CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."

        Returns:
            CVSSMetrics instance
        """
        # Remove prefix if present
        if vector.startswith("CVSS:3.1/"):
            vector = vector[9:]

        metrics = {}
        for part in vector.split("/"):
            if ":" in part:
                key, value = part.split(":")
                metrics[key] = value

        return cls(
            attack_vector=AttackVector(metrics.get("AV", "N")),
            attack_complexity=AttackComplexity(metrics.get("AC", "L")),
            privileges_required=PrivilegesRequired(metrics.get("PR", "N")),
            user_interaction=UserInteraction(metrics.get("UI", "N")),
            scope=Scope(metrics.get("S", "U")),
            confidentiality=Impact(metrics.get("C", "N")),
            integrity=Impact(metrics.get("I", "N")),
            availability=Impact(metrics.get("A", "N")),
        )


# Predefined CVSS profiles for common cloud misconfigurations
# These provide consistent risk scoring across findings

CHECK_CVSS_PROFILES: dict[str, CVSSMetrics] = {
    # Critical: Direct exposure to internet with no authentication
    "gcp-firewall-001": CVSSMetrics(  # Overly permissive firewall (SSH/RDP open)
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),  # Score: 10.0 (Critical)
    "gcp-storage-001": CVSSMetrics(  # Public storage bucket
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.LOW,
    ),  # Score: 7.5 (High)
    "gcp-iam-003": CVSSMetrics(  # Overly permissive IAM (Owner/Editor)
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),  # Score: 9.9 (Critical)
    "gcp-sql-001": CVSSMetrics(  # Cloud SQL public IP
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.LOW,
    ),  # Score: 7.5 (High)
    "gcp-gke-001": CVSSMetrics(  # GKE public control plane
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),  # Score: 10.0 (Critical)
    # High: Significant security risk but requires some conditions
    "gcp-iam-001": CVSSMetrics(  # Service account key rotation
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.LOW,
    ),  # Score: 7.2 (High)
    "gcp-iam-002": CVSSMetrics(  # Overly permissive IAM roles
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),  # Score: 9.9 (Critical)
    "gcp-storage-002": CVSSMetrics(  # Uniform bucket-level access disabled
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 4.3 (Medium)
    "gcp-compute-001": CVSSMetrics(  # VM with public IP
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),  # Score: 10.0 (Critical)
    "gcp-kms-002": CVSSMetrics(  # KMS key overly permissive IAM
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),  # Score: 8.5 (High)
    # Medium: Moderate concerns, defense in depth
    "gcp-compute-002": CVSSMetrics(  # Disk without CMEK
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),  # Score: 2.0 (Low)
    "gcp-compute-003": CVSSMetrics(  # Serial port access enabled
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 3.0 (Low)
    "gcp-compute-004": CVSSMetrics(  # OS Login not enabled
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 3.0 (Low)
    "gcp-firewall-002": CVSSMetrics(  # Default VPC exists
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 3.8 (Low)
    "gcp-firewall-003": CVSSMetrics(  # VPC Flow Logs disabled
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),  # Score: 2.0 (Low)
    "gcp-kms-001": CVSSMetrics(  # KMS key rotation
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),  # Score: 2.0 (Low)
    "gcp-sql-002": CVSSMetrics(  # Cloud SQL SSL not enforced
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 5.3 (Medium)
    "gcp-sql-003": CVSSMetrics(  # Cloud SQL no automated backups
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.NONE,
        availability=Impact.LOW,
    ),  # Score: 3.1 (Low)
    "gcp-logging-002": CVSSMetrics(  # No log export sinks
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),  # Score: 2.0 (Low)
    "gcp-logging-003": CVSSMetrics(  # Log retention too short
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),  # Score: 2.0 (Low)
    "gcp-bigquery-001": CVSSMetrics(  # BigQuery dataset public
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 5.3 (Medium)
    "gcp-gke-002": CVSSMetrics(  # GKE legacy ABAC enabled
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.LOW,
    ),  # Score: 8.5 (High)
    "gcp-gke-003": CVSSMetrics(  # GKE no workload identity
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),  # Score: 4.0 (Medium)
    # Cost/Reliability checks - Lower security impact
    "gcp-storage-003": CVSSMetrics(  # Bucket without versioning
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.LOW,
        availability=Impact.LOW,
    ),  # Score: 2.5 (Low)
    "gcp-storage-004": CVSSMetrics(  # Bucket without lifecycle policy
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.NONE,
        availability=Impact.LOW,
    ),  # Score: 2.0 (Low)
    "gcp-storage-005": CVSSMetrics(  # Bucket without lifecycle rules
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.NONE,
        availability=Impact.LOW,
    ),  # Score: 2.0 (Low)
    "gcp-compute-005": CVSSMetrics(  # Unattached disk
        attack_vector=AttackVector.LOCAL,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),  # Score: 0.0 (None)
}


def get_cvss_profile(check_id: str) -> CVSSMetrics:
    """Get CVSS metrics for a check ID.

    Returns predefined profile if available, otherwise returns
    a default medium-risk profile.

    Args:
        check_id: The check identifier (e.g., "gcp-firewall-001")

    Returns:
        CVSSMetrics instance for the check
    """
    if check_id in CHECK_CVSS_PROFILES:
        return CHECK_CVSS_PROFILES[check_id]

    # Default medium-risk profile for unknown checks
    return CVSSMetrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    )  # Score: 4.3 (Medium)

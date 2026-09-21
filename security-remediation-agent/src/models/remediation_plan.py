from dataclasses import dataclass, field
from typing import Any

from ..models.security_remediation_context import SecurityRemediationContext
from ..models.triage_result import ActionType, PackageContext
from ..tools.model.pull_request_metadata import PullRequestMetadata
from ..tools.model.vulnerability_alert import VulnerabilityAlert


@dataclass
class RemeditionPackage:
    remediation_package: str
    ecosystem: str
    current_version: str | None = None
    remediation_version: str = ""
    packages: list[PackageContext] = field(default_factory=list)
    remediation_prs: list[PullRequestMetadata] = field(default_factory=list)
    # Set when peer-dependency reconciliation had to RAISE this package's
    # remediation_version above the originally requested/floor version to
    # satisfy another package's peerDependencies range within the bundle.
    # The floor itself (the security-mandated minimum, e.g. from Renovate's
    # allowedVersions) is never lowered by reconciliation -- only raised or
    # left unresolved as a reported conflict.
    peer_adjusted: bool = False
    original_remediation_version: str | None = None


@dataclass
class PeerDependencyConflict:
    """A peer dependency requirement that the bundle's chosen versions cannot satisfy together."""
    package: str
    peer_of: str
    required_range: str
    resolved_version: str


@dataclass
class RemeditionPackageBundle:
    groupName: str
    ecosystem: str
    severity: str
    packages: list[RemeditionPackage] = field(default_factory=list)
    action_type: ActionType | None = None
    # Unresolved peer-dependency conflicts remaining after reconciliation
    # (empty when everything in the bundle is peer-compatible).
    peer_dependency_conflicts: list[PeerDependencyConflict] = field(default_factory=list)


@dataclass
class RemediationPlan:
    remediation_plan_bundles: list[RemeditionPackageBundle] = field(default_factory=list)
    summary: SecurityRemediationContext | None = None

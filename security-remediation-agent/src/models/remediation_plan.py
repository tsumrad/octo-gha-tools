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


@dataclass
class RemeditionPackageBundle:
    groupName: str
    ecosystem: str
    severity: str
    update_category: str = "" # Major, Minor/Patch
    packages: list[RemeditionPackage] = field(default_factory=list)
    action_type: ActionType | None = None


@dataclass
class RemediationPlan:
    remediation_plan_bundles: list[RemeditionPackageBundle] = field(default_factory=list)
    summary: SecurityRemediationContext | None = None

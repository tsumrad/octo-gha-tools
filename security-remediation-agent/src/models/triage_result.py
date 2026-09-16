from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..tools.model.pull_request_metadata import PullRequestMetadata
from ..tools.model.vulnerability_alert import VulnerabilityAlert
from ..models.security_package_triage import PackageUpgradeRecommendation, TransistiveOccurances, is_direct_package

# ── Enums ──────────────────────────────────────────────────────────────────────

class ActionType(str, Enum):
    ROLLUP_PR      = "rollup_pr"        # non-breaking + PR exists → grouped
    STANDALONE_PR  = "standalone_pr"    # breaking + PR exists → separate
    PLACEHOLDER_PR = "placeholder_pr"   # no PR exists → markdown stub
    OPEN_ISSUE     = "open_issue"       # no fix available

class CodingAgent(str, Enum):
    COPILOT = "copilot"
    LLM     = "llm"
    NONE    = "none"

# ── Sub-models ─────────────────────────────────────────────────────────────────


@dataclass
class PackageContext:
    name: str
    ecosystem: str
    transitive_dependency_occurrences: list[TransistiveOccurances] = field(default_factory=list)
    package_upgrade_recommendations: list[PackageUpgradeRecommendation] = field(default_factory=list)
    current_version: str | None = None
    relationship: str | None = None
    vulnerabilities: list[VulnerabilityAlert] = field(default_factory=list)
    pull_requests: list[PullRequestMetadata] = field(default_factory=list)
    fixed_minimum_version: str = ""
    fixed_maximum_version: str = ""
    isbreakable: bool = False
    upgrade_to_version: str = ""
    action_type: ActionType | None = None

    @property
    def is_direct(self) -> bool:
        return is_direct_package(self.transitive_dependency_occurrences)


@dataclass
class IssueContext:        
    ecosystem: str | None = None
    severity: str | None = None
    packages: list[PackageContext] = field(default_factory=list)


# ── Main model ─────────────────────────────────────────────────────────────────


@dataclass
class TriageResult:
    plan_id:    str
    created_at: datetime
    remediation_plans: list[IssueContext] = field(default_factory=list)

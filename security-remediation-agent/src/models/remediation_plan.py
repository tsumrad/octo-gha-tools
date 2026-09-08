from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from dataclasses import field

from tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata
from tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert

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
    current_version: str | None = None
    relationship: str | None = None
    vulnerabilities: list[VulnerabilityAlert] = field(default_factory=list)
    pull_requests: list[PullRequestMetadata] = field(default_factory=list)
    fixed_minimum_version: str = ""
    fixed_maximum_version: str = ""
    isbreakable: bool = False
    upgrade_to_version: str = ""
    action_type: ActionType | None = None


@dataclass
class IssueContext:        
    ecosystem: str | None = None
    severity: str | None = None
    packages: list[PackageContext] = field(default_factory=list)
    coding_agent: CodingAgent | None = None


@dataclass
class SummaryContext:
    total_vulnerabilities: int = 0
    total_code_scanning_alerts: int = 0
    total_reviewed_prs: int = 0
    total_ignored_prs: int = 0
    total_remediation_prs: int = 0
    total_created_rollup_prs: int = 0
    total_created_issues: int = 0

    ecosystem_summary: list[EcosystemContext] = field(default_factory=list)
    

@dataclass
class EcosystemContext:
    name: str = ""
    direct_vulnerabile_packages: list[str] = field(default_factory=list)
    transitive_vulnerabile_packages: list[str] = field(default_factory=list)

# ── Main model ─────────────────────────────────────────────────────────────────

@dataclass
class RemediationPlan:
    plan_id:    str
    created_at: datetime
    summary: SummaryContext | None = None
    remediation_plans:    list[IssueContext] = field(default_factory=list)

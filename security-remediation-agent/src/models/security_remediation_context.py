from dataclasses import dataclass, field
from typing import Any
from dataclasses import field

@dataclass
class VulnerabilitySummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    others: int = 0

@dataclass
class SecurityRemediationContext:
    total_vulnerabilities: int = 0
    total_code_scanning_alerts: int = 0
    total_reviewed_prs: int = 0
    total_ignored_prs: int = 0
    total_remediation_prs: int = 0
    vulnerabilities_summary: VulnerabilitySummary = field(default_factory=VulnerabilitySummary)
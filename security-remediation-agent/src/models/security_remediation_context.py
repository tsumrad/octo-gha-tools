from dataclasses import dataclass, field
from typing import Any
from dataclasses import field


@dataclass
class SecurityRemediationContext:
    total_vulnerabilities: int = 0
    total_code_scanning_alerts: int = 0
    total_reviewed_prs: int = 0
    total_ignored_prs: int = 0
    total_remediation_prs: int = 0
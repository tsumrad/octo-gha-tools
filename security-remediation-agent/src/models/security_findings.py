from dataclasses import dataclass

from src.tools.model.codescanning_alert import CodescanningAlert
from src.tools.model.vulnerability_alert import VulnerabilityAlert

@dataclass
class SecurityFindings:
    dependabot_alerts: list[VulnerabilityAlert]
    codescanning_alerts: list[CodescanningAlert]

    def is_empty(self) -> bool:
        return not self.dependabot_alerts and not self.codescanning_alerts

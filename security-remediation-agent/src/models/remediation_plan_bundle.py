from dataclasses import dataclass, field
from typing import Iterator

from ..models.remediation_plan import RemediationPlan   # ← the real RemediationPlan


@dataclass
class RemediationPlanGroup:                             # ← fix 1
    severity: str
    plans: list[RemediationPlan] = field(default_factory=list)

    def add(self, plan: RemediationPlan) -> None:
        self.plans.append(plan)

    def __len__(self) -> int:
        return len(self.plans)


@dataclass
class RemediationPlanBundle:                            # ← fix 2
    groups: dict[str, RemediationPlanGroup] = field(default_factory=dict)

    _SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]

    @classmethod
    def from_plans(cls, plans: list[RemediationPlan]) -> RemediationPlanBundle:
        bundle = cls()
        for plan in plans:
            bundle.add(plan)
        return bundle

    def add(self, plan: RemediationPlan) -> None:
        severity = plan.package.effective_severity.lower()
        if severity not in self.groups:
            self.groups[severity] = RemediationPlanGroup(severity=severity)
        self.groups[severity].add(plan)

    def by_severity(self, severity: str) -> RemediationPlanGroup | None:
        return self.groups.get(severity.lower())

    def ordered(self) -> Iterator[RemediationPlanGroup]:
        for sev in self._SEVERITY_ORDER:
            if sev in self.groups:
                yield self.groups[sev]

    def summary(self) -> dict[str, int]:
        return {sev: len(group) for sev, group in self.groups.items()}

    def __len__(self) -> int:
        return sum(len(g) for g in self.groups.values())
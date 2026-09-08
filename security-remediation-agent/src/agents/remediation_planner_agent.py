from models.remediation_plan import EcosystemContext, RemediationPlan, SummaryContext
import logging
logger = logging.getLogger(__name__)
from ..models.security_package_triage import SecurityPackageTriage
from ..tools.remediation_planning_assistant.remediation_planning_tool import (
    build_remediation_plan,
)
from ..models.security_remediation_context import SecurityRemediationContext

class RemediationPlannerAgent:
    def __init__(self) -> None:
        self.tools = [build_remediation_plan]

    async def plan(
        self,
        triage_result: list[SecurityPackageTriage],
        context: SecurityRemediationContext
    ) -> RemediationPlan:
        plan = await build_remediation_plan.ainvoke({"triage_result": triage_result})
        return RemediationPlan(
            plan_id=plan.plan_id,
            created_at=plan.created_at,
            remediation_plans=plan.remediation_plans,
            summary=self.build_summary(triage_result, context),
        )
        


    def build_summary(
        self,
        triage_result: list[SecurityPackageTriage],
        context: SecurityRemediationContext
    ) -> SummaryContext:
        grouped: dict[str, EcosystemContext] = {} 
        
        for pkg in triage_result:
            ecosystem = grouped.setdefault(
                pkg.ecosystem,
                EcosystemContext(
                    name=pkg.ecosystem,
                ),
            )
            context.total_remediation_prs += len(pkg.pull_request_metadata)
            
            # Direct / transitive classification
            if pkg.istransitive:
                if pkg.package not in ecosystem.transitive_vulnerabile_packages:
                    ecosystem.transitive_vulnerabile_packages.append(pkg.package)
            else:
                if pkg.package not in ecosystem.direct_vulnerabile_packages:
                    ecosystem.direct_vulnerabile_packages.append(pkg.package)
        context.total_ignored_prs = context.total_reviewed_prs - context.total_remediation_prs
        return SummaryContext(
            ecosystem_summary=list(grouped.values()),
            context=context
        )

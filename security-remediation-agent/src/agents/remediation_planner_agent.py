from models.remediation_plan import RemediationPlan
import logging
logger = logging.getLogger(__name__)
from ..models.security_package_triage import SecurityPackageTriage
from ..tools.remediation_planning_assistant.remediation_planning_tool import (
    build_remediation_plan,
)


class RemediationPlannerAgent:
    def __init__(self) -> None:
        self.tools = [build_remediation_plan]

    async def plan(
        self,
        triage_result: list[SecurityPackageTriage],
    ) -> RemediationPlan:
        logger.info("Planning remediation for package: %s", len(triage_result))
        plans = await build_remediation_plan.ainvoke({"triage_result": triage_result})

        return plans

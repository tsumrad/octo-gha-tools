import logging
import uuid

from ..engines.peer_dependency_reconciler import PeerDependencyReconciler
from ..engines.remediation_grouping_engine import RemediationGroupingEngine
from ..models.remediation_plan import (
    RemediationPlan,
    RemeditionPackage,
    RemeditionPackageBundle,
)
from ..models.security_package_triage import SecurityPackageTriage, is_direct_occurrence
from ..models.security_remediation_context import SecurityRemediationContext
from ..models.triage_result import PackageContext, TriageResult
from ..tools.remediation_planning_tool import build_remediation_plan
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)


class RemediationPlannerAgent:
    def __init__(self) -> None:
        self.tools = [build_remediation_plan]
        self._peer_reconciler = PeerDependencyReconciler()

    @staticmethod
    def _merge_packages(target: RemeditionPackage, package: PackageContext) -> None:
        if any(existing.name == package.name for existing in target.packages):
            return
        target.packages.append(package)

    @staticmethod
    def _merge_pull_requests(target: RemeditionPackage, pull_requests) -> None:
        for pull in pull_requests:
            if any(existing.pr_number == pull.pr_number for existing in target.remediation_prs):
                continue
            target.remediation_prs.append(pull)

    @staticmethod
    def _merge_remediation_packages(target: RemeditionPackage, source: RemeditionPackage) -> None:
        """Fold a duplicate RemeditionPackage entry (same remediation_package name)
        into the first one seen for that name, keeping the highest remediation
        version and merging their PackageContext/PR lists.
        """
        for package in source.packages:
            if not any(existing.name == package.name for existing in target.packages):
                target.packages.append(package)
        RemediationPlannerAgent._merge_pull_requests(target, source.remediation_prs)

        if not target.current_version and source.current_version:
            target.current_version = source.current_version
        if not target.remediation_version and source.remediation_version:
            target.remediation_version = source.remediation_version

    @staticmethod
    def _dedupe_bundle_packages(
        packages: list[RemeditionPackage],
    ) -> list[RemeditionPackage]:
        """Collapse duplicate entries in a bundle that share the same
        remediation_package name (e.g. the same package reported once as a
        direct dependency and again as a transitive one, such as showdown or
        axios appearing twice under the same group)."""
        deduped: dict[str, RemeditionPackage] = {}
        for package in packages:
            key = package.remediation_package
            if key not in deduped:
                deduped[key] = package
            else:
                RemediationPlannerAgent._merge_remediation_packages(deduped[key], package)
        return list(deduped.values())

    @staticmethod
    def _build_remediation_package_bundles_by_ecosystem(
        remediation_packages: list[RemeditionPackage],
    ) -> list[RemeditionPackageBundle]:
        """Fallback grouping used when Renovate packageRules aren't available."""
        grouped: dict[str, list[RemeditionPackage]] = {}
        for package in remediation_packages:
            group_name = package.ecosystem or "unknown"
            grouped.setdefault(group_name, []).append(package)

        return [
            RemeditionPackageBundle(
                groupName=group_name,
                ecosystem=group_name,
                severity=None,
                packages=RemediationPlannerAgent._dedupe_bundle_packages(packages),
            )
            for group_name, packages in grouped.items()
        ]

    async def _build_remediation_package_bundles(
        self,
        remediation_packages: list[RemeditionPackage],
        repo: dict | None,
    ) -> list[RemeditionPackageBundle]:
        logger.info("Starting to build remediation package bundles")
        """Group packages using the repository's Renovate packageRules when possible.

        Falls back to grouping by ecosystem if `repo` isn't provided or the
        renovate.json5 config can't be fetched/parsed. Every returned bundle
        has had its packages' versions peer-dependency-reconciled: grouping
        alone (Renovate packageRules) does not guarantee the chosen versions
        install together, so this is re-verified each time a bundle is built.
        """
        owner = (repo or {}).get("owner")
        name = (repo or {}).get("name")
        logger.info("Building remediation package bundles for repo: %s/%s", owner, name)
        if not owner or not name:
            bundles = self._build_remediation_package_bundles_by_ecosystem(remediation_packages)
            await self._reconcile_peer_dependencies(bundles)
            return bundles

        try:
            bundles = await RemediationGroupingEngine.group_packages_from_github(
                remediation_packages, owner, name
            )
        except Exception as e:
            logger.warning(
                "Falling back to ecosystem-based grouping; failed to group by Renovate packageRules for %s/%s: %s",
                owner,
                name,
                e,
            )
            bundles = self._build_remediation_package_bundles_by_ecosystem(remediation_packages)
            await self._reconcile_peer_dependencies(bundles)
            return bundles

        for bundle in bundles:
            bundle.packages = self._dedupe_bundle_packages(bundle.packages)
        await self._reconcile_peer_dependencies(bundles)
        return bundles

    async def _reconcile_peer_dependencies(self, bundles: list[RemeditionPackageBundle]) -> None:
        """Verify/adjust each bundle's package versions for npm peerDependencies
        compatibility. Runs every time bundles are (re)built, since grouping
        (Renovate packageRules) and per-package version floors (allowedVersions)
        don't by themselves guarantee the set installs together."""
        for bundle in bundles:
            try:
                await self._peer_reconciler.reconcile(bundle)
            except Exception as e:
                logger.warning(
                    "Peer dependency reconciliation failed for bundle %s: %s", bundle.groupName, e
                )

    def _normalize_remediation_bundle(self, remediation_plan_bundles: list[RemeditionPackageBundle]) -> None:
        for bundle in remediation_plan_bundles:
            bundle.severity = (
                "HIGH"
                if any(
                    Version(p.remediation_version.lstrip("vV")).major
                    > Version(p.current_version.lstrip("vV")).major
                    for p in bundle.packages
                    if p.current_version and p.remediation_version
                )
                else "MINOR/PATCH"
            )

           
    async def plan(
        self,
        triage_result: TriageResult,
        context: SecurityRemediationContext,
        repo: dict | None = None,
    ) -> RemediationPlan:
        logger.info(
            "Planning remediation for triage result with %d remediation plans",
            len(triage_result.remediation_plans),
        )

        direct_remediation_packages: list[RemeditionPackage] = []
        transitive_remediation_packages: list[RemeditionPackage] = []
        unique_update_packages: dict[str, RemeditionPackage] = {}

        for plan in triage_result.remediation_plans:
            for package in plan.packages:
                if package.is_direct:     
                    logger.info("Direct Package: %s", package.name)               
                    direct_remediation_packages.append(
                        RemeditionPackage(
                            remediation_package=package.name,
                            ecosystem=package.ecosystem,
                            current_version=package.current_version,
                            remediation_version=package.fixed_minimum_version,
                            packages=[package],
                            remediation_prs=list(package.pull_requests),
                        )
                    )
                    continue

                logger.info(
                    "Transitive package: %s | current_version: %s | vulnerabilities: %d",
                    package.name,
                    package.current_version,
                    len(package.vulnerabilities),
                )

                for occurrence in package.package_upgrade_recommendations:
                    key = occurrence.package
                    # For a transitive RemeditionPackage, the "package" being
                    # remediated here IS the introducer (occurrence.package),
                    # not the vulnerable child (package.name). Its
                    # current_version must reflect the introducer's own
                    # installed version (occurrence.from_version, resolved
                    # from the lockfile/manifest ancestor), not the child
                    # vulnerable package's current_version -- otherwise the
                    # bundle shows e.g. "@vue/cli-service" upgrading from the
                    # child dependency's version instead of its own.
                    if key not in unique_update_packages:
                        unique_update_packages[key] = RemeditionPackage(
                            remediation_package=key,
                            ecosystem=package.ecosystem,
                            current_version=occurrence.from_version or package.current_version,
                            remediation_version=occurrence.to_version,
                            packages=[package],
                            remediation_prs=list(package.pull_requests),
                        )
                    else:
                        update_package = unique_update_packages[key]
                        self._merge_packages(update_package, package)
                        self._merge_pull_requests(update_package, package.pull_requests)
                        if not update_package.current_version and occurrence.from_version:
                            update_package.current_version = occurrence.from_version

        transitive_remediation_packages = list(unique_update_packages.values())

        all_remediation_packages = [*direct_remediation_packages, *transitive_remediation_packages]
        remediation_plan_bundles = await self._build_remediation_package_bundles(all_remediation_packages, repo)
        plan_result = RemediationPlan(
            remediation_plan_bundles=remediation_plan_bundles,
            summary= context,
        )

        for bundle in remediation_plan_bundles:
            logger.info(
                "Remediation bundle: %s (%s) (%d packages)", bundle.groupName, bundle.ecosystem, len(bundle.packages)
            )
            for package in bundle.packages:
                logger.info(
                    "  Package: %s | current_version: %s | remediation_version: %s | remediation_prs: %d",
                    package.remediation_package,
                    package.current_version,
                    package.remediation_version,
                    len(package.remediation_prs),
                )
        return plan_result


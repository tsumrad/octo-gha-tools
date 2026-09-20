"""Resolve installed npm introducers from cached repository lockfiles."""
import json
import asyncio
import subprocess
import logging
from pathlib import PurePosixPath

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..engines.relationship_resolver.npm_resolver import NpmResolver
from ..engines.relationship_resolver.pip_resolver import PipResolver
from ..engines.relationship_resolver.poetry_resolver import PoetryResolver
from ..engines.version_resolver.npm_parent_version_resolver import NpmParentVersionResolver
from ..models.security_package_triage import (
    OccurrenceClassification,
    PackageUpgradeRecommendation,
)
from ..tools.github_manifest_fetcher import ManifestFetcher

logger = logging.getLogger(__name__)


class TransitiveLookup:
    def __init__(self, fetcher=None):
        self.fetcher = fetcher or ManifestFetcher()

    async def populate(self, owner, repo, items, ref=None):
        resolvers = {}
        npm_upgrade_resolvers = {}
        npm_resolution_cache = {}
        npm_root_packages = {}
        for item in items:
            ecosystem = item.ecosystem.lower()
            # The resolver is now mandatory for every supported ecosystem so it
            # can independently verify Dependabot's reported relationship,
            # regardless of what Dependabot claims (direct vs transitive).
            if ecosystem not in {"npm", "npm_and_yarn", "pip", "pypi", "poetry"}:
                continue
            paths = {a.manifest_path for a in item.vulnerabilities if a.manifest_path}
            for path in sorted(paths):
                is_python = ecosystem in {"pip", "pypi", "poetry"}
                is_poetry = is_python and PurePosixPath(path).name in {"poetry.lock", "pyproject.toml"}
                lock_path = path if is_python else str(PurePosixPath(path).parent / "package-lock.json")
                if is_poetry:
                    lock_path = str(PurePosixPath(path).parent / "poetry.lock")
                # Include the complete repository snapshot identity. This also
                # prevents a future refactor that reuses this resolver map from
                # accidentally serving a graph from another ref.
                key = (owner.lower(), repo.lower(), ref, ecosystem, lock_path)
                if key not in resolvers:
                    try:
                        text = await self.fetcher.fetch(owner, repo, lock_path, ref)
                        if is_poetry:
                            project_path = str(PurePosixPath(path).parent / "pyproject.toml")
                            project_text = await self.fetcher.fetch(owner, repo, project_path, ref)
                            resolvers[key] = PoetryResolver(text, project_text)
                        else:
                            if is_python:
                                resolvers[key] = await asyncio.to_thread(PipResolver.from_text, text)
                            else:
                                resolvers[key] = NpmResolver(json.loads(text))
                                package_path = str(
                                    PurePosixPath(lock_path).parent / "package.json"
                                )
                                package_text = await self.fetcher.fetch(
                                    owner, repo, package_path, ref
                                )
                                package_manifest = json.loads(package_text)
                                npm_root_packages[key] = {
                                    package_name.lower()
                                    for field in (
                                        "dependencies",
                                        "devDependencies",
                                        "optionalDependencies",
                                    )
                                    for package_name in package_manifest.get(field, {})
                                }
                                npm_upgrade_resolvers[key] = NpmParentVersionResolver(
                                    package_text, text
                                )
                    except (httpx.HTTPError, ValueError, subprocess.SubprocessError) as exc:
                        logger.warning("Cannot resolve transitive parents from %s: %s", lock_path, exc)
                        resolvers[key] = None
                resolver = resolvers[key]
                if resolver is None:
                    continue
                result = resolver.resolve(item.package)
                occurrences = ([result] if result.get("version") else []) if is_python and not is_poetry else result["occurrences"]
                for occurrence in occurrences:
                    if not self._is_vulnerable_occurrence(
                        occurrence.get("version"),
                        item.vulnerable_version_range,
                        item.remediated_version,
                    ):
                        continue
                    introducers = [
                        {
                            **introducer,
                            "classification": OccurrenceClassification.ROOT,
                        }
                        for introducer in occurrence.get("introducers", [])
                        # A vulnerable transitive package cannot introduce itself.
                        # Also verify roots against package.json instead of
                        # trusting an inferred lockfile ancestor classification.
                        if is_python
                        or (
                            introducer.get("package", "").lower()
                            != item.package.lower()
                            and introducer.get("package", "").lower()
                            in npm_root_packages.get(key, set())
                        )
                    ]
                    if not is_python:
                        upgrade_resolver = npm_upgrade_resolvers.get(key)
                        if upgrade_resolver is not None:
                            for introducer in introducers:
                                resolution_key = (
                                    key,
                                    introducer["package"].lower(),
                                    introducer.get("version"),
                                    item.package.lower(),
                                    item.vulnerable_version_range,
                                    item.remediated_version,
                                )
                                if resolution_key not in npm_resolution_cache:
                                    try:
                                        npm_resolution_cache[resolution_key] = (
                                            await upgrade_resolver.resolve(
                                                introducer["package"],
                                                item.package,
                                                item.vulnerable_version_range,
                                                fixed_version=item.remediated_version,
                                                current_parent_version=introducer.get("version"),
                                            )
                                        )
                                    except (httpx.HTTPError, OSError, subprocess.SubprocessError) as exc:
                                        logger.warning(
                                            "Cannot resolve npm parent upgrade for %s: %s",
                                            introducer["package"], exc,
                                        )
                                        npm_resolution_cache[resolution_key] = None
                                resolution = npm_resolution_cache[resolution_key]
                                if resolution is not None and resolution.resolved:
                                    introducer["recommended_version"] = resolution.resolved_version
                                    introducer["recommendation_source"] = resolution.source
                                    introducer["requires_verification"] = (
                                        resolution.requires_verification
                                    )
                                    introducer["recommendation_action"] = resolution.action
                                    self._upsert_recommendation(
                                        item,
                                        package=introducer["package"],
                                        from_version=introducer.get("version") or "",
                                        to_version=resolution.resolved_version,
                                        source=resolution.source,
                                        requires_verification=resolution.requires_verification,
                                    )
                                elif resolution is not None:
                                    logger.warning(
                                        "npm recommendation unresolved for %s; candidates: %s",
                                        introducer["package"],
                                        resolution.candidates_considered,
                                    )
                    # Absence of a path is not evidence that the package is a
                    # direct dependency; it can also mean an incomplete graph.
                    # NpmResolver explicitly reports direct-root membership.
                    # PipResolver reports direct/root packages by returning the
                    # target itself as its own introducer (requested=True), so
                    # detect that self-introducer case explicitly.
                    is_pip_self_introduced = is_python and not is_poetry and any(
                        introducer.get("package", "").lower() == item.package.lower()
                        for introducer in introducers
                    )
                    classification = (
                        OccurrenceClassification.ROOT
                        if occurrence.get("is_root", False) or is_pip_self_introduced
                        else OccurrenceClassification.TRANSITIVE
                    )
                    # The resolver reads the actual manifest/lockfile and is
                    # treated as the source of truth. Dependabot's reported
                    # relationship is only used for comparison/logging so any
                    # disagreement is visible without silently overriding
                    # the resolver's verdict.
                    resolver_says_transitive = classification == OccurrenceClassification.TRANSITIVE
                    if resolver_says_transitive != item.istransitive:
                        logger.warning(
                            "Relationship mismatch for %s in %s: Dependabot reported %s, "
                            "PipResolver/NpmResolver determined %s from %s. Using resolver result.",
                            item.package,
                            lock_path,
                            "transitive" if item.istransitive else "direct",
                            "transitive" if resolver_says_transitive else "direct",
                            lock_path,
                        )
                    item.istransitive = resolver_says_transitive
                    occurrence = {
                        **occurrence,
                        "introducers": introducers,
                        "manifest_path": lock_path,
                        "classification": classification,
                    }
                    if occurrence not in item.transitive_dependency_occurrences:
                        item.transitive_dependency_occurrences.append(occurrence)
                    if occurrence.get("version") and not item.current_version:
                        item.current_version = occurrence["version"]

    @staticmethod
    def _upsert_recommendation(
        item,
        *,
        package: str,
        from_version: str,
        to_version: str,
        source: str,
        requires_verification: bool,
    ) -> None:
        """Populate one recommendation per root package, independently of PRs."""
        existing = next(
            (
                recommendation
                for recommendation in item.package_upgrade_recommendations
                if recommendation.package.lower() == package.lower()
            ),
            None,
        )
        if existing is None:
            item.package_upgrade_recommendations.append(
                PackageUpgradeRecommendation(
                    package=package,
                    from_version=from_version,
                    to_version=to_version,
                    source=source,
                    requires_verification=requires_verification,
                )
            )
            return

        # Prefer a verified result if another occurrence produced one.
        if existing.requires_verification and not requires_verification:
            existing.from_version = from_version
            existing.to_version = to_version
            existing.source = source
            existing.requires_verification = False

    @staticmethod
    def _is_vulnerable_occurrence(
        installed_version: str | None,
        vulnerable_range: str | None,
        first_patched_version: str | None,
    ) -> bool:
        """Keep only occurrences covered by the alert's vulnerable range.

        GitHub ranges can contain comma-separated AND constraints and ``||``
        alternatives. If the range cannot be parsed, fall back to the first
        patched version. On an unrecognised version, retain the occurrence so
        a vulnerable path is never silently hidden.
        """
        if not installed_version:
            return True
        try:
            installed = Version(installed_version)
        except InvalidVersion:
            return True

        if vulnerable_range:
            try:
                return any(
                    SpecifierSet(part.strip()).contains(
                        installed, prereleases=True
                    )
                    for part in vulnerable_range.split("||")
                    if part.strip()
                )
            except InvalidSpecifier:
                pass

        if not first_patched_version:
            return True
        try:
            return installed < Version(first_patched_version)
        except InvalidVersion:
            return True

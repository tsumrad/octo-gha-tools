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
        await self._populate_direct_versions(owner, repo, items, resolvers, ref)
        for item in items:
            ecosystem = item.ecosystem.lower()
            if not item.istransitive or ecosystem not in {"npm", "npm_and_yarn", "pip", "pypi", "poetry"}:
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
                    classification = (
                        OccurrenceClassification.ROOT
                        if occurrence.get("is_root", False)
                        else OccurrenceClassification.TRANSITIVE
                    )
                    occurrence = {
                        **occurrence,
                        "introducers": introducers,
                        "manifest_path": lock_path,
                        "classification": classification,
                    }
                    # The same package@version can be installed at multiple
                    # nested node_modules locations in a single lockfile, each
                    # producing its own NpmResolver occurrence with only the
                    # introducers reachable from that specific location. Merge
                    # those into one occurrence per (package, version,
                    # manifest_path) so the union of all introducers is shown,
                    # instead of duplicating the "introduced via" section once
                    # per nested copy.
                    self._merge_occurrence(item, occurrence)
                    if occurrence.get("version") and not item.current_version:
                        item.current_version = occurrence["version"]

    async def _populate_direct_versions(self, owner, repo, items, resolvers, ref=None) -> None:
        """Resolve current_version for direct packages from the manifest/lockfile.

        Direct packages are never processed by the transitive walk above, so
        without this pass their current_version could only come from a
        Dependabot PR's from_version (populate_remediation_version), which is
        unreliable when a PR is stale or superseded. Reading the lockfile here
        gives the actual installed version, matching what's in package.json/
        requirements.txt/pyproject.toml at the analyzed ref.
        """
        for item in items:
            if item.istransitive or item.current_version:
                continue
            ecosystem = item.ecosystem.lower()
            if ecosystem not in {"npm", "npm_and_yarn", "pip", "pypi", "poetry"}:
                continue
            paths = {a.manifest_path for a in item.vulnerabilities if a.manifest_path}
            for path in sorted(paths):
                if item.current_version:
                    break
                is_python = ecosystem in {"pip", "pypi", "poetry"}
                is_poetry = is_python and PurePosixPath(path).name in {"poetry.lock", "pyproject.toml"}
                lock_path = path if is_python else str(PurePosixPath(path).parent / "package-lock.json")
                if is_poetry:
                    lock_path = str(PurePosixPath(path).parent / "poetry.lock")
                key = (owner.lower(), repo.lower(), ref, ecosystem, lock_path)
                if key not in resolvers:
                    try:
                        text = await self.fetcher.fetch(owner, repo, lock_path, ref)
                        if is_poetry:
                            project_path = str(PurePosixPath(path).parent / "pyproject.toml")
                            project_text = await self.fetcher.fetch(owner, repo, project_path, ref)
                            resolvers[key] = PoetryResolver(text, project_text)
                        elif is_python:
                            resolvers[key] = await asyncio.to_thread(PipResolver.from_text, text)
                        else:
                            resolvers[key] = NpmResolver(json.loads(text))
                    except (httpx.HTTPError, ValueError, subprocess.SubprocessError) as exc:
                        logger.warning("Cannot resolve direct version from %s: %s", lock_path, exc)
                        resolvers[key] = None
                resolver = resolvers[key]
                if resolver is None:
                    continue
                result = resolver.resolve(item.package)
                if is_python and not is_poetry:
                    if result.get("version"):
                        item.current_version = result["version"]
                    continue
                # npm/poetry: prefer the occurrence installed at the manifest
                # root (is_root) since that's the version package.json/
                # pyproject.toml actually declares for a direct dependency.
                occurrences = result.get("occurrences", [])
                root_occurrence = next(
                    (occ for occ in occurrences if occ.get("is_root") and occ.get("version")),
                    None,
                ) or next((occ for occ in occurrences if occ.get("version")), None)
                if root_occurrence:
                    item.current_version = root_occurrence["version"]

    @staticmethod
    def _merge_occurrence(item, occurrence: dict) -> None:
        merge_key = (occurrence.get("package"), occurrence.get("version"), occurrence.get("manifest_path"))
        for existing in item.transitive_dependency_occurrences:
            existing_key = (existing.get("package"), existing.get("version"), existing.get("manifest_path"))
            if existing_key != merge_key:
                continue
            seen = {(i.get("package"), i.get("version")) for i in existing.get("introducers", [])}
            for introducer in occurrence.get("introducers", []):
                key = (introducer.get("package"), introducer.get("version"))
                if key not in seen:
                    seen.add(key)
                    existing.setdefault("introducers", []).append(introducer)
            existing["introducers"] = sorted(
                existing["introducers"],
                key=lambda i: (i.get("package") or "", i.get("version") or ""),
            )
            return
        item.transitive_dependency_occurrences.append(occurrence)

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

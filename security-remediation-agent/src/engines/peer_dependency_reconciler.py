"""Verify and reconcile npm peerDependencies compatibility across a bundle.

Renovate's `packageRules` groups related packages (e.g. "ESLint and
TypeScript linting") and `allowedVersions` sets a per-package security floor,
but neither step proves the chosen versions are mutually installable: each
package in a group may declare `peerDependencies` ranges on the others, and
picking every package's own floor version independently can produce a set
that fails `npm install` (ERESOLVE).

This module re-verifies peer compatibility every time a bundle of
RemeditionPackage entries is reconciled (i.e. every time a `remediation_package`
grouping is finalized before being handed to PR creation), by:

1. Fetching each package's chosen version's `peerDependencies` from the npm
   registry.
2. Checking whether every other in-bundle package's resolved version
   satisfies those peer ranges.
3. Where a conflict exists, searching for the lowest release of the
   dependent package AT OR ABOVE its security floor (the remediation_version
   in effect when reconciliation started -- typically a CVE-fix minimum from
   Renovate's allowedVersions) that satisfies the peer's range. Versions are
   only ever RAISED to resolve a conflict, never lowered below that floor --
   downgrading would silently defeat the security remediation the bundle
   exists to deliver.
4. If no such release exists for either side, the conflict is left
   unresolved and recorded on the bundle, so the caller can surface it (e.g.
   fall back to a placeholder PR / manual fix) rather than either silently
   emitting an uninstallable bundle or silently undoing the fix.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from ..models.remediation_plan import PeerDependencyConflict, RemeditionPackage, RemeditionPackageBundle
from .version_resolver.npm_parent_version_resolver import NpmMetadataClient
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

try:
    from semantic_version import NpmSpec, Version as SemVersion
except ImportError:  # pragma: no cover - optional dependency, degrades gracefully
    NpmSpec = None
    SemVersion = None


def _parse_version(raw: str | None) -> Version | None:
    if not raw:
        return None
    try:
        return Version(raw.lstrip("vV"))
    except InvalidVersion:
        return None


def _satisfies(requirement: str, version: str) -> bool:
    """True if `version` satisfies the npm range `requirement`.

    When semantic_version isn't installed, conflicts can't be proven, so the
    candidate is optimistically kept rather than dropping a recommendation.
    """
    if NpmSpec is None or SemVersion is None:
        return True
    try:
        return NpmSpec(requirement).match(SemVersion.coerce(version))
    except ValueError:
        return True


@dataclass
class _PeerRequirement:
    dependent: str    # package declaring the peerDependencies entry
    depends_on: str   # the other bundle package it constrains
    range: str        # the semver range required of depends_on


class PeerDependencyReconciler:
    """Reconciles npm peerDependencies across the members of a remediation bundle."""

    def __init__(self, metadata: NpmMetadataClient | None = None):
        self._metadata = metadata

    async def reconcile(self, bundle: RemeditionPackageBundle) -> RemeditionPackageBundle:
        """Verify peer compatibility for an npm bundle and adjust versions in place.

        Non-npm bundles are returned unchanged. Mutates `bundle.packages` in
        place (only ever raising `remediation_version`, never lowering it
        below its value when reconciliation started) and populates
        `bundle.peer_dependency_conflicts` with anything that could not be
        reconciled without a downgrade.
        """
        if (bundle.ecosystem or "").lower() != "npm" or len(bundle.packages) < 2:
            return bundle

        if self._metadata is not None:
            return await self._reconcile(self._metadata, bundle)
        async with NpmMetadataClient() as metadata:
            return await self._reconcile(metadata, bundle)

    async def _reconcile(
        self, metadata: NpmMetadataClient, bundle: RemeditionPackageBundle
    ) -> RemeditionPackageBundle:
        by_name = {pkg.remediation_package.lower(): pkg for pkg in bundle.packages}
        # Security floor per package: the remediation_version already in
        # effect (from allowedVersions/CVE-fix data) before this reconciler
        # touches anything. Never search below this, even across iterations.
        floors = {name: pkg.remediation_version for name, pkg in by_name.items()}
        registry_data = await metadata.get_many(list(by_name.keys()))

        conflicts: list[PeerDependencyConflict] = []

        # Iterate until stable: raising one package's version can change what
        # it requires of others, so re-check after each adjustment instead of
        # assuming a single pass converges.
        for _ in range(len(bundle.packages) + 1):
            requirements = self._collect_requirements(by_name, registry_data)
            unresolved = self._find_unsatisfied(by_name, requirements)
            if not unresolved:
                conflicts = []
                break

            progressed = False
            for req in unresolved:
                dependent = by_name.get(req.dependent.lower())
                target = by_name.get(req.depends_on.lower())
                if dependent is None or target is None:
                    continue
                floor = floors[target.remediation_package.lower()]
                fixed = await self._find_version_satisfying_range(
                    metadata, target, floor, req.range
                )
                if fixed and fixed != target.remediation_version:
                    if not target.peer_adjusted:
                        target.original_remediation_version = target.remediation_version
                    target.remediation_version = fixed
                    target.peer_adjusted = True
                    registry_data[target.remediation_package.lower()] = await metadata.get(
                        target.remediation_package
                    )
                    progressed = True

            if not progressed:
                conflicts = [
                    PeerDependencyConflict(
                        package=req.depends_on,
                        peer_of=req.dependent,
                        required_range=req.range,
                        resolved_version=by_name[req.depends_on.lower()].remediation_version,
                    )
                    for req in unresolved
                    if req.depends_on.lower() in by_name
                ]
                break

        bundle.peer_dependency_conflicts = conflicts
        if conflicts:
            logger.warning(
                "Unresolved peer dependency conflicts in bundle %s (no fix found without "
                "downgrading below a security floor): %s",
                bundle.groupName,
                [(c.package, c.peer_of, c.required_range) for c in conflicts],
            )
        return bundle

    @staticmethod
    def _collect_requirements(
        by_name: dict[str, RemeditionPackage], registry_data: dict[str, dict]
    ) -> list[_PeerRequirement]:
        requirements: list[_PeerRequirement] = []
        for name, pkg in by_name.items():
            manifest = registry_data.get(name, {}).get("versions", {}).get(pkg.remediation_version, {})
            peer_deps = manifest.get("peerDependencies", {}) if manifest else {}
            for peer_name, peer_range in peer_deps.items():
                if peer_name.lower() in by_name:
                    requirements.append(
                        _PeerRequirement(dependent=pkg.remediation_package, depends_on=peer_name, range=peer_range)
                    )
        return requirements

    @staticmethod
    def _find_unsatisfied(
        by_name: dict[str, RemeditionPackage], requirements: list[_PeerRequirement]
    ) -> list[_PeerRequirement]:
        unsatisfied = []
        for req in requirements:
            target = by_name.get(req.depends_on.lower())
            if target is None or not target.remediation_version:
                continue
            if not _satisfies(req.range, target.remediation_version):
                unsatisfied.append(req)
        return unsatisfied

    @staticmethod
    async def _find_version_satisfying_range(
        metadata: NpmMetadataClient,
        target: RemeditionPackage,
        security_floor: str,
        required_range: str,
    ) -> str | None:
        """Lowest release of `target` AT OR ABOVE its security floor whose
        version itself satisfies `required_range` (a peerDependencies range
        declared by another bundle member against `target`).

        The floor is `target`'s remediation_version as it stood before
        reconciliation started (the CVE-fix/allowedVersions minimum) -- never
        `current_version`, and never lowered once raised. Only releases at or
        above that floor are considered, so a conflict can only ever be
        resolved by raising `target`'s version, never by silently reverting
        the security fix the bundle is meant to deliver. Returns None if no
        such release exists (an unresolved conflict, not a downgrade).
        """
        data = await metadata.get(target.remediation_package)
        floor = _parse_version(security_floor)
        candidates: list[Version] = []
        for raw, manifest in data.get("versions", {}).items():
            parsed = _parse_version(raw)
            if parsed is None or parsed.is_prerelease or manifest.get("deprecated"):
                continue
            if floor is not None and parsed < floor:
                continue
            if _satisfies(required_range, raw):
                candidates.append(parsed)
        if not candidates:
            return None
        # Prefer the lowest satisfying release above the floor (smallest
        # additional bump needed), not the newest -- minimizes the blast
        # radius of the extra change forced by the conflict.
        return str(min(candidates))

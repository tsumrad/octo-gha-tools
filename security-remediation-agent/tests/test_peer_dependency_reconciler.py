"""Tests for PeerDependencyReconciler: verifying/adjusting npm peerDependencies
compatibility across the members of a remediation bundle, without ever
lowering a package below its security-floor remediation_version.
"""
from __future__ import annotations

import pytest

from src.engines.peer_dependency_reconciler import PeerDependencyReconciler
from src.models.remediation_plan import RemeditionPackage, RemeditionPackageBundle


class FakeMetadataClient:
    """Stand-in for NpmMetadataClient backed by an in-memory registry fixture."""

    def __init__(self, registry: dict[str, dict]):
        self._registry = registry

    async def get(self, package: str) -> dict:
        return self._registry.get(package.lower(), {"versions": {}})

    async def get_many(self, packages: list[str]) -> dict[str, dict]:
        return {name.lower(): await self.get(name) for name in packages}


def make_bundle(packages: list[RemeditionPackage]) -> RemeditionPackageBundle:
    return RemeditionPackageBundle(groupName="ESLint and TypeScript linting", ecosystem="npm", severity="HIGH", packages=packages)


@pytest.mark.asyncio
async def test_non_npm_bundle_is_left_untouched():
    bundle = make_bundle(
        [RemeditionPackage(remediation_package="requests", ecosystem="pip", remediation_version="2.32.0")]
    )
    bundle.ecosystem = "pip"
    reconciler = PeerDependencyReconciler(metadata=FakeMetadataClient({}))

    result = await reconciler.reconcile(bundle)

    assert result.peer_dependency_conflicts == []
    assert result.packages[0].peer_adjusted is False


@pytest.mark.asyncio
async def test_compatible_versions_are_left_unchanged():
    registry = {
        "eslint-plugin-vue": {
            "versions": {
                "7.20.0": {"peerDependencies": {"eslint": "^6.2.0 || ^7.0.0"}},
            }
        },
        "eslint": {
            "versions": {
                "6.8.0": {},
                "7.32.0": {},
            }
        },
    }
    bundle = make_bundle(
        [
            RemeditionPackage(remediation_package="eslint-plugin-vue", ecosystem="npm", current_version="6.2.2", remediation_version="7.20.0"),
            RemeditionPackage(remediation_package="eslint", ecosystem="npm", current_version="6.8.0", remediation_version="6.8.0"),
        ]
    )
    reconciler = PeerDependencyReconciler(metadata=FakeMetadataClient(registry))

    result = await reconciler.reconcile(bundle)

    assert result.peer_dependency_conflicts == []
    eslint = next(p for p in result.packages if p.remediation_package == "eslint")
    assert eslint.remediation_version == "6.8.0"
    assert eslint.peer_adjusted is False


@pytest.mark.asyncio
async def test_conflict_is_resolved_by_raising_the_peer_never_by_downgrading_the_security_floor():
    # eslint-plugin-vue's security floor is 10.11.0 (the CVE-fix minimum from
    # renovate.json5 allowedVersions) and requires eslint ^8.57.0 || ^9.0.0.
    # The bundle's eslint floor (6.8.0) can't satisfy that -- the fix must be
    # to RAISE eslint to a version that satisfies the requirement, never to
    # lower eslint-plugin-vue back down to an older release.
    registry = {
        "eslint-plugin-vue": {
            "versions": {
                "10.11.0": {"peerDependencies": {"eslint": "^8.57.0 || ^9.0.0"}},
            }
        },
        "eslint": {
            "versions": {
                "6.8.0": {},
                "8.57.0": {},
                "9.9.0": {},
            }
        },
    }
    bundle = make_bundle(
        [
            RemeditionPackage(remediation_package="eslint-plugin-vue", ecosystem="npm", current_version="6.2.2", remediation_version="10.11.0"),
            RemeditionPackage(remediation_package="eslint", ecosystem="npm", current_version="6.8.0", remediation_version="6.8.0"),
        ]
    )
    reconciler = PeerDependencyReconciler(metadata=FakeMetadataClient(registry))

    result = await reconciler.reconcile(bundle)

    plugin = next(p for p in result.packages if p.remediation_package == "eslint-plugin-vue")
    eslint = next(p for p in result.packages if p.remediation_package == "eslint")
    # The security-mandated floor must never be lowered.
    assert plugin.remediation_version == "10.11.0"
    assert plugin.peer_adjusted is False
    # eslint is raised (not eslint-plugin-vue downgraded) to resolve the conflict.
    assert eslint.remediation_version == "8.57.0"
    assert eslint.peer_adjusted is True
    assert eslint.original_remediation_version == "6.8.0"
    assert result.peer_dependency_conflicts == []


@pytest.mark.asyncio
async def test_previously_raised_target_is_never_downgraded_by_a_later_check():
    # target-pkg's floor is 1.0.0. dependent-a requires target-pkg ^2.0.0,
    # forcing a raise to 2.0.0 first. dependent-b requires target-pkg
    # ^1.0.0 || ^2.0.0 -- satisfied by both 1.0.0 and 2.0.0 -- so its check
    # must not pick 1.0.0 and undo dependent-a's already-applied raise.
    registry = {
        "dependent-a": {"versions": {"1.0.0": {"peerDependencies": {"target-pkg": "^2.0.0"}}}},
        "dependent-b": {"versions": {"1.0.0": {"peerDependencies": {"target-pkg": "^1.0.0 || ^2.0.0"}}}},
        "target-pkg": {"versions": {"1.0.0": {}, "2.0.0": {}}},
    }
    bundle = make_bundle(
        [
            RemeditionPackage(remediation_package="dependent-a", ecosystem="npm", current_version="1.0.0", remediation_version="1.0.0"),
            RemeditionPackage(remediation_package="dependent-b", ecosystem="npm", current_version="1.0.0", remediation_version="1.0.0"),
            RemeditionPackage(remediation_package="target-pkg", ecosystem="npm", current_version="1.0.0", remediation_version="1.0.0"),
        ]
    )
    reconciler = PeerDependencyReconciler(metadata=FakeMetadataClient(registry))

    result = await reconciler.reconcile(bundle)

    target = next(p for p in result.packages if p.remediation_package == "target-pkg")
    assert target.remediation_version == "2.0.0"
    assert result.peer_dependency_conflicts == []



@pytest.mark.asyncio
async def test_unresolvable_conflict_is_recorded_not_silently_downgraded():
    # No release of dependent-pkg at or above its security floor (2.0.0) has
    # a peerDependencies range that target-pkg@2.0.0 (also a security floor)
    # can satisfy -- the conflict must be reported, and neither package's
    # floor may be lowered to make it "resolve".
    registry = {
        "dependent-pkg": {
            "versions": {
                "2.0.0": {"peerDependencies": {"target-pkg": "^1.0.0"}},
                "3.0.0": {"peerDependencies": {"target-pkg": "^1.0.0"}},
            }
        },
        "target-pkg": {
            "versions": {
                "2.0.0": {},
            }
        },
    }
    bundle = make_bundle(
        [
            RemeditionPackage(remediation_package="dependent-pkg", ecosystem="npm", current_version="2.0.0", remediation_version="2.0.0"),
            RemeditionPackage(remediation_package="target-pkg", ecosystem="npm", current_version="2.0.0", remediation_version="2.0.0"),
        ]
    )
    reconciler = PeerDependencyReconciler(metadata=FakeMetadataClient(registry))

    result = await reconciler.reconcile(bundle)

    dependent = next(p for p in result.packages if p.remediation_package == "dependent-pkg")
    target = next(p for p in result.packages if p.remediation_package == "target-pkg")
    assert dependent.remediation_version == "2.0.0"
    assert target.remediation_version == "2.0.0"
    assert len(result.peer_dependency_conflicts) == 1
    conflict = result.peer_dependency_conflicts[0]
    assert conflict.package == "target-pkg"
    assert conflict.peer_of == "dependent-pkg"
    assert conflict.required_range == "^1.0.0"

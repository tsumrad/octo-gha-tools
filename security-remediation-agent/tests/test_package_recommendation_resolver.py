from types import SimpleNamespace
from unittest.mock import AsyncMock

from src.engines.package_recommendation_resolver import PackageRecommendationResolver
from src.engines.recommendation_resolver.pip_parent_version_resolver import (
    PipParentVersionResolver,
)
from src.engines.version_resolver.npm_parent_version_resolver import (
    NpmMetadataClient,
    NpmParentVersionResolver,
)
from src.models.gh.pull_request_metadata import PullRequestMetadata
from src.models.security_package_triage import (
    SecurityPackageTriage,
    TransistiveOccurances,
    TransistiveSourcePackage,
)
from src.tools.utils.version_bump_resolver import VersionBump


def make_triage(fixed_version: str = "2.0.0") -> SecurityPackageTriage:
    return SecurityPackageTriage(
        package="example-package",
        vulnerablility_version_range="<2.0.0",
        vulnerablility_fixed_version=fixed_version,
    )


def make_pull_request(package: str, to_version: str) -> PullRequestMetadata:
    return PullRequestMetadata(
        pr_number=42,
        version_bumps=[
            VersionBump(
                package=package,
                from_version="1.0.0",
                to_version=to_version,
            )
        ],
    )


def test_returns_pr_when_version_equals_fixed_version():
    resolver = PackageRecommendationResolver()
    pull_request = make_pull_request("example-package", "2.0.0")

    assert resolver.filter_remediation_pull_requests(
        make_triage(),
        [pull_request],
    ) == [pull_request]


def test_returns_pr_when_version_is_newer_than_fixed_version():
    resolver = PackageRecommendationResolver()
    pull_request = make_pull_request("EXAMPLE-PACKAGE", "2.1.0")

    assert resolver.filter_remediation_pull_requests(
        make_triage(),
        [pull_request],
    ) == [pull_request]


def test_filters_older_and_unrelated_package_versions():
    resolver = PackageRecommendationResolver()

    assert resolver.filter_remediation_pull_requests(
        make_triage(),
        [
            make_pull_request("example-package", "1.9.9"),
            make_pull_request("another-package", "3.0.0"),
        ],
    ) == []


def test_skips_invalid_versions():
    resolver = PackageRecommendationResolver()

    assert resolver.filter_remediation_pull_requests(
        make_triage("not-a-version"),
        [make_pull_request("example-package", "2.0.0")],
    ) == []
    assert resolver.filter_remediation_pull_requests(
        make_triage(),
        [make_pull_request("example-package", "not-a-version")],
    ) == []


def test_returns_only_qualifying_pull_requests():
    resolver = PackageRecommendationResolver()
    older = make_pull_request("example-package", "1.9.9")
    fixed = make_pull_request("example-package", "2.0.0")
    newer = make_pull_request("example-package", "3.0.0")

    assert resolver.filter_remediation_pull_requests(
        make_triage(),
        [older, fixed, newer],
    ) == [fixed, newer]


async def test_uses_factory_version_resolver_for_transitive_remediation():
    version_resolver = PipParentVersionResolver()
    version_resolver.resolve = AsyncMock(
        return_value=SimpleNamespace(
            resolved=True,
            resolved_version="2.1.0",
            minimum_upgradable_version="2.1.0",
        )
    )
    factory = SimpleNamespace(load=AsyncMock(return_value=version_resolver))
    resolver = PackageRecommendationResolver(resolver_factory=factory)
    triage = make_triage()
    triage.ecosystem = "pip"
    triage.manifest_path = "requirements.txt"
    triage.istransitive = True
    triage.transitive_dependency_occurrences = [
        TransistiveOccurances(
            package=triage.package,
            version="1.0.0",
            introducers=[
                TransistiveSourcePackage(package="parent-package", version="2.0.0")
            ],
        )
    ]

    await resolver.populate_remediation_version(
        triage,
        owner="octo",
        repo="example",
    )

    factory.load.assert_awaited_once()
    version_resolver.resolve.assert_awaited_once_with(
        "parent-package",
        "example-package",
        "2.0.0",
        current_parent_version="2.0.0",
    )
    assert len(triage.package_upgrade_recommendations) == 1
    recommendation = triage.package_upgrade_recommendations[0]
    assert recommendation.package == "parent-package"
    assert recommendation.from_version == "2.0.0"
    assert recommendation.to_version == "2.1.0"
    assert recommendation.minimum_upgradable_version == "2.1.0"
    assert recommendation.source == "pypi_verified"


async def test_skips_transitive_resolution_without_fixed_version():
    factory = SimpleNamespace(load=AsyncMock())
    resolver = PackageRecommendationResolver(resolver_factory=factory)
    triage = make_triage("")
    triage.ecosystem = "pip"
    triage.manifest_path = "requirements.txt"
    triage.istransitive = True

    await resolver.populate_remediation_version(
        triage,
        owner="octo",
        repo="example",
    )

    factory.load.assert_not_awaited()
    assert triage.package_upgrade_recommendations == []
    assert not triage.is_pull_available


async def test_npm_fallback_preserves_minimum_progressive_upgrade():
    metadata = SimpleNamespace(
        select_candidates=AsyncMock(
            return_value=(["5.2.0", "5.9.0", "6.0.0", "14.9.0"], False, False)
        )
    )
    resolver = NpmParentVersionResolver(
        package_text="{}",
        lock_text="{}",
        metadata=metadata,
    )

    resolution = await resolver.resolve(
        "@vue/eslint-config-typescript",
        "vulnerable-child",
        "<2.0.0",
        current_parent_version="5.1.0",
        fixed_version="2.0.0",
    )

    assert resolution.resolved_version == "14.9.0"
    assert resolution.minimum_upgradable_version == "5.9.0"
    assert resolution.requires_verification


async def test_npm_candidates_exclude_unsupported_node_engines():
    metadata = NpmMetadataClient()
    metadata.get = AsyncMock(
        return_value={
            "versions": {
                "1.0.0": {},
                "2.0.0": {"engines": {"node": ">=22"}},
                "3.0.0": {"engines": {"node": ">=20"}},
                "4.0.0": {},
            }
        }
    )

    candidates, direct_inference, lockfile_refresh = await metadata.select_candidates(
        "parent",
        "deep-child",
        "<2.0.0",
        current_parent_version="1.0.0",
        fixed_version="2.0.0",
        node_version="20.10.0",
    )

    assert candidates == ["3.0.0", "4.0.0"]
    assert not direct_inference
    assert not lockfile_refresh

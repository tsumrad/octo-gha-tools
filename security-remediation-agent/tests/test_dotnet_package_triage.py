from unittest.mock import patch

import pytest

from src.engines.package_relationship_resolver import PackageRelationshipResolver
from src.engines.recommendation_resolver.dotnet_recommendation_resolver import (
    DotNetRecommendationResolver,
)
from src.models.security_package_triage import SecurityPackageTriage


@pytest.mark.asyncio
async def test_nuget_project_path_is_not_guessed_when_manifest_is_ambiguous():
    class Provider:
        async def repository_tree(self, owner, repo, ref):
            assert (owner, repo, ref) == ("owner", "repo", "commit")
            return [
                {"path": "src/App.csproj"},
                {"path": "src/Other.csproj"},
                {"path": "src/packages.lock.json"},
            ]

    resolver = DotNetRecommendationResolver(manifest_provider=Provider())
    assert await resolver.resolve_project_path(
        "owner",
        "repo",
        "src/packages.lock.json",
        ref="commit",
    ) is None


@pytest.mark.asyncio
async def test_nuget_project_path_resolves_matching_project_from_repository_tree():
    class Provider:
        async def repository_tree(self, owner, repo, ref):
            return [
                {"path": "src/App.csproj"},
                {"path": "src/Other.csproj"},
            ]

    resolver = DotNetRecommendationResolver(manifest_provider=Provider())
    assert await resolver.resolve_project_path(
        "owner",
        "repo",
        "src/App.csproj",
    ) == "src/App.csproj"


@pytest.mark.asyncio
async def test_nuget_lockfile_resolves_unique_project_from_repository_tree():
    class Provider:
        async def repository_tree(self, owner, repo, ref):
            return [{"path": "src/App.csproj"}, {"path": "src/packages.lock.json"}]

    resolver = DotNetRecommendationResolver(manifest_provider=Provider())
    assert await resolver.resolve_project_path(
        "owner",
        "repo",
        "src/packages.lock.json",
    ) == "src/App.csproj"


@pytest.mark.asyncio
async def test_nuget_triage_populates_current_version_from_dotnet_list():
    triage = SecurityPackageTriage(
        package="System.Linq.Dynamic.Core",
        vulnerablility_version_range="<1.6.0",
        vulnerablility_fixed_version="1.6.0",
        ecosystem="nuget",
        manifest_path="DotnetSecurityFailures/DotnetSecurityFailures.csproj",
    )
    class Provider:
        async def repository_tree(self, owner, repo, ref):
            return [{"path": triage.manifest_path}]

    resolver = DotNetRecommendationResolver(manifest_provider=Provider())
    with (
        patch(
            "src.engines.package_relationship_resolver.DotNetRecommendationResolver",
            return_value=resolver,
        ),
        patch.object(
            resolver,
            "highest_minor_versions",
            return_value={
                "system.linq.dynamic.core:requested": "1.5.0",
                "system.linq.dynamic.core:minimum": "1.9.0",
            },
        ) as run,
    ):
        package_resolver = PackageRelationshipResolver(
            manifest_provider=Provider()
        )
        await package_resolver.populate("owner", "repo", [triage])

    assert triage.current_version == "1.5.0"
    run.assert_called_once()
    assert run.call_args.args == (
        "DotnetSecurityFailures/DotnetSecurityFailures.csproj",
    )

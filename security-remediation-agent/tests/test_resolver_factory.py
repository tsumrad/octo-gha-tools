import pytest

from src.engines.recommendation_resolver.pip_parent_version_resolver import (
    PipParentVersionResolver,
)
from src.engines.relationship_resolver.npm_resolver import NpmResolver
from src.engines.relationship_resolver.pip_resolver import PipResolver
from src.engines.relationship_resolver.poetry_resolver import PoetryResolver
from src.engines.resolver_factory import (
    RecommendationResolverFactory,
    RelationshipResolverFactory,
)
from src.engines.version_resolver.npm_parent_version_resolver import (
    NpmParentVersionResolver,
)


@pytest.mark.asyncio
async def test_relationship_factory_creates_npm_resolver():
    resolver = await RelationshipResolverFactory().create(
        "npm",
        '{"name": "example", "lockfileVersion": 3, "packages": {"": {}}}',
    )

    assert isinstance(resolver, NpmResolver)


@pytest.mark.asyncio
async def test_relationship_factory_creates_pip_resolver():
    resolver = await RelationshipResolverFactory().create(
        "pypi",
        "",
    )

    assert isinstance(resolver, PipResolver)


@pytest.mark.asyncio
async def test_relationship_factory_creates_poetry_resolver():
    resolver = await RelationshipResolverFactory().create(
        "poetry",
        '[[package]]\nname = "example-package"\nversion = "1.0.0"\n',
        project_text='[tool.poetry.dependencies]\nexample-package = "1.0.0"\n',
    )

    assert isinstance(resolver, PoetryResolver)


@pytest.mark.asyncio
async def test_relationship_factory_rejects_unsupported_ecosystem():
    with pytest.raises(ValueError, match="Unsupported relationship"):
        await RelationshipResolverFactory().create("maven", "")


def test_recommendation_factory_creates_npm_resolver():
    resolver = RecommendationResolverFactory().create(
        "npm",
        package_text='{"dependencies": {"example-package": "1.0.0"}}',
        lock_text='{"lockfileVersion": 3, "packages": {}}',
    )

    assert isinstance(resolver, NpmParentVersionResolver)


def test_recommendation_factory_creates_python_resolver():
    assert isinstance(
        RecommendationResolverFactory().create("pip"),
        PipParentVersionResolver,
    )


def test_recommendation_factory_requires_npm_manifests():
    with pytest.raises(ValueError, match="package_text and lock_text"):
        RecommendationResolverFactory().create("npm")

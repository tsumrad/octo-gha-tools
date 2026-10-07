from unittest.mock import AsyncMock

from src.models.security_remediation_context import SecurityRemediationCache
from src.utils.manifest_provider import ManifestProvider


async def test_lockfile_is_fetched_once_across_providers_with_shared_cache():
    cache = SecurityRemediationCache()
    relationship_provider = ManifestProvider(cache=cache)
    recommendation_provider = ManifestProvider(cache=cache)
    relationship_provider._fetch = AsyncMock(return_value='{"lockfileVersion": 3}')
    recommendation_provider._fetch = AsyncMock(
        side_effect=AssertionError("lockfile should come from the shared cache")
    )

    first = await relationship_provider.get(
        "octo",
        "example",
        "package-lock.json",
        "main",
    )
    second = await recommendation_provider.get(
        "OCTO",
        "EXAMPLE",
        "package-lock.json",
        "main",
    )

    assert second == first
    relationship_provider._fetch.assert_awaited_once()
    recommendation_provider._fetch.assert_not_awaited()

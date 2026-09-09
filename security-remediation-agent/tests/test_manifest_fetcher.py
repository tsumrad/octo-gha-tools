import httpx
import pytest

from src.tools.github_manifest_fetcher import ManifestFetcher


@pytest.mark.asyncio
async def test_cache_is_scoped_by_repository_path_and_ref():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=b'{"dependencies": {}}', headers={"content-type": "text/plain"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fetcher = ManifestFetcher("test-token", client=client)
        assert await fetcher.fetch("owner", "repo", "web/package.json", "main") == '{"dependencies": {}}'
        await fetcher.fetch("OWNER", "REPO", "/web/package.json", "main")
        assert len(requests) == 1
        await fetcher.fetch("owner", "repo", "web/package.json", "feature/test")
        await fetcher.fetch("owner", "other", "web/package.json", "main")
        await fetcher.fetch("owner", "repo", "package.json", "main")
        await fetcher.fetch("owner", "repo", "web/package.json", "main", refresh=True)
        assert len(requests) == 5
        fetcher.clear_cache()
        await fetcher.fetch("owner", "repo", "web/package.json", "main")
        assert len(requests) == 6
        assert requests[1].url.params["ref"] == "feature/test"
        assert requests[0].headers["accept"] == "application/vnd.github.raw+json"


@pytest.mark.asyncio
async def test_failed_request_is_not_cached():
    responses = [httpx.Response(404), httpx.Response(200, text="requests==2.32.0")]
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: responses.pop(0))) as client:
        fetcher = ManifestFetcher("test-token", client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await fetcher.fetch("owner", "repo", "requirements.txt")
        assert await fetcher.fetch("owner", "repo", "requirements.txt") == "requests==2.32.0"

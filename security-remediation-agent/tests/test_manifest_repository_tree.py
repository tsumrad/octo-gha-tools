import httpx
import pytest

from src.utils.manifest_provider import ManifestProvider


@pytest.mark.asyncio
async def test_repository_tree_uses_repository_default_branch():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/repos/owner/repo":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.path == "/repos/owner/repo/git/trees/main":
            return httpx.Response(
                200,
                json={
                    "truncated": False,
                    "tree": [
                        {"path": "src/App.csproj", "type": "blob"},
                        {"path": "src", "type": "tree"},
                    ],
                },
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = ManifestProvider(token="token", client=client)
        entries = await provider.repository_tree("owner", "repo")

    assert entries == [{"path": "src/App.csproj"}]
    assert [request.url.path for request in requests] == [
        "/repos/owner/repo",
        "/repos/owner/repo/git/trees/main",
    ]
    assert requests[1].url.params["recursive"] == "1"


@pytest.mark.asyncio
async def test_repository_tree_uses_supplied_ref_without_metadata_request():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"truncated": False, "tree": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = ManifestProvider(token="token", client=client)
        entries = await provider.repository_tree("owner", "repo", "commit-sha")

    assert entries == []
    assert [request.url.path for request in requests] == [
        "/repos/owner/repo/git/trees/commit-sha"
    ]

"""Fetch manifest text through the Contents API; cache for this component's lifetime."""

import os
from urllib.parse import quote

import httpx


class ManifestFetcher:
    """Reuse one instance per run. Use a commit SHA for a stable repository snapshot."""

    def __init__(self, token: str | None = None, *, client: httpx.AsyncClient | None = None):
        self._token = token or os.getenv("GITHUB_TOKEN")
        self._client = client
        self._cache: dict[tuple[str, str, str, str | None], str] = {}

    async def fetch(
        self, owner: str, repo: str, path: str, ref: str | None = None, *, refresh: bool = False
    ) -> str:
        """Return UTF-8 manifest text. Failed requests are never cached.

        Omitting ref uses the default branch. refresh=True reloads a cached file.
        Nothing is written to disk; callers can parse the returned JSON/TOML/text.
        """
        path = path.lstrip("/")
        if not owner or not repo or not path or any(p in {".", "..", ""} for p in path.split("/")):
            raise ValueError("Expected owner, repository, and a repository-relative file path")
        key = (owner.lower(), repo.lower(), path, ref)
        if not refresh and key in self._cache:
            return self._cache[key]
        if not self._token:
            raise RuntimeError("GITHUB_TOKEN environment variable or token argument is required")
        url = (f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
               f"/contents/{quote(path, safe='/')}")
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {"ref": ref} if ref is not None else None
        if self._client is not None:
            response = await self._client.get(url, headers=headers, params=params)
        else:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers, params=params)
        response.raise_for_status()
        # Directories are returned as API JSON even when raw media is requested.
        if response.headers.get("content-type", "").startswith("application/json"):
            raise ValueError(f"Contents API did not return a raw file for {path}")
        content = response.content.decode("utf-8-sig")
        self._cache[key] = content
        return content

    def clear_cache(self) -> None:
        """Discard all cached manifests, for example before starting another run."""
        self._cache.clear()

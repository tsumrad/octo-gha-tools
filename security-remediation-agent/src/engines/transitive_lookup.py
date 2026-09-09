"""Resolve installed npm introducers from cached repository lockfiles."""
import json
import asyncio
import subprocess
import logging
from pathlib import PurePosixPath

import httpx

from src.engines.relationship_resolver.npm_resolver import NpmResolver
from src.engines.relationship_resolver.pip_resolver import PipResolver
from src.engines.relationship_resolver.poetry_resolver import PoetryResolver
from src.tools.github_manifest_fetcher import ManifestFetcher

logger = logging.getLogger(__name__)


class TransitiveLookup:
    def __init__(self, fetcher=None):
        self.fetcher = fetcher or ManifestFetcher()

    async def populate(self, owner, repo, items, ref=None):
        resolvers = {}
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
                key = (is_python, lock_path)
                if key not in resolvers:
                    try:
                        text = await self.fetcher.fetch(owner, repo, lock_path, ref)
                        if is_poetry:
                            project_path = str(PurePosixPath(path).parent / "pyproject.toml")
                            project_text = await self.fetcher.fetch(owner, repo, project_path, ref)
                            resolvers[key] = PoetryResolver(text, project_text)
                        else:
                            resolvers[key] = (await asyncio.to_thread(PipResolver.from_text, text)
                                          if is_python else NpmResolver(json.loads(text)))
                    except (httpx.HTTPError, ValueError, subprocess.SubprocessError) as exc:
                        logger.warning("Cannot resolve transitive parents from %s: %s", lock_path, exc)
                        resolvers[key] = None
                resolver = resolvers[key]
                if resolver is None:
                    continue
                result = resolver.resolve(item.package)
                occurrences = ([result] if result.get("version") else []) if is_python and not is_poetry else result["occurrences"]
                for occurrence in occurrences:
                    occurrence = {**occurrence, "manifest_path": lock_path}
                    if occurrence not in item.dependency_occurrences:
                        item.dependency_occurrences.append(occurrence)
                    for parent in occurrence["introducers"]:
                        source = f"{parent['package']}@{parent['version']}"
                        if source not in item.transitive_source_package:
                            item.transitive_source_package.append(source)

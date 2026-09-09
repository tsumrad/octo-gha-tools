import unittest
from types import SimpleNamespace

from src.engines.relationship_resolver.poetry_resolver import PoetryResolver
from src.engines.transitive_lookup import TransitiveLookup

LOCK = '''
[[package]]
name = "fastapi"
version = "0.125.0"
[package.dependencies]
starlette = ">=0.40,<0.51"
[[package]]
name = "starlette"
version = "0.50.0"
[package.dependencies]
anyio = ">=4"
[[package]]
name = "anyio"
version = "4.15.0"
'''
PROJECT = '''
[tool.poetry.dependencies]
python = "^3.12"
fastapi = "0.125.0"
'''


class PoetryParentLookupTest(unittest.IsolatedAsyncioTestCase):
    def test_direct_and_multihop_parents(self):
        resolver = PoetryResolver(LOCK, PROJECT)
        for target, version in [("Starlette", "0.50.0"), ("anyio", "4.15.0")]:
            occurrence = resolver.resolve(target)["occurrences"][0]
            self.assertEqual(occurrence["version"], version)
            self.assertEqual(occurrence["introducers"], [{"package": "fastapi", "version": "0.125.0"}])
        self.assertEqual(resolver.resolve("absent")["occurrences"], [])

    def test_declaration_formats(self):
        for project in ['[project]\ndependencies=["fastapi==0.125.0"]',
                        '[tool.poetry.group.web.dependencies]\nfastapi="*"',
                        '[tool.poetry.dev-dependencies]\nfastapi="*"',
                        '[project.optional-dependencies]\nweb=["fastapi"]',
                        '[dependency-groups]\nweb=["fastapi"]']:
            self.assertEqual(len(PoetryResolver(LOCK, project).resolve("starlette")["occurrences"][0]["introducers"]), 1)

    async def test_nested_manifests_reuse_resolver(self):
        calls = []

        async def fetch(owner, repo, path, ref):
            calls.append((path, ref))
            return {"api/poetry.lock": LOCK, "api/pyproject.toml": PROJECT}[path]

        items = [SimpleNamespace(package="starlette", ecosystem="pip", istransitive=True,
            vulnerabilities=[SimpleNamespace(manifest_path=path)],
            dependency_occurrences=[], transitive_source_package=[])
            for path in ["api/poetry.lock", "api/pyproject.toml"]]
        await TransitiveLookup(SimpleNamespace(fetch=fetch)).populate("owner", "repo", items, "main")
        self.assertEqual(calls, [("api/poetry.lock", "main"), ("api/pyproject.toml", "main")])
        self.assertEqual(items[1].transitive_source_package, ["fastapi@0.125.0"])

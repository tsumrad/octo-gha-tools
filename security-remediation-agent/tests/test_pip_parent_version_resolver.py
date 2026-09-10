import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from src.engines.version_resolver.pip_parent_version_resolver import (
    ParentVersionShortlister,
    PipParentVersionResolver,
    PyPiMetadataClient,
    VenvInstallVerifier,
)


def _metadata_response(releases: dict) -> dict:
    return {"info": {"version": None}, "releases": releases}


class ParentVersionShortlisterTest(unittest.IsolatedAsyncioTestCase):
    async def test_shortlists_versions_satisfying_safe_child_version(self):
        pypi = MagicMock(spec=PyPiMetadataClient)
        pypi.list_versions_descending = AsyncMock(return_value=["3.0.0", "2.5.0", "2.0.0", "1.0.0"])

        async def requires_dist(name, version):
            return {
                "3.0.0": ["starlette>=0.40,<0.51"],
                "2.5.0": ["starlette>=0.30,<0.40"],
                "2.0.0": ["starlette>=0.20,<0.30"],
            }.get(version, [])

        pypi.get_release_requires_dist = AsyncMock(side_effect=requires_dist)

        shortlister = ParentVersionShortlister(pypi, max_candidates=5)
        candidates = await shortlister.shortlist(
            "fastapi", "starlette", "0.40.0", current_parent_version="1.0.0"
        )

        self.assertEqual([c.version for c in candidates], ["3.0.0"])

    async def test_stops_at_max_candidates(self):
        pypi = MagicMock(spec=PyPiMetadataClient)
        pypi.list_versions_descending = AsyncMock(return_value=["5.0.0", "4.0.0", "3.0.0", "2.0.0"])
        pypi.get_release_requires_dist = AsyncMock(return_value=[])  # unconstrained -> always shortlisted

        shortlister = ParentVersionShortlister(pypi, max_candidates=2)
        candidates = await shortlister.shortlist("fastapi", "starlette", "0.40.0")

        self.assertEqual([c.version for c in candidates], ["5.0.0", "4.0.0"])


class VenvInstallVerifierTest(unittest.TestCase):
    @patch("src.engines.version_resolver.pip_parent_version_resolver.subprocess.run")
    @patch("src.engines.version_resolver.pip_parent_version_resolver.venv.EnvBuilder")
    def test_verify_confirms_safe_child_version(self, env_builder_cls, run):
        env_builder_cls.return_value.create.return_value = None
        install_result = MagicMock(returncode=0)
        inspect_result = MagicMock(
            returncode=0,
            stdout=json.dumps({"installed": [
                {"metadata": {"name": "starlette", "version": "0.50.0"}},
            ]}),
        )
        run.side_effect = [install_result, inspect_result]

        verifier = VenvInstallVerifier()
        result = verifier.verify("fastapi", "0.125.0", "starlette", "0.40.0")

        self.assertEqual(result, "0.50.0")

    @patch("src.engines.version_resolver.pip_parent_version_resolver.subprocess.run")
    @patch("src.engines.version_resolver.pip_parent_version_resolver.venv.EnvBuilder")
    def test_verify_rejects_still_vulnerable_child_version(self, env_builder_cls, run):
        env_builder_cls.return_value.create.return_value = None
        install_result = MagicMock(returncode=0)
        inspect_result = MagicMock(
            returncode=0,
            stdout=json.dumps({"installed": [
                {"metadata": {"name": "starlette", "version": "0.30.0"}},
            ]}),
        )
        run.side_effect = [install_result, inspect_result]

        verifier = VenvInstallVerifier()
        result = verifier.verify("fastapi", "1.0.0", "starlette", "0.40.0")

        self.assertIsNone(result)

    @patch("src.engines.version_resolver.pip_parent_version_resolver.subprocess.run")
    @patch("src.engines.version_resolver.pip_parent_version_resolver.venv.EnvBuilder")
    def test_verify_returns_none_on_install_failure(self, env_builder_cls, run):
        env_builder_cls.return_value.create.return_value = None
        run.return_value = MagicMock(returncode=1, stderr="no matching distribution")

        verifier = VenvInstallVerifier()
        result = verifier.verify("fastapi", "999.0.0", "starlette", "0.40.0")

        self.assertIsNone(result)


class PipParentVersionResolverTest(unittest.IsolatedAsyncioTestCase):
    async def test_resolve_returns_first_verified_candidate(self):
        shortlister = MagicMock(spec=ParentVersionShortlister)
        shortlister.shortlist = AsyncMock(return_value=[
            MagicMock(version="3.0.0"),
            MagicMock(version="2.5.0"),
        ])
        verifier = MagicMock(spec=VenvInstallVerifier)
        verifier.verify.side_effect = [None, "0.50.0"]

        resolver = PipParentVersionResolver(shortlister=shortlister, verifier=verifier)
        result = await resolver.resolve("fastapi", "starlette", "0.40.0", current_parent_version="1.0.0")

        self.assertEqual(result.resolved_version, "2.5.0")
        self.assertEqual(result.installed_child_version, "0.50.0")
        self.assertEqual(result.candidates_considered, ["3.0.0", "2.5.0"])
        self.assertTrue(result.resolved)

    async def test_resolve_returns_unresolved_when_no_candidate_verifies(self):
        shortlister = MagicMock(spec=ParentVersionShortlister)
        shortlister.shortlist = AsyncMock(return_value=[MagicMock(version="3.0.0")])
        verifier = MagicMock(spec=VenvInstallVerifier)
        verifier.verify.return_value = None

        resolver = PipParentVersionResolver(shortlister=shortlister, verifier=verifier)
        result = await resolver.resolve("fastapi", "starlette", "0.40.0")

        self.assertFalse(result.resolved)
        self.assertIsNone(result.resolved_version)


class PyPiMetadataClientTest(unittest.IsolatedAsyncioTestCase):
    async def test_list_versions_descending_skips_yanked_and_empty_releases(self):
        transport = httpx.MockTransport(lambda request: httpx.Response(
            200,
            json=_metadata_response({
                "1.0.0": [{"yanked": False}],
                "2.0.0": [{"yanked": True}],
                "3.0.0": [],
                "1.5.0": [{"yanked": False}],
            }),
        ))
        async with httpx.AsyncClient(transport=transport) as http_client:
            async with PyPiMetadataClient(http_client) as pypi:
                versions = await pypi.list_versions_descending("fastapi")

        self.assertEqual(versions, ["1.5.0", "1.0.0"])


if __name__ == "__main__":
    unittest.main()

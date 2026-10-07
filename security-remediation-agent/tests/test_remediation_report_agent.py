import json

import pytest

from src.agents.remediation_report_agent import RemediationReportAgent
from src.models.remediation_plan import (
    RemediationPlan,
    RemeditionPackage,
    RemeditionPackageBundle,
)


class ManifestProviderStub:
    def __init__(self, content):
        self.content = content
        self.requests = []

    async def get(self, owner, repo, path, ref):
        self.requests.append((owner, repo, path, ref))
        return self.content if path == "renovate.json5" else None


@pytest.mark.asyncio
async def test_report_appends_rules_using_lower_remediation_version(tmp_path):
    provider = ManifestProviderStub(
        """
        {
          // Existing Renovate settings remain in the generated config.
          "extends": ["config:recommended"],
          "packageRules": [
            {
              "matchPackageNames": ["existing-package"],
              "allowedVersions": "<3",
            },
          ],
        }
        """
    )
    plan = RemediationPlan(
        remediation_plan_bundles=[
            RemeditionPackageBundle(
                ecosystem="npm",
                groupName="default",
                severity="HIGH",
                packages=[
                    RemeditionPackage(
                        ecosystem="npm",
                        remediation_package="eslint-plugin-vue",
                        remediation_version="9.33.0",
                        upgrade_to_version="9.40.1",
                    ),
                    RemeditionPackage(
                        ecosystem="npm",
                        remediation_package="typescript",
                        remediation_version="v5.8.2",
                        upgrade_to_version="5.7.3",
                    ),
                ],
            )
        ]
    )
    output = tmp_path / "renovate.json5"

    result = await RemediationReportAgent(provider, output).report(
        plan,
        {"owner": "owner", "name": "repo"},
        ref="commit",
    )

    assert result == output
    config = json.loads(output.read_text(encoding="utf-8"))
    assert config["extends"] == ["config:recommended"]
    assert config["packageRules"] == [
        {
            "matchPackageNames": ["existing-package"],
            "allowedVersions": "<3",
        },
        {
            "matchPackageNames": ["eslint-plugin-vue"],
            "allowedVersions": ">=9.33.0 <10",
        },
        {
            "matchPackageNames": ["typescript"],
            "allowedVersions": ">=5.7.3 <6",
        },
    ]
    assert provider.requests == [("owner", "repo", "renovate.json5", "commit")]


@pytest.mark.asyncio
async def test_report_creates_config_and_deduplicates_packages(tmp_path):
    provider = ManifestProviderStub(None)
    plan = RemediationPlan(
        remediation_plan_bundles=[
            RemeditionPackageBundle(
                ecosystem="nuget",
                groupName="default",
                severity="MEDIUM",
                packages=[
                    RemeditionPackage(
                        ecosystem="nuget",
                        remediation_package="Example.Package",
                        remediation_version="2.4.0",
                        upgrade_to_version="",
                    ),
                    RemeditionPackage(
                        ecosystem="nuget",
                        remediation_package="example.package",
                        remediation_version="2.5.0",
                        upgrade_to_version="2.6.0",
                    ),
                ],
            )
        ]
    )
    output = tmp_path / "renovate.json5"

    await RemediationReportAgent(provider, output).report(
        plan,
        {"owner": "owner", "name": "repo"},
    )

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "packageRules": [
            {
                "matchPackageNames": ["Example.Package"],
                "allowedVersions": ">=2.4.0 <3",
            }
        ]
    }

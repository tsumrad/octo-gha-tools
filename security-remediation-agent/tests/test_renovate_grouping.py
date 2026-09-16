from src.models.remediation_plan import RemeditionPackage
from src.engines.remediation_grouping_engine import RenovateGroupingService


def test_renovate_grouping_matches_package_rules_and_groups_packages():
    config = {
        "packageRules": [
            {
                "matchPackageNames": ["lodash", "axios"],
                "groupName": "web-core",
            },
        ]
    }

    packages = [
        RemeditionPackage(remediation_package="lodash", ecosystem="npm"),
        RemeditionPackage(remediation_package="axios", ecosystem="npm"),
        RemeditionPackage(remediation_package="@types/node", ecosystem="npm"),
    ]

    bundles = RenovateGroupingService.group_packages_by_package_rules(packages, config)

    assert {bundle.groupName for bundle in bundles} == {"web-core", "default"}

    web_core_bundle = next(bundle for bundle in bundles if bundle.groupName == "web-core")
    assert {pkg.remediation_package for pkg in web_core_bundle.packages} == {"lodash", "axios"}

    default_bundle = next(bundle for bundle in bundles if bundle.groupName == "default")
    assert {pkg.remediation_package for pkg in default_bundle.packages} == {"@types/node"}

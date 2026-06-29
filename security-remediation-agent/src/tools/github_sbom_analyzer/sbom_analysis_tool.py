from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator
from spdx_tools.spdx.model import Package, RelationshipType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

GITHUB_API   = "https://api.github.com"
ROOT_SPDX_ID = "SPDXRef-DOCUMENT"


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class PackageInfo:
    name: str
    version: str
    spdx_id: str
    purl: Optional[str]
    ecosystem: str                # "pypi" | "npm" | "maven" | "githubactions" | …
    dependency_type: str          # "direct" | "transitive" | "unknown"
    source_packages: List[str]    # names of packages that depend on this one


class SBOMAnalysisInput(BaseModel):
    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")
    package: Optional[str] = Field(
        default=None,
        description="Optional package name to look up in the repository SBOM.",
    )
    ecosystem: Optional[str] = Field(
        default=None,
        description="Optional package ecosystem filter, for example pypi, npm, or maven.",
    )
    list_ecosystems: bool = Field(
        default=False,
        description="Return ecosystem counts instead of package details.",
    )

    @field_validator("owner", "repo")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value must not be empty.")
        return value


def _ecosystem_from_purl(purl: Optional[str]) -> str:
    """Extract ecosystem from a purl, e.g. 'pkg:pypi/six@1.17.0' → 'pypi'."""
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/")[0].split("@")[0]
    return "unknown"


# ── GitHub fetch ──────────────────────────────────────────────────────────────

def fetch_github_sbom(repo: str) -> Document:
    owner, name = _parse_repo(repo)
    url = f"{GITHUB_API}/repos/{owner}/{name}/dependency-graph/sbom"
    print(f"[*] Fetching SBOM: {url}")

    resp = requests.get(url, headers=_gh_headers(), timeout=30)
    _check_response(resp)

    sbom_json = resp.json().get("sbom")
    if not sbom_json:
        raise ValueError("GitHub response missing 'sbom' key.")

    with tempfile.NamedTemporaryFile(suffix=".spdx.json", mode="w",
                                     delete=False, encoding="utf-8") as tmp:
        json.dump(sbom_json, tmp)
        tmp_path = tmp.name
    try:
        doc = parse_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    print(f"[✓] {len(doc.packages)} packages in '{doc.creation_info.name}'")
    return doc


def load_local_sbom(path: Path) -> Document:
    print(f"[*] Loading local SBOM: {path}")
    doc = parse_file(str(path))
    print(f"[✓] {len(doc.packages)} packages in '{doc.creation_info.name}'")
    return doc


def _parse_repo(repo: str):
    parts = repo.strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError(f"Expected 'owner/repo', got: '{repo}'")
    return parts


def _gh_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _check_response(resp: requests.Response) -> None:
    if resp.status_code == 401:
        raise RuntimeError("401 Unauthorized – set GITHUB_TOKEN env var.")
    if resp.status_code == 403:
        raise RuntimeError(f"403 Forbidden – {resp.json().get('message', '')}")
    if resp.status_code == 404:
        raise RuntimeError(
            "404 Not Found – check the repo name, or enable the Dependency Graph "
            "under Settings → Security → Code security.")
    resp.raise_for_status()


# ── Graph builder ─────────────────────────────────────────────────────────────

class SBOMGraph:
    """
    Builds a dependency graph from an spdx-tools Document and provides
    fast lookup of direct/transitive classification + source packages.
    """

    def __init__(self, doc: Document):
        self.doc = doc
        self._pkg_by_id: Dict[str, Package] = {p.spdx_id: p for p in doc.packages}

        # Forward:  parent_id -> {child_id}
        # Reverse:  child_id  -> {parent_id}
        children: Dict[str, Set[str]] = defaultdict(set)
        parents:  Dict[str, Set[str]] = defaultdict(set)
        for rel in doc.relationships:
            if rel.relationship_type == RelationshipType.DEPENDS_ON:
                element_id = _relationship_element_id(rel)
                related_id = _relationship_related_id(rel)
                children[element_id].add(related_id)
                parents[related_id].add(element_id)

        # Root package = what DOCUMENT DESCRIBES
        roots = {
            _relationship_related_id(rel)
            for rel in doc.relationships
            if _relationship_element_id(rel) == ROOT_SPDX_ID
            and rel.relationship_type == RelationshipType.DESCRIBES
        } or {ROOT_SPDX_ID}

        self._direct_ids: Set[str] = {
            child for root in roots for child in children[root]
        }

        # BFS for full transitive closure
        self._visited: Set[str] = set(roots) | self._direct_ids
        queue = list(self._direct_ids)
        while queue:
            node = queue.pop(0)
            for child in children[node]:
                if child not in self._visited:
                    self._visited.add(child)
                    queue.append(child)

        self._parents = parents

    def _dep_type(self, spdx_id: str) -> str:
        if spdx_id in self._direct_ids:
            return "direct"
        if spdx_id in self._visited:
            return "transitive"
        return "unknown"

    def _source_packages(self, spdx_id: str) -> List[str]:
        """Names (with version) of packages that directly depend on this one."""
        result = []
        for parent_id in self._parents.get(spdx_id, set()):
            pkg = self._pkg_by_id.get(parent_id)
            if pkg:
                ver = f"@{pkg.version}" if pkg.version else ""
                result.append(f"{pkg.name}{ver}")
        return sorted(result)

    def _purl(self, pkg: Package) -> Optional[str]:
        for ref in (pkg.external_references or []):
            if ref.reference_type == "purl":
                return ref.locator
        return None

    def _to_info(self, p: Package) -> PackageInfo:
        purl = self._purl(p)
        return PackageInfo(
            name=p.name,
            version=p.version or "unknown",
            spdx_id=p.spdx_id,
            purl=purl,
            ecosystem=_ecosystem_from_purl(purl),
            dependency_type=self._dep_type(p.spdx_id),
            source_packages=self._source_packages(p.spdx_id),
        )

    def get_package(self, name: str, ecosystem: Optional[str] = None) -> List[PackageInfo]:
        """Return info for all packages whose name matches (case-insensitive),
        optionally filtered by ecosystem."""
        infos = [
            self._to_info(p) for p in self.doc.packages
            if p.name.lower() == name.lower()
        ]
        if ecosystem:
            infos = [i for i in infos if i.ecosystem.lower() == ecosystem.lower()]
        return infos

    def get_packages(self, ecosystem: Optional[str] = None) -> List[PackageInfo]:
        """Return all packages, optionally filtered by ecosystem (e.g. 'pypi', 'npm')."""
        infos = [self._to_info(p) for p in self.doc.packages]
        if ecosystem:
            infos = [i for i in infos if i.ecosystem.lower() == ecosystem.lower()]
        return infos

    def list_ecosystems(self) -> List[str]:
        """Return sorted list of distinct ecosystems present in the SBOM."""
        return sorted({_ecosystem_from_purl(self._purl(p)) for p in self.doc.packages})


def _relationship_element_id(rel) -> str:
    return getattr(rel, "element_id", getattr(rel, "spdx_element_id"))


def _relationship_related_id(rel) -> str:
    return getattr(rel, "related_spdx_element_id", getattr(rel, "related_spdx_element"))


# ── Output ────────────────────────────────────────────────────────────────────

def print_lookup(results: List[PackageInfo], query: str) -> None:
    if not results:
        print(f"[!] No package found matching '{query}'")
        return
    for info in results:
        print(f"\n{'─' * 50}")
        print(f"  Name        : {info.name}")
        print(f"  Version     : {info.version}")
        print(f"  SPDX ID     : {info.spdx_id}")
        print(f"  PURL        : {info.purl or 'n/a'}")
        print(f"  Ecosystem   : {info.ecosystem}")
        print(f"  Dep Type    : {info.dependency_type.upper()}")
        if info.source_packages:
            print(f"  Source Pkgs : {', '.join(info.source_packages)}")
        else:
            print(f"  Source Pkgs : (root / none)")
    print(f"{'─' * 50}")


def print_table(infos: List[PackageInfo]) -> None:
    col_w = [38, 15, 12, 12]
    sep = "+-" + "-+-".join("-" * w for w in col_w) + "-+"

    def row(*cells):
        print("| " + " | ".join(str(c or "")[:w].ljust(w)
                                 for c, w in zip(cells, col_w)) + " |")

    print(sep); row("Name", "Version", "Ecosystem", "Dep Type"); print(sep)
    counts: Dict[str, int] = {}
    for info in sorted(infos, key=lambda i: (i.ecosystem, i.name)):
        counts[info.dependency_type] = counts.get(info.dependency_type, 0) + 1
        row(info.name, info.version, info.ecosystem, info.dependency_type)
    print(sep)
    print(f"\nTotal: {len(infos)}  |  "
          f"Direct: {counts.get('direct', 0)}  |  "
          f"Transitive: {counts.get('transitive', 0)}")


def _package_info_to_dict(info: PackageInfo) -> dict:
    return {
        "name": info.name,
        "version": info.version,
        "spdx_id": info.spdx_id,
        "purl": info.purl,
        "ecosystem": info.ecosystem,
        "dependency_type": info.dependency_type,
        "source_packages": info.source_packages,
    }


@tool(
    "analyze_github_sbom",
    args_schema=SBOMAnalysisInput,
)
def sbom_analysis_tool(
    owner: str,
    repo: str,
    package: Optional[str] = None,
    ecosystem: Optional[str] = None,
    list_ecosystems: bool = False,
) -> dict:
    """Fetch a repository SBOM from GitHub and classify dependencies as direct or transitive."""
    doc = fetch_github_sbom(f"{owner}/{repo}")
    graph = SBOMGraph(doc)

    if list_ecosystems:
        ecosystems = graph.list_ecosystems()
        return {
            "repository": f"{owner}/{repo}",
            "ecosystems": [
                {
                    "name": item,
                    "package_count": len(graph.get_packages(ecosystem=item)),
                }
                for item in ecosystems
            ],
        }

    packages = (
        graph.get_package(package, ecosystem=ecosystem)
        if package
        else graph.get_packages(ecosystem=ecosystem)
    )
    counts: dict[str, int] = {}
    for item in packages:
        counts[item.dependency_type] = counts.get(item.dependency_type, 0) + 1

    return {
        "repository": f"{owner}/{repo}",
        "package": package,
        "ecosystem": ecosystem,
        "total_packages": len(packages),
        "direct_packages": counts.get("direct", 0),
        "transitive_packages": counts.get("transitive", 0),
        "unknown_packages": counts.get("unknown", 0),
        "packages": [_package_info_to_dict(item) for item in packages],
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch GitHub SBOM and classify direct / transitive deps.",
        epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--github", metavar="OWNER/REPO",
                     help="Fetch SBOM from GitHub Dependency Graph API.")
    src.add_argument("--file", type=Path, metavar="FILE",
                     help="Load a local SPDX JSON file.")

    p.add_argument("--lookup", metavar="PACKAGE_NAME",
                   help="Look up a specific package by name.")
    p.add_argument("--ecosystem", metavar="ECOSYSTEM",
                   help="Filter by ecosystem: pypi, npm, maven, githubactions, … "
                        "Use --list-ecosystems to see what's in the SBOM.")
    p.add_argument("--list-ecosystems", action="store_true",
                   help="Print all ecosystems present in the SBOM and exit.")
    p.add_argument("--format", choices=["table", "json", "tv", "xml", "yaml", "rdf"],
                   default="table", help="Output format when not using --lookup (default: table).")
    p.add_argument("--output", type=Path, metavar="FILE",
                   help="Output file path for SPDX export (auto-named if omitted).")
    args = p.parse_args()

    try:
        doc = fetch_github_sbom(args.github) if args.github else load_local_sbom(args.file)
    except (ValueError, RuntimeError, requests.HTTPError) as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)

    graph = SBOMGraph(doc)

    if args.list_ecosystems:
        ecosystems = graph.list_ecosystems()
        print(f"Ecosystems in this SBOM ({len(ecosystems)}):")
        for e in ecosystems:
            count = len(graph.get_packages(ecosystem=e))
            print(f"  {e:<20} {count} packages")
        return

    if args.lookup:
        results = graph.get_package(args.lookup, ecosystem=args.ecosystem)
        print_lookup(results, args.lookup)
        return

    if args.format == "table":
        print_table(graph.get_packages(ecosystem=args.ecosystem))
        return

    ext = {"json": ".spdx.json", "tv": ".spdx", "xml": ".spdx.xml",
           "yaml": ".spdx.yaml", "rdf": ".spdx.rdf"}
    out = args.output or Path(f"{doc.creation_info.name}{ext[args.format]}")
    write_file(doc, str(out))
    print(f"[✓] Written to {out}")


if __name__ == "__main__":
    main()
import re

from pydantic import BaseModel, Field


class VersionBump(BaseModel):
    package: str
    from_version: str
    to_version: str

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return self.model_dump() == other
        if isinstance(other, VersionBump):
            return self.model_dump() == other.model_dump()
        return super().__eq__(other)

    def __iter__(self):
        yield from self.model_dump().items()


def _clean_version(version: str) -> str:
    """Strip semver prefixes and whitespace from a version string."""
    return (version or "").lstrip("vV^~>=< ").strip()


def _strip_markdown_text(value: str) -> str:
    value = value or ""
    value = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = value.replace("`", "").replace("*", "").strip()
    value = re.sub(r"\s+\([^)]*\)$", "", value)
    value = value.replace("(source)", "").replace("(source )", "")
    return value.strip()


def _add_version_bump(results: list[VersionBump], seen: set[tuple[str, str, str]], pkg: str, old: str, new: str) -> None:
    pkg = _strip_markdown_text(pkg)
    old = _clean_version(old)
    new = _clean_version(new)
    key = (pkg, old, new)
    if pkg and key not in seen:
        seen.add(key)
        results.append(VersionBump(package=pkg, from_version=old, to_version=new))


def _extract_dependabot_body(body: str) -> list[VersionBump]:
    body = body or ""
    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()

    pattern = (
        r"(?:Bumps?|Updates?)\s+"
        r"\[?`?([^\]`\s]+)`?\]?"
        r"(?:\([^)]*\))?\s+"
        r"from\s+`?([0-9A-Za-z._+-]+)`?\s+"
        r"to\s+`?([0-9A-Za-z._+-]+)`?"
    )

    for match in re.finditer(pattern, body, re.IGNORECASE):
        _add_version_bump(results, seen, match.group(1), match.group(2), match.group(3))

    grouped_pattern = re.compile(
        r"^\|\s*\[?`?([\w@/.\-]+)`?\]?(?:\([^)]*\))?\s*\|\s*"
        r"([0-9][0-9A-Za-z._+-]*)\s*\|\s*"
        r"([0-9][0-9A-Za-z._+-]*)\s*\|",
        re.IGNORECASE,
    )
    for line in body.splitlines():
        if "->" in line or "→" in line or "|" not in line:
            continue
        match = grouped_pattern.match(line.strip())
        if match:
            _add_version_bump(results, seen, match.group(1), match.group(2), match.group(3))

    generic_pattern = re.compile(
        r"([\w@/.\-]+)\s+from\s+`?([0-9A-Za-z._+-]+)`?\s+to\s+`?([0-9A-Za-z._+-]+)`?",
        re.IGNORECASE,
    )
    for match in generic_pattern.finditer(body):
        _add_version_bump(results, seen, match.group(1), match.group(2), match.group(3))

    return results


def _extract_renovate_body(body: str) -> list[VersionBump]:
    body = body or ""
    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()

    for line in body.splitlines():
        row = line.strip()
        if not row.startswith("|") or "|" not in row:
            continue
        if re.match(r"^\|?\s*[-|: ]+\|", row):
            continue

        columns = [part.strip() for part in row.strip("|").split("|")]
        if len(columns) < 2:
            continue

        package_cell = columns[0]
        if package_cell.lower() in {"package", "dependency", "name", "---"}:
            continue

        package = _strip_markdown_text(package_cell)
        if not package:
            continue

        change_cell = next((cell for cell in columns[1:] if "→" in cell or "->" in cell), "")
        if not change_cell:
            continue

        version_match = re.search(
            r"`?([0-9A-Za-z._~^=<>+-]+)`?\s*(?:->|→)\s*`?([0-9A-Za-z._~^=<>+-]+)`?",
            change_cell,
        )
        if not version_match:
            continue

        _add_version_bump(results, seen, package, version_match.group(1), version_match.group(2))

    return results


def extract_from_body(body: str) -> list[VersionBump]:
    """Pull all package updates out of the PR body by updater type."""
    return _extract_dependabot_body(body) + _extract_renovate_body(body)


def extract_from_title(title: str) -> list[VersionBump]:
    """Support direct dependency bumps formatted in the PR title."""
    title = title or ""
    results: list[VersionBump] = []
    seen: set[tuple[str, str, str]] = set()

    pattern = re.compile(
        r"(?i)\b(?:bump|update|upgrade)\s+"
        r"([\w@/.:\-]+)\s+from\s+"
        r"([0-9A-Za-z._~^=<>+-]+)\s+to\s+"
        r"([0-9A-Za-z._~^=<>+-]+)"
    )

    for match in pattern.finditer(title):
        _add_version_bump(results, seen, match.group(1), match.group(2), match.group(3))

    return results


def get_version_bumps(title: str, body: str) -> list[VersionBump]:
    """Return version bumps from the PR body, falling back to the title."""
    bumps = extract_from_body(body)
    if bumps:
        return bumps
    return extract_from_title(title)
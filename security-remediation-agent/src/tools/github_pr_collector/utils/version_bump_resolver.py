import re
from dataclasses import dataclass


@dataclass
class VersionUpdate:
    package: str
    from_version: str | None
    to_version: str
    source: str


def extract_from_title(title: str) -> list[VersionUpdate]:
    """Try to pull a single package update out of the PR title."""
    title = title or ""
    results = []

    # Dependabot:
    # Bump python-jose from 3.3.0 to 3.4.0
    m = re.search(
        r"^[Bb]umps?\s+(\S+)\s+from\s+(\S+)\s+to\s+(\S+)",
        title,
    )
    if m:
        results.append(
            VersionUpdate(
                package=m.group(1),
                from_version=m.group(2),
                to_version=m.group(3),
                source="title:dependabot",
            )
        )
        return results

    # Renovate:
    # chore(deps): update dependency requests to v2.31.0
    m = re.search(
        r"(?:update|bump)(?:\s+dependency)?\s+(\S+)\s+to\s+v?(\S+)",
        title,
        re.IGNORECASE,
    )
    if m:
        results.append(
            VersionUpdate(
                package=m.group(1),
                from_version=None,
                to_version=m.group(2),
                source="title:renovate",
            )
        )

    return results

def _clean_version(version: str) -> str:
    """
    Strip semver range-operator prefixes (^, ~, >=, <=, >, <, =) and
    surrounding whitespace from a version string.
 
    Renovate table cells often render the *range* rather than the bare
    version, e.g. "^0.31.0" or "~> 1.2.3". Without stripping this, the
    extracted to_version/from_version will never exactly equal a bare
    version string computed elsewhere (e.g. "0.31.0" from an advisory's
    first_patched field), causing downstream exact-match comparisons to
    silently fail even though the versions are equivalent.
    """
    return version.lstrip("^~>=< ").strip()

def extract_from_body(body: str) -> list[VersionUpdate]:
    """Pull all package updates out of the PR body."""
    body = body or ""
 
    results = []
    seen = set()
 
    def add(pkg, old, new, source):
        old = _clean_version(old)
        new = _clean_version(new)
        key = (pkg, old, new)
        if pkg and key not in seen:
            seen.add(key)
            results.append(
                VersionUpdate(
                    package=pkg,
                    from_version=old,
                    to_version=new,
                    source=source,
                )
            )
 
    # Dependabot
    pattern = (
        r"(?:Bumps?|Updates?)\s+"
        r"\[?`?([^\]`\s]+)`?\]?"
        r"(?:\([^)]*\))?\s+"
        r"from\s+`?([0-9A-Za-z._+-]+)`?\s+"
        r"to\s+`?([0-9A-Za-z._+-]+)`?"
    )
 
    for m in re.finditer(pattern, body, re.IGNORECASE):
        add(
            m.group(1),
            m.group(2),
            m.group(3),
            "body:dependabot",
        )
 
    # Renovate markdown table
    for line in body.splitlines():
        if "->" not in line or "|" not in line:
            continue
 
        pkg_match = re.match(
            r"\s*\|\s*\[?`?([\w@/.\-]+)`?\]?(?:\([^)]*\))?\s*\|",
            line,
        )
 
        ver_match = re.search(
            r"`([^`]+)`\s*->\s*`([^`]+)`",
            line,
        )
 
        if pkg_match and ver_match:
            add(
                pkg_match.group(1),
                ver_match.group(1),
                ver_match.group(2),
                "body:renovate-table",
            )
 
    # Generic fallback
    if not results:
        for m in re.finditer(
            r"([\w@/.\-]+)\s+from\s+`?([0-9A-Za-z._+-]+)`?\s+to\s+`?([0-9A-Za-z._+-]+)`?",
            body,
            re.IGNORECASE,
        ):
            add(
                m.group(1),
                m.group(2),
                m.group(3),
                "body:generic",
            )
 
    return results


def get_version_bumps(title: str, body: str) -> list[VersionUpdate]:
    updates = extract_from_body(body)
    if not updates:
        updates = extract_from_title(title)

    return updates
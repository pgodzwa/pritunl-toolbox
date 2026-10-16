#!/usr/bin/env python3
"""Compute the next release version from git tags and commit messages.

Used by .github/workflows/release.yml on every push to main.

Rules (commits since the latest vX.Y.Z tag; merge commits include the PR title/body):
  * no release tag yet                                   -> 1.0.0
  * "BREAKING CHANGE", "[major]" or a "type!:" subject   -> major bump
  * "[minor]" or a "feat:" / "feat(scope):" subject      -> minor bump
  * anything else                                        -> patch bump
  * "[skip release]" in any commit, or HEAD already tagged -> no release

Prints GitHub Actions outputs (key=value lines): release, version, previous, bump.
Commit messages are only read, never executed or interpolated into a shell.
"""

from __future__ import annotations

import re
import subprocess
import sys

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
FIRST_VERSION = (1, 0, 0)

MAJOR_RE = re.compile(r"BREAKING[ -]CHANGE|\[major\]|^\s*\w+(\([^)]*\))?!:", re.I | re.M)
MINOR_RE = re.compile(r"\[minor\]|^\s*feat(\([^)]*\))?:", re.I | re.M)
SKIP_RE = re.compile(r"\[skip release\]", re.I)


def parse_tag(tag: str) -> tuple[int, int, int] | None:
    m = TAG_RE.match(tag.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def bump_kind(messages: list[str]) -> str:
    text = "\n".join(messages)
    if MAJOR_RE.search(text):
        return "major"
    if MINOR_RE.search(text):
        return "minor"
    return "patch"


def next_version(tags: list[str], messages: list[str]) -> tuple[str | None, str | None, str]:
    """Returns (next_version or None to skip, previous_version, bump)."""
    versions = sorted(v for v in (parse_tag(t) for t in tags) if v)
    if any(SKIP_RE.search(m) for m in messages):
        return None, _fmt(versions[-1]) if versions else None, "skip"
    if not versions:
        return _fmt(FIRST_VERSION), None, "initial"
    major, minor, patch = versions[-1]
    kind = bump_kind(messages)
    if kind == "major":
        new = (major + 1, 0, 0)
    elif kind == "minor":
        new = (major, minor + 1, 0)
    else:
        new = (major, minor, patch + 1)
    return _fmt(new), _fmt(versions[-1]), kind


def _fmt(v: tuple[int, int, int]) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True,  # noqa: S603,S607
                          text=True).stdout


def main() -> int:
    tags = [t for t in _git("tag", "--list", "v*").split() if parse_tag(t)]
    head_tags = [t for t in _git("tag", "--points-at", "HEAD").split() if parse_tag(t)]
    if head_tags:
        print("release=false")
        print(f"version={head_tags[0][1:]}")
        print("bump=already-tagged")
        return 0
    latest = max(tags, key=parse_tag) if tags else None
    rev_range = f"{latest}..HEAD" if latest else "HEAD"
    messages = [m for m in _git("log", "--format=%B%x00", rev_range).split("\x00") if m.strip()]
    version, previous, bump = next_version(tags, messages)
    print(f"release={'true' if version else 'false'}")
    print(f"version={version or ''}")
    print(f"previous={previous or ''}")
    print(f"bump={bump}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

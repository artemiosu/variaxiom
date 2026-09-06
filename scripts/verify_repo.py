#!/usr/bin/env python3
"""Repository checks that require only the Python standard library."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote

REQUIRED_FILES = (
    "README.md",
    "README.ru.md",
    "START_HERE.ru.md",
    "PROJECT_STATUS.md",
    "REPRODUCIBILITY.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "constitution/constitution.toml",
    "schemas/event.schema.json",
    "schemas/skill-package.schema.json",
    "schemas/tool-manifest.schema.json",
    "docs/architecture/overview.md",
    "docs/project/expert-council.ru.md",
    "docs/project/github-setup.md",
    "docs/demo/authority-test.html",
    "docs/research/harness-comparison.md",
    "docs/launch/launch-strategy.ru.md",
    "assets/social-preview.png",
    ".github/workflows/ci.yml",
)

MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HTML_SOURCE = re.compile(r"(?:src|href)=[\"']([^\"']+)[\"']")
IGNORED_SCHEMES = ("http://", "https://", "mailto:", "data:", "tel:")


def _local_target(root: Path, document: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    if not target or target.startswith("#") or target.startswith(IGNORED_SCHEMES):
        return None
    target = unquote(target.split("#", 1)[0].split("?", 1)[0])
    if not target:
        return None
    if target.startswith("/"):
        return root / target.lstrip("/")
    return document.parent / target


def _verify_links(root: Path, markdown: Path) -> list[str]:
    text = markdown.read_text("utf-8")
    targets = MARKDOWN_LINK.findall(text) + HTML_SOURCE.findall(text)
    errors: list[str] = []
    for raw_target in targets:
        target = _local_target(root, markdown, raw_target)
        if target is None:
            continue
        if not target.exists():
            errors.append(
                f"broken local link in {markdown.relative_to(root)}: {raw_target}"
            )
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")

    for schema in sorted((root / "schemas").glob("*.json")):
        try:
            value = json.loads(schema.read_text("utf-8"))
        except json.JSONDecodeError as error:
            errors.append(f"invalid JSON in {schema.relative_to(root)}: {error}")
            continue
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"unexpected schema draft in {schema.relative_to(root)}")

    for markdown in root.rglob("*.md"):
        if ".git" in markdown.parts or ".variaxiom" in markdown.parts:
            continue
        text = markdown.read_text("utf-8")
        if "TODO: FILL BEFORE PUBLIC LAUNCH" in text:
            errors.append(f"unresolved launch blocker in {markdown.relative_to(root)}")
        errors.extend(_verify_links(root, markdown))

    for relative in ("scripts/bootstrap.sh", "scripts/demo.sh", "scripts/verify.sh"):
        script = root / relative
        if script.is_file() and not os.access(script, os.X_OK):
            errors.append(f"script is not executable: {relative}")

    if errors:
        print("Repository verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Repository structure verified ({len(REQUIRED_FILES)} required files).")
    print("Local Markdown links and executable scripts verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

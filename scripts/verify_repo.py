#!/usr/bin/env python3
"""Repository, schema, fixture, and documentation integrity checks."""

from __future__ import annotations

import os
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from variaxiom.canonical import strict_json_loads

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
    ".github/workflows/codeql.yml",
    ".github/copilot-instructions.md",
    ".githooks/pre-commit",
    "AGENTS.md",
    "CLAUDE.md",
    "project.yaml",
    "schemas/project.schema.json",
    "schemas/promotion-input-envelope.schema.json",
    "schemas/decision-envelope.schema.json",
    "docs/context/index.md",
    "docs/product/requirements.md",
    "docs/product/mvp-scope.md",
    "docs/project/current.md",
    "docs/project/traceability.md",
    "docs/specs/m1.1-cross-language-conformance.md",
    "fixtures/conformance/v1/promotion/bounded-accepted.json",
)

MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HTML_SOURCE = re.compile(r"(?:src|href)=[\"']([^\"']+)[\"']")
IGNORED_SCHEMES = ("http://", "https://", "mailto:", "data:", "tel:")
IGNORED_PARTS = {".git", ".variaxiom", ".venv", "target"}
REQUIREMENT_ID = re.compile(r"REQ-[A-Z]+-[0-9]{3}")
REQUIREMENT_ROW = re.compile(r"^\|\s*(REQ-[A-Z]+-[0-9]{3})\s*\|", re.MULTILINE)
MILESTONE_HEADING = re.compile(r"^##\s+(M[0-9]+)\s+(?:—|-)\s+", re.MULTILINE)
CYRILLIC = re.compile(r"[\u0400-\u04ff]")


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
            errors.append(f"broken local link in {markdown.relative_to(root)}: {raw_target}")
    return errors


def _verify_pages_landing(root: Path) -> list[str]:
    """Check constraints that differ between the checkout and the /docs Pages root."""
    landing = root / "docs/index.html"
    text = landing.read_text("utf-8")
    errors: list[str] = []
    if '<html lang="en">' not in text:
        errors.append("docs/index.html must declare English as its document language")
    if CYRILLIC.search(text):
        errors.append("docs/index.html must contain English-only text and controls")

    pages_root = (root / "docs").resolve()
    for raw_target in HTML_SOURCE.findall(text):
        target = raw_target.strip()
        if (
            not target
            or target.startswith("#")
            or target.startswith(IGNORED_SCHEMES)
            or target.startswith("//")
        ):
            continue
        target_path = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not target_path:
            continue
        if target_path.startswith("/"):
            errors.append(
                f"Pages link must be repository-relative or absolute HTTPS in docs/index.html: "
                f"{raw_target}"
            )
            continue
        resolved = (landing.parent / target_path).resolve()
        try:
            resolved.relative_to(pages_root)
        except ValueError:
            errors.append(f"Pages link escapes the published /docs root: {raw_target}")
            continue
        if not resolved.exists():
            errors.append(f"broken Pages link in docs/index.html: {raw_target}")
    return errors


def _validate_instance(
    instance: object,
    schema_name: str,
    schemas: dict[str, dict[str, object]],
    label: str,
) -> list[str]:
    schema = schemas[schema_name]
    registry = Registry().with_resources(
        (str(item["$id"]), Resource.from_contents(item))
        for item in schemas.values()
        if isinstance(item.get("$id"), str)
    )
    validator = Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    return [
        f"{label}: {error.message} at {'/'.join(map(str, error.absolute_path)) or '$'}"
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path))
    ]


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def _traceability_statuses(text: str) -> tuple[list[str], dict[str, str]]:
    identifiers: list[str] = []
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) != 5 or REQUIREMENT_ID.fullmatch(cells[0]) is None:
            continue
        identifier = cells[0]
        identifiers.append(identifier)
        statuses[identifier] = cells[-1]
    return identifiers, statuses


def _verify_project_path(root: Path, raw_path: object, label: str) -> list[str]:
    if not isinstance(raw_path, str):
        return []  # JSON Schema reports the type error.
    candidate = Path(raw_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return [f"unsafe repository-relative path in {label}: {raw_path}"]
    resolved_root = root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        return [f"repository path escapes the checkout in {label}: {raw_path}"]
    if not resolved.exists():
        return [f"missing project context path in {label}: {raw_path}"]
    return []


def _verify_project_context(root: Path, project: dict[str, object]) -> list[str]:
    errors: list[str] = []

    requirements_path = root / "docs/product/requirements.md"
    traceability_path = root / "docs/project/traceability.md"
    milestones_path = root / "docs/project/milestones.md"
    current_path = root / "docs/project/current.md"

    requirement_ids = REQUIREMENT_ROW.findall(requirements_path.read_text("utf-8"))
    for duplicate in _duplicates(requirement_ids):
        errors.append(f"duplicate requirement ID in docs/product/requirements.md: {duplicate}")

    project_requirements = project.get("requirements")
    project_ids: list[str] = []
    project_statuses: dict[str, str] = {}
    if isinstance(project_requirements, list):
        for index, entry in enumerate(project_requirements):
            if not isinstance(entry, dict):
                continue
            identifier = entry.get("id")
            status = entry.get("status")
            if isinstance(identifier, str):
                project_ids.append(identifier)
                if isinstance(status, str):
                    project_statuses[identifier] = status
            evidence = entry.get("evidence")
            if isinstance(evidence, list):
                for evidence_index, path in enumerate(evidence):
                    errors.extend(
                        _verify_project_path(
                            root,
                            path,
                            f"project.yaml requirements[{index}].evidence[{evidence_index}]",
                        )
                    )

    for duplicate in _duplicates(project_ids):
        errors.append(f"duplicate requirement ID in project.yaml: {duplicate}")

    documented_ids = set(requirement_ids)
    machine_ids = set(project_ids)
    for missing in sorted(documented_ids - machine_ids):
        errors.append(f"requirement missing from project.yaml: {missing}")
    for extra in sorted(machine_ids - documented_ids):
        errors.append(f"project.yaml requirement absent from registry: {extra}")

    traceability_ids, traceability_statuses = _traceability_statuses(
        traceability_path.read_text("utf-8")
    )
    for duplicate in _duplicates(traceability_ids):
        errors.append(f"duplicate requirement ID in docs/project/traceability.md: {duplicate}")
    for missing in sorted(machine_ids - set(traceability_ids)):
        errors.append(f"requirement missing from traceability table: {missing}")
    for extra in sorted(set(traceability_ids) - machine_ids):
        errors.append(f"traceability requirement absent from project.yaml: {extra}")
    for identifier in sorted(machine_ids & set(traceability_ids)):
        project_status = project_statuses.get(identifier)
        traceability_status = traceability_statuses.get(identifier)
        if project_status != traceability_status:
            errors.append(
                f"status drift for {identifier}: project.yaml={project_status}, "
                f"traceability={traceability_status}"
            )

    source_of_truth = project.get("source_of_truth")
    if isinstance(source_of_truth, dict):
        for name, path in source_of_truth.items():
            errors.extend(_verify_project_path(root, path, f"project.yaml source_of_truth.{name}"))

    milestones = project.get("milestones")
    milestone_ids: list[str] = []
    if isinstance(milestones, list):
        for index, milestone in enumerate(milestones):
            if not isinstance(milestone, dict):
                continue
            identifier = milestone.get("id")
            if isinstance(identifier, str):
                milestone_ids.append(identifier)
            errors.extend(
                _verify_project_path(
                    root, milestone.get("document"), f"project.yaml milestones[{index}].document"
                )
            )
    for duplicate in _duplicates(milestone_ids):
        errors.append(f"duplicate milestone ID in project.yaml: {duplicate}")

    documented_milestones = MILESTONE_HEADING.findall(milestones_path.read_text("utf-8"))
    for duplicate in _duplicates(documented_milestones):
        errors.append(f"duplicate milestone heading in docs/project/milestones.md: {duplicate}")
    for missing in sorted(set(documented_milestones) - set(milestone_ids)):
        errors.append(f"milestone missing from project.yaml: {missing}")
    for extra in sorted(set(milestone_ids) - set(documented_milestones)):
        errors.append(f"project.yaml milestone absent from milestone document: {extra}")

    for collection_name, path_key in (
        ("evidence", "artifact"),
        ("risks", "document"),
    ):
        collection = project.get(collection_name)
        if not isinstance(collection, list):
            continue
        identifiers: list[str] = []
        for index, entry in enumerate(collection):
            if not isinstance(entry, dict):
                continue
            identifier = entry.get("id")
            if isinstance(identifier, str):
                identifiers.append(identifier)
            errors.extend(
                _verify_project_path(
                    root,
                    entry.get(path_key),
                    f"project.yaml {collection_name}[{index}].{path_key}",
                )
            )
        for duplicate in _duplicates(identifiers):
            errors.append(f"duplicate {collection_name} ID in project.yaml: {duplicate}")

    context_packs = project.get("context_packs")
    if isinstance(context_packs, dict):
        for pack, paths in context_packs.items():
            if not isinstance(paths, list):
                continue
            for index, path in enumerate(paths):
                errors.extend(
                    _verify_project_path(root, path, f"project.yaml context_packs.{pack}[{index}]")
                )

    current_text = current_path.read_text("utf-8")
    active_increment = project.get("active_increment")
    next_increment = project.get("next_increment")
    for label, increment in (
        ("active_increment", active_increment),
        ("next_increment", next_increment),
    ):
        if not isinstance(increment, dict):
            continue
        identifier = increment.get("id")
        if isinstance(identifier, str):
            parent_milestone = identifier.split(".", 1)[0]
            if parent_milestone not in milestone_ids:
                errors.append(
                    f"project.yaml {label} {identifier} has no parent milestone {parent_milestone}"
                )
        specification = increment.get("specification")
        if isinstance(specification, str):
            errors.extend(
                _verify_project_path(root, specification, f"project.yaml {label}.specification")
            )

    if isinstance(active_increment, dict):
        active_id = active_increment.get("id")
        active_specification = active_increment.get("specification")
        current_id_match = re.search(
            r"^(?:-\s+)?\*\*Current product increment:\*\*\s*([^\s]+)",
            current_text,
            re.MULTILINE,
        )
        if isinstance(active_id, str) and (
            current_id_match is None or current_id_match.group(1) != active_id
        ):
            observed = current_id_match.group(1) if current_id_match else "missing"
            errors.append(
                f"active increment drift: project.yaml={active_id}, docs/project/current.md={observed}"
            )

        current_spec_match = re.search(
            r"^(?:-\s+)?\*\*Active specification:\*\*\s*\[[^]]+\]\(([^)]+)\)",
            current_text,
            re.MULTILINE,
        )
        if isinstance(active_specification, str):
            expected_specification = (root / active_specification).resolve()
            if current_spec_match is None:
                errors.append("active specification link missing from docs/project/current.md")
            else:
                observed_specification = (
                    current_path.parent / current_spec_match.group(1)
                ).resolve()
                if observed_specification != expected_specification:
                    errors.append(
                        "active specification drift: "
                        f"project.yaml={active_specification}, "
                        f"docs/project/current.md={current_spec_match.group(1)}"
                    )

        active_requirements = active_increment.get("requirements")
        if isinstance(active_requirements, list):
            for identifier in active_requirements:
                if isinstance(identifier, str) and identifier not in machine_ids:
                    errors.append(f"active increment references unknown requirement: {identifier}")

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")

    schemas: dict[str, dict[str, object]] = {}
    for schema in sorted((root / "schemas").glob("*.json")):
        try:
            value = strict_json_loads(schema.read_bytes())
        except (TypeError, ValueError) as error:
            errors.append(f"invalid JSON in {schema.relative_to(root)}: {error}")
            continue
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"unexpected schema draft in {schema.relative_to(root)}")
        try:
            Draft202012Validator.check_schema(value)
        except Exception as error:  # jsonschema exposes several schema-error subclasses
            errors.append(f"invalid JSON Schema in {schema.relative_to(root)}: {error}")
        schemas[schema.name] = value

    project_file = root / "project.yaml"
    try:
        # The project file intentionally uses the JSON subset of YAML for deterministic,
        # dependency-neutral consumers. Check that a general YAML parser sees the same value.
        project = strict_json_loads(project_file.read_bytes())
        yaml_project = yaml.safe_load(project_file.read_text("utf-8"))
        if yaml_project != project:
            errors.append("project.yaml has different JSON and YAML interpretations")
        if not isinstance(project, dict):
            errors.append("project.yaml root must be a mapping")
        elif "project.schema.json" in schemas:
            errors.extend(
                _validate_instance(project, "project.schema.json", schemas, "project.yaml")
            )
            errors.extend(_verify_project_context(root, project))
    except (TypeError, ValueError, OSError, yaml.YAMLError) as error:
        errors.append(f"invalid JSON-compatible YAML in project.yaml: {error}")

    for fixture_path in sorted((root / "fixtures/conformance/v1/promotion").glob("*.json")):
        try:
            fixture = strict_json_loads(fixture_path.read_bytes())
            label = str(fixture_path.relative_to(root))
            errors.extend(
                _validate_instance(fixture["candidate"], "candidate.schema.json", schemas, label)
            )
            for index, evidence in enumerate(fixture["evidence"]):
                errors.extend(
                    _validate_instance(
                        evidence, "evidence.schema.json", schemas, f"{label} evidence[{index}]"
                    )
                )
            errors.extend(
                _validate_instance(
                    fixture["constitution"], "constitution.schema.json", schemas, label
                )
            )
            errors.extend(
                _validate_instance(
                    fixture["context"], "promotion-context.schema.json", schemas, label
                )
            )
            expected = fixture["expected"]
            errors.extend(
                _validate_instance(expected["decision"], "promotion.schema.json", schemas, label)
            )
            errors.extend(
                _validate_instance(
                    strict_json_loads(expected["input_envelope_json"]),
                    "promotion-input-envelope.schema.json",
                    schemas,
                    label,
                )
            )
            errors.extend(
                _validate_instance(
                    strict_json_loads(expected["decision_envelope_json"]),
                    "decision-envelope.schema.json",
                    schemas,
                    label,
                )
            )
        except (KeyError, TypeError, ValueError, OSError) as error:
            errors.append(f"invalid conformance fixture {fixture_path.relative_to(root)}: {error}")

    demo_ledger = root / "docs/demo/lineage.jsonl"
    try:
        for index, line in enumerate(demo_ledger.read_text("utf-8").splitlines(), start=1):
            event = strict_json_loads(line)
            label = f"docs/demo/lineage.jsonl:{index}"
            errors.extend(_validate_instance(event, "event.schema.json", schemas, label))
            payload_schema = {
                "candidate.proposed": "candidate.schema.json",
                "evidence.recorded": "evidence.schema.json",
                "promotion.decided": "promotion.schema.json",
            }.get(event.get("kind"))
            if payload_schema:
                errors.extend(
                    _validate_instance(event.get("payload"), payload_schema, schemas, label)
                )
    except (AttributeError, ValueError, OSError, TypeError) as error:
        errors.append(f"invalid generated demo ledger: {error}")

    try:
        report = strict_json_loads((root / "docs/demo/demo-report.json").read_bytes())
        for index, decision in enumerate(report["decisions"]):
            errors.extend(
                _validate_instance(
                    decision,
                    "promotion.schema.json",
                    schemas,
                    f"docs/demo/demo-report.json decisions[{index}]",
                )
            )
    except (KeyError, ValueError, OSError, TypeError) as error:
        errors.append(f"invalid generated demo report: {error}")

    for toml_file in sorted(root.rglob("*.toml")):
        if IGNORED_PARTS.intersection(toml_file.parts):
            continue
        try:
            tomllib.loads(toml_file.read_text("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            errors.append(f"invalid TOML in {toml_file.relative_to(root)}: {error}")

    for yaml_file in sorted((root / ".github").rglob("*.yml")):
        try:
            value = yaml.safe_load(yaml_file.read_text("utf-8"))
            if not isinstance(value, dict):
                errors.append(f"YAML root is not a mapping in {yaml_file.relative_to(root)}")
        except (yaml.YAMLError, UnicodeDecodeError) as error:
            errors.append(f"invalid YAML in {yaml_file.relative_to(root)}: {error}")

    for markdown in root.rglob("*.md"):
        if IGNORED_PARTS.intersection(markdown.parts):
            continue
        text = markdown.read_text("utf-8")
        if "TODO: FILL BEFORE PUBLIC LAUNCH" in text:
            errors.append(f"unresolved launch blocker in {markdown.relative_to(root)}")
        errors.extend(_verify_links(root, markdown))

    errors.extend(_verify_pages_landing(root))

    for relative in (
        ".githooks/pre-commit",
        "scripts/bootstrap.sh",
        "scripts/demo.sh",
        "scripts/regenerate_conformance_fixtures.py",
        "scripts/setup-github.sh",
        "scripts/verify.sh",
    ):
        script = root / relative
        if script.is_file() and not os.access(script, os.X_OK):
            errors.append(f"script is not executable: {relative}")

    if errors:
        print("Repository verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Repository structure verified ({len(REQUIRED_FILES)} required files).")
    print("Local Markdown links, GitHub Pages landing, and executable scripts verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

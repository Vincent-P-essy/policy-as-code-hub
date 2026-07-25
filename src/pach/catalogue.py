"""The catalogue, read from the policies themselves.

Metadata lives in Rego `# METADATA` annotations, not in a parallel YAML file.
That is the whole reason this is trustworthy: a sidecar file drifts from the
policy it describes within a release, and nothing catches it because nothing
reads both. OPA parses the annotations as part of compiling the policy, so a
malformed one fails `opa check` rather than silently producing a catalogue
entry that describes a rule which no longer exists.

`opa inspect -a` is therefore the source of truth here, and this module is a
reader rather than a second copy of the data.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class CatalogueError(RuntimeError):
    """Raised when the catalogue cannot be built."""


class OpaMissing(CatalogueError):
    """Raised when the `opa` binary is not on PATH."""

    def __init__(self) -> None:
        super().__init__(
            "the `opa` binary was not found on PATH. This project does not "
            "reimplement Rego evaluation - it curates policies that OPA runs. "
            "Install it from https://www.openpolicyagent.org/docs/latest/#running-opa"
        )


SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def opa_path() -> str:
    found = shutil.which("opa")
    if not found:
        raise OpaMissing()
    return found


def run_opa(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [opa_path(), *args], capture_output=True, text=True, check=check, timeout=300
    )


@dataclass(frozen=True)
class Policy:
    """One policy, as its own annotations describe it."""

    id: str
    package: str
    title: str
    description: str
    severity: str
    remediation: str
    frameworks: dict[str, list[str]]
    file: str
    line: int = 0

    @property
    def domain(self) -> str:
        """`kubernetes`, `terraform`, ... taken from the package path."""
        return self.package.split(".")[0] if self.package else "unknown"

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def controls(self, framework: str) -> list[str]:
        return self.frameworks.get(framework, [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "package": self.package,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "remediation": self.remediation,
            "frameworks": self.frameworks,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class Catalogue:
    policies: list[Policy] = field(default_factory=list)
    #: Packages carrying no `custom.id`, i.e. libraries rather than policies.
    helpers: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.policies)

    def by_id(self, policy_id: str) -> Policy | None:
        return next((p for p in self.policies if p.id == policy_id), None)

    def frameworks(self) -> list[str]:
        names: set[str] = set()
        for policy in self.policies:
            names.update(policy.frameworks)
        return sorted(names)

    def domains(self) -> list[str]:
        return sorted({p.domain for p in self.policies})

    def controls_covered(self, framework: str) -> dict[str, list[Policy]]:
        """`control id -> the policies that enforce it`."""
        out: dict[str, list[Policy]] = {}
        for policy in self.policies:
            for control in policy.controls(framework):
                out.setdefault(control, []).append(policy)
        return out

    def duplicate_ids(self) -> list[str]:
        seen: dict[str, int] = {}
        for policy in self.policies:
            seen[policy.id] = seen.get(policy.id, 0) + 1
        return sorted(policy_id for policy_id, count in seen.items() if count > 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policies": [p.to_dict() for p in self.policies],
            "frameworks": self.frameworks(),
            "domains": self.domains(),
            "helpers": self.helpers,
        }


def build(path: str | Path = "policies") -> Catalogue:
    """Read every policy's annotations via `opa inspect`."""
    source = Path(path)
    if not source.exists():
        raise CatalogueError(f"policy directory not found: {source}")

    result = run_opa(["inspect", "-a", "--format", "json", str(source)])
    if result.returncode != 0:
        raise CatalogueError(f"opa inspect failed:\n{result.stderr.strip()}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CatalogueError(f"could not parse opa inspect output: {exc}") from None

    catalogue = Catalogue()
    for entry in data.get("annotations", []):
        annotations = entry.get("annotations", {})
        if annotations.get("scope") != "package":
            continue

        package = ".".join(
            part.get("value", "")
            for part in entry.get("path", [])
            if part.get("value") not in (None, "data")
        )
        custom = annotations.get("custom") or {}

        if "id" not in custom:
            # A package with no id is a helper library, not a policy. Listing it
            # as one would inflate the catalogue with things that enforce nothing.
            catalogue.helpers.append(package)
            continue

        location = entry.get("location", {})
        catalogue.policies.append(
            Policy(
                id=str(custom["id"]),
                package=package,
                title=annotations.get("title", ""),
                description=(annotations.get("description") or "").strip(),
                severity=str(custom.get("severity", "medium")).lower(),
                remediation=str(custom.get("remediation", "")),
                frameworks={
                    str(name): [str(c) for c in controls]
                    for name, controls in (custom.get("frameworks") or {}).items()
                },
                file=location.get("file", ""),
                line=int(location.get("row", 0)),
            )
        )

    catalogue.policies.sort(key=lambda p: p.id)
    return catalogue


def validate(catalogue: Catalogue, path: str | Path = "policies") -> list[str]:
    """Problems that would make the catalogue misleading rather than merely thin."""
    problems: list[str] = []

    for policy_id in catalogue.duplicate_ids():
        problems.append(f"duplicate policy id {policy_id!r}")

    for policy in catalogue.policies:
        if not policy.title:
            problems.append(f"{policy.id}: no title")
        if not policy.description:
            problems.append(f"{policy.id}: no description")
        if not policy.remediation:
            problems.append(
                f"{policy.id}: no remediation — a policy that says what is wrong "
                "and not what to do is a complaint"
            )
        if policy.severity not in SEVERITY_RANK:
            problems.append(
                f"{policy.id}: severity {policy.severity!r} is not one of "
                f"{', '.join(SEVERITY_RANK)}"
            )
        if not policy.frameworks:
            problems.append(
                f"{policy.id}: maps to no framework control — the mapping is the "
                "reason this catalogue exists"
            )

    # A policy without tests is a policy nobody has shown to work.
    source = Path(path)
    for policy in catalogue.policies:
        policy_file = Path(policy.file)
        candidate = source.parent / policy_file if not policy_file.is_absolute() else policy_file
        if not candidate.exists():
            candidate = Path(policy.file)
        test_file = candidate.with_name(candidate.stem + "_test.rego")
        if not test_file.exists():
            problems.append(f"{policy.id}: no {test_file.name} beside it")

    return problems

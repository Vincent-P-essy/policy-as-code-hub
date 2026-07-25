"""Running the policies, and packaging them for distribution.

OPA does the evaluation. This project curates, maps and packages — it does not
reimplement Rego, because a second evaluator that agrees with OPA 95% of the
time is worse than no evaluator at all: the 5% is where a policy passes in CI
and fails at admission, or the reverse.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .catalogue import Catalogue, CatalogueError, Policy, opa_path, run_opa


@dataclass(frozen=True)
class Violation:
    policy: Policy | None
    package: str
    rule: str          # "deny" or "warn"
    message: str
    resource: str = ""
    source: str = ""

    @property
    def severity(self) -> str:
        if self.rule == "warn":
            return "low"
        return self.policy.severity if self.policy else "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.id if self.policy else self.package,
            "package": self.package,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "resource": self.resource,
            "source": self.source,
        }


@dataclass
class EvalResult:
    violations: list[Violation] = field(default_factory=list)
    documents: int = 0
    files: list[str] = field(default_factory=list)

    @property
    def denials(self) -> list[Violation]:
        return [v for v in self.violations if v.rule == "deny"]

    @property
    def warnings(self) -> list[Violation]:
        return [v for v in self.violations if v.rule == "warn"]

    @property
    def clean(self) -> bool:
        return not self.denials

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean": self.clean,
            "documents": self.documents,
            "files": self.files,
            "denials": len(self.denials),
            "warnings": len(self.warnings),
            "violations": [v.to_dict() for v in self.violations],
        }


def _documents(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]


def evaluate(
    manifests: list[str | Path],
    catalogue: Catalogue,
    *,
    policy_dir: str | Path = "policies",
) -> EvalResult:
    """Evaluate every document against every policy, in one OPA process.

    One `opa eval` for the whole set rather than one per document: OPA's start-up
    dominates otherwise, and a policy tool that takes a minute on a repository
    gets moved out of the pre-commit hook and then forgotten.
    """
    result = EvalResult()
    by_package = {p.package: p for p in catalogue.policies}

    documents: list[tuple[str, dict[str, Any]]] = []
    for manifest in manifests:
        path = Path(manifest)
        if not path.exists():
            raise CatalogueError(f"manifest not found: {path}")
        for document in _documents(path):
            documents.append((str(path), document))
        result.files.append(str(path))

    result.documents = len(documents)
    if not documents:
        return result

    for source, document in documents:
        completed = _eval_with_input(policy_dir, document)
        if completed.returncode != 0:
            raise CatalogueError(f"opa eval failed:\n{completed.stderr.strip()}")

        payload = json.loads(completed.stdout or "{}")
        expressions = payload.get("result", [{}])[0].get("expressions", [{}])
        data = expressions[0].get("value", {}) if expressions else {}

        resource = "/".join(
            filter(None, [document.get("kind", ""), _name(document)])
        )
        for package, rules in _walk(data):
            for rule in ("deny", "warn"):
                for message in rules.get(rule, []) or []:
                    result.violations.append(
                        Violation(
                            policy=by_package.get(package),
                            package=package,
                            rule=rule,
                            message=str(message),
                            resource=resource,
                            source=source,
                        )
                    )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.violations.sort(
        key=lambda v: (v.rule != "deny", order.get(v.severity, 9), v.package)
    )
    return result


def _eval_with_input(policy_dir: str | Path, document: dict[str, Any]):
    """`opa eval` with the document on stdin."""
    import subprocess

    return subprocess.run(
        [
            opa_path(), "eval",
            "--data", str(policy_dir),
            "--stdin-input",
            "--format", "json",
            "data",
        ],
        input=json.dumps(document),
        capture_output=True,
        text=True,
        timeout=120,
    )


def _name(document: dict[str, Any]) -> str:
    return str((document.get("metadata") or {}).get("name", ""))


def _walk(data: dict[str, Any], prefix: str = "") -> list[tuple[str, dict[str, Any]]]:
    """Find every package that produced a `deny` or `warn` set."""
    out: list[tuple[str, dict[str, Any]]] = []
    for key, value in (data or {}).items():
        if not isinstance(value, dict):
            continue
        package = f"{prefix}.{key}" if prefix else key
        if "deny" in value or "warn" in value:
            out.append((package, value))
        out.extend(_walk(value, package))
    return out


# -- opa test ---------------------------------------------------------------

_TEST_LINE = re.compile(r"^(?P<pkg>\S+)\.(?P<name>test_\S+):\s+(?P<outcome>PASS|FAIL|ERROR)")


@dataclass
class TestResult:
    passed: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.passed > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "failed": self.failed,
            "failures": self.failures,
            "ok": self.ok,
        }


def run_tests(policy_dir: str | Path = "policies") -> TestResult:
    """Run `opa test` and parse the result."""
    completed = run_opa(["test", str(policy_dir), "-v"])
    result = TestResult(output=completed.stdout + completed.stderr)

    for line in result.output.splitlines():
        match = _TEST_LINE.match(line.strip())
        if not match:
            continue
        if match.group("outcome") == "PASS":
            result.passed += 1
        else:
            result.failed += 1
            result.failures.append(f"{match.group('pkg')}.{match.group('name')}")
    return result


def check(policy_dir: str | Path = "policies", *, strict: bool = True) -> tuple[bool, str]:
    """`opa check --strict`: unused imports, shadowed names, deprecated builtins."""
    args = ["check", str(policy_dir)]
    if strict:
        args.append("--strict")
    completed = run_opa(args)
    return completed.returncode == 0, (completed.stderr or completed.stdout).strip()


def build_bundle(
    policy_dir: str | Path = "policies",
    output: str | Path = "dist/policies.tar.gz",
    *,
    revision: str = "",
) -> Path:
    """Build a signed-ready OPA bundle for distribution.

    A bundle is how these policies reach an admission controller or a sidecar:
    one artefact with a revision, pulled and hot-reloaded rather than baked into
    an image and redeployed.
    """
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    args = ["build", "-b", str(policy_dir), "-o", str(out)]
    if revision:
        args += ["--revision", revision]
    completed = run_opa(args)
    if completed.returncode != 0:
        raise CatalogueError(f"opa build failed:\n{completed.stderr.strip()}")
    return out

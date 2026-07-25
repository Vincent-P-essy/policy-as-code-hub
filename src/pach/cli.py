"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .catalogue import CatalogueError, OpaMissing, build, validate
from .evaluate import build_bundle, check, evaluate, run_tests

SEVERITY_STYLE = {
    "critical": "bright_red", "high": "red", "medium": "yellow", "low": "cyan",
}


def cmd_list(args: argparse.Namespace, console: Console) -> int:
    catalogue = build(args.policies)
    table = Table(
        title=f"{len(catalogue)} policies across {len(catalogue.domains())} domain(s)",
        title_style="bold", header_style="dim",
    )
    table.add_column("id", style="bold")
    table.add_column("sev")
    table.add_column("policy", overflow="fold")
    for framework in catalogue.frameworks():
        table.add_column(framework, style="cyan", overflow="fold")

    for policy in catalogue.policies:
        row = [
            policy.id,
            Text(policy.severity, style=SEVERITY_STYLE.get(policy.severity, "white")),
            policy.title,
        ]
        row += [", ".join(policy.controls(f)) or "—" for f in catalogue.frameworks()]
        table.add_row(*row)
    console.print(table)
    console.print(
        "\n[dim]Metadata comes from the Rego `# METADATA` annotations, so the "
        "catalogue cannot drift from the policies it describes.[/]"
    )
    return 0


def cmd_coverage(args: argparse.Namespace, console: Console) -> int:
    catalogue = build(args.policies)
    for framework in catalogue.frameworks():
        covered = catalogue.controls_covered(framework)
        table = Table(
            title=f"{framework} — {len(covered)} control(s) enforced by "
            f"{len({p.id for ps in covered.values() for p in ps})} policies",
            title_style="bold", header_style="dim",
        )
        table.add_column("control", style="bold")
        table.add_column("enforced by", style="cyan")
        table.add_column("severity")
        for control in sorted(covered):
            policies = covered[control]
            worst = max(policies, key=lambda p: p.severity_rank)
            table.add_row(
                control,
                ", ".join(p.id for p in policies),
                Text(worst.severity, style=SEVERITY_STYLE.get(worst.severity, "white")),
            )
        console.print(table)
        console.print()

    console.print(
        "[dim]Coverage means a control has a policy, not that the control is "
        "satisfied — a mapped control with a policy nobody runs is still a gap.[/]"
    )
    return 0


def cmd_validate(args: argparse.Namespace, console: Console) -> int:
    ok, output = check(args.policies, strict=True)
    if not ok:
        console.print("[bold red]opa check --strict failed:[/]")
        console.print(output)
        return 1
    console.print("[green]OK[/]   opa check --strict")

    catalogue = build(args.policies)
    console.print(
        f"[green]OK[/]   {len(catalogue)} policies parsed from their annotations"
    )

    problems = validate(catalogue, args.policies)
    if problems:
        for problem in problems:
            console.print(f"[bold red]FAIL[/] {problem}")
        return 1
    console.print("[green]OK[/]   every policy has a title, description, remediation,")
    console.print("[green]  [/]   a severity, at least one framework mapping and a test file")

    result = run_tests(args.policies)
    if not result.ok:
        console.print(f"[bold red]FAIL[/] {result.failed} test(s) failed:")
        for failure in result.failures:
            console.print(f"       {failure}")
        return 1
    console.print(f"[green]OK[/]   opa test: {result.passed} assertions pass")
    console.print("\n[bold green]catalogue is sound[/]")
    return 0


def cmd_test(args: argparse.Namespace, console: Console) -> int:
    result = run_tests(args.policies)
    style = "green" if result.ok else "bright_red"
    console.print(
        Panel(
            Text.assemble(
                (f"{result.passed} passed", style),
                ("  ", ""),
                (f"{result.failed} failed", "bright_red" if result.failed else "dim"),
            ),
            title="opa test",
            border_style="green" if result.ok else "red",
            expand=False,
        )
    )
    if result.failures:
        for failure in result.failures:
            console.print(f"  [bright_red]FAIL[/] {failure}")
        return 1
    return 0


def cmd_eval(args: argparse.Namespace, console: Console) -> int:
    catalogue = build(args.policies)
    paths: list[str] = []
    for raw in args.manifest:
        path = Path(raw)
        if path.is_dir():
            paths.extend(
                str(p) for p in sorted(path.rglob("*"))
                if p.suffix in (".yaml", ".yml", ".json")
            )
        else:
            paths.append(str(path))

    result = evaluate(paths, catalogue, policy_dir=args.policies)

    header = Text()
    header.append(f"{result.documents} document(s) from {len(result.files)} file(s)\n", style="dim")
    if result.clean:
        header.append("no policy denied anything", style="bold green")
    else:
        header.append(f"{len(result.denials)} denial(s)", style="bold bright_red")
        if result.warnings:
            header.append(f"   {len(result.warnings)} warning(s)", style="yellow")
    console.print(Panel(header, title="pach eval", border_style="blue", expand=False))

    if result.violations:
        table = Table(header_style="dim")
        table.add_column("policy", style="bold")
        table.add_column("sev")
        table.add_column("resource", style="cyan")
        table.add_column("what is wrong", overflow="fold")
        table.add_column("fix", style="dim", overflow="fold")
        for violation in result.violations[: args.limit]:
            table.add_row(
                violation.policy.id if violation.policy else violation.package,
                Text(violation.severity, style=SEVERITY_STYLE.get(violation.severity, "white")),
                violation.resource,
                violation.message,
                violation.policy.remediation if violation.policy else "",
            )
        console.print(table)
        if len(result.violations) > args.limit:
            console.print(f"[dim]... and {len(result.violations) - args.limit} more[/]")

    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]wrote {args.json}[/]")

    return 0 if result.clean else 1


def cmd_bundle(args: argparse.Namespace, console: Console) -> int:
    result = run_tests(args.policies)
    if not result.ok and not args.force:
        console.print(
            f"[bold red]refusing to bundle:[/] {result.failed} test(s) fail. "
            "A bundle is what reaches an admission controller — pass --force only "
            "if you mean it."
        )
        return 1

    path = build_bundle(args.policies, args.out, revision=args.revision)
    size = path.stat().st_size
    console.print(
        f"[green]built[/] {path} ({size // 1024} KB)"
        + (f" revision {args.revision}" if args.revision else "")
    )
    console.print(
        "[dim]serve it with `opa run --server --bundle`, or point an admission "
        "controller at it for hot reload without a redeploy[/]"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pach", description="A curated OPA policy library with framework mappings."
    )
    parser.add_argument("--version", action="version", version=f"pach {__version__}")
    parser.add_argument("--policies", default="policies", help="policy directory")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="show the catalogue and its mappings")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("coverage", help="which framework controls have a policy")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("validate", help="check the catalogue is sound")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("test", help="run the Rego test suite")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("eval", help="evaluate manifests against the policies")
    p.add_argument("manifest", nargs="+")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--json", help="write the result here")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("bundle", help="build a distributable OPA bundle")
    p.add_argument("--out", default="dist/policies.tar.gz")
    p.add_argument("--revision", default="")
    p.add_argument("--force", action="store_true", help="bundle even if tests fail")
    p.set_defaults(func=cmd_bundle)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return int(args.func(args, console))
    except OpaMissing as exc:
        console.print(f"[bold red]{exc}[/]")
        return 3
    except CatalogueError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

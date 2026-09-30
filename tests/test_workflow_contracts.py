"""Every script the qualification workflow invokes, checked against how it is invoked.

`qualify.yml` was missing `--child-dir` on its call to `verify.py`: a required
argument that argparse itself would refuse, that no local test caught, because
every local test calls these functions directly or through `run_entry`, never
through the literal shell command in the workflow file. This walks every
`add_argument(..., required=True)` in every anchor script, by source, and
confirms the exact flag string appears in the exact workflow step that invokes
it - mechanically, for every script and every subcommand, not only the one that
already failed.
"""

from __future__ import annotations

import ast
import shlex

import pytest
from support import ANCHOR, WORKFLOW

yaml = pytest.importorskip("yaml")


def _with_parents(tree: ast.AST) -> ast.AST:
    """`ast` gives no parent links; attach them once so a subparser's owning
    assignment (`builder = sub.add_parser("build")`) can be found from the call."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]
    return tree


def required_flags_of(script: str) -> dict[str | None, set[str]]:
    """subcommand (or None, for a script with none) -> the `--flag`s its parser
    requires. Read from the source, not imported: importing would run module-level
    code these scripts deliberately keep minimal, and the parser itself is built
    inside `main()`, not exposed as an object."""
    source = ANCHOR / script
    tree = _with_parents(
        ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    )
    subparser_of: dict[str, str] = {}
    required: dict[str | None, set[str]] = {None: set()}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if (
            node.func.attr == "add_parser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Assign) and isinstance(
                parent.targets[0], ast.Name
            ):
                subparser_of[parent.targets[0].id] = node.args[0].value
                required.setdefault(node.args[0].value, set())
        elif (
            node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            flag = node.args[0].value
            if not isinstance(flag, str) or not flag.startswith("--"):
                continue
            is_required = any(
                keyword.arg == "required"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if is_required and isinstance(node.func.value, ast.Name):
                owner = subparser_of.get(node.func.value.id)
                required.setdefault(owner, set()).add(flag)
    return required


def _flags_in(run_block: str) -> set[str]:
    tokens = shlex.split(run_block.replace("\\\n", " "), posix=True)
    return {token.split("=", 1)[0] for token in tokens if token.startswith("--")}


# (script, subcommand, the substring in a `run:` block that identifies its call site)
INVOCATIONS = [
    ("gate.py", None, "anchor/anchor/gate.py"),
    ("capture.py", None, "anchor/anchor/capture.py"),
    ("sandbox.py", None, "anchor/anchor/sandbox.py"),
    ("verify.py", None, "anchor/anchor/verify.py"),
    ("preserve.py", "build", "preserve.py build"),
    ("preserve.py", "check", "preserve.py check"),
    ("publish.py", "audit", "publish.py audit"),
    ("publish.py", "check-digest", "publish.py check-digest"),
]


def _all_run_blocks() -> list[str]:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return [
        step["run"]
        for job in document["jobs"].values()
        for step in job["steps"]
        if "run" in step
    ]


@pytest.mark.parametrize("script,subcommand,marker", INVOCATIONS)
def test_every_required_argument_is_present_at_every_call_site(
    script, subcommand, marker
):
    required = required_flags_of(script)[subcommand]
    if not required:
        pytest.skip(f"{script} {subcommand or ''} declares no required flags")
    blocks = [block for block in _all_run_blocks() if marker in block]
    assert blocks, f"nothing in the workflow invokes {marker!r}"
    for block in blocks:
        if script == "gate.py" and "--identity-only" in block:
            # A different, smaller contract: --observation-out is a manual check
            # in main(), conditional on --identity-only, not one of argparse's
            # own required=True flags.
            continue
        missing = required - _flags_in(block)
        assert not missing, f"{marker} is missing required flags {sorted(missing)}"

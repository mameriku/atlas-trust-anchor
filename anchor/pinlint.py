"""Mechanical rules over the workflow files, checked as text.

These are text rules, not YAML semantics: nothing is parsed as YAML, because the
linter runs under -S and cannot import a YAML library. The rules are written so
that being wrong about the structure makes the lint noisier, never quieter.

Supply chain and injection:

  1. every `uses:` names a full 40-hex commit, so a moved tag cannot change what
     executes
  2. no `continue-on-error` anywhere, so a failing job stays failed
  3. no `${{ ... }}` inside a `run:` block, so a caller-supplied string is never
     spliced into a shell command

Public-repository disclosure - the rules this repository needs because its logs
and artifacts are world-readable and it judges something private:

  4. an `upload-artifact` step may upload only from `public/` or `attestation/`,
     both of which hold only anchor-built documents. This is the rule
     that makes the old failure - a private git bundle uploaded as an artifact -
     unwritable rather than merely absent
  5. no shell tracing and no environment dumps: `set -x`, `bash -x`, `printenv`,
     `env`, `export -p`, ACTIONS_STEP_DEBUG, ACTIONS_RUNNER_DEBUG
  6. a secret is only ever bound to an environment variable of one step
     (`NAME: ${{ secrets.NAME }}`); never inlined, never `secrets: inherit`, and
     never referenced in a workflow other than the qualification workflow
  7. no `docker` in a workflow: the only place a container is started is
     sandbox.py, whose command is audited
  8. no trigger that runs a workflow from a fork or a comment with secrets in
     reach: `pull_request_target`, `workflow_run`, `issue_comment`
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import publog

PINNED = re.compile(r"\A[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}\Z")
USES = re.compile(r"\A(\s*)-?\s*uses:\s*(\S+)")
RUN = re.compile(r"\A(\s*)-?\s*run:\s*(\S?)")
EXPRESSION = re.compile(r"\$\{\{")
UPLOAD = re.compile(r"upload-artifact@", re.IGNORECASE)
PATH_LINE = re.compile(r"\A\s*path:\s*(.*?)\s*\Z")
SECRET_REFERENCE = re.compile(r"secrets\s*(?:\.(?!GITHUB_TOKEN\b)|\[)|toJSON\(\s*secrets", re.IGNORECASE)
SECRET_BINDING = re.compile(
    r"\A\s+[A-Z][A-Z0-9_]*:\s*\$\{\{\s*secrets\.[A-Z][A-Z0-9_]*\s*\}\}\s*\Z"
)
TRACING = re.compile(
    r"(?<![\w-])(set\s+-[a-z]*x[a-z]*|bash\s+-[a-z]*x[a-z]*|xtrace|printenv|export\s+-p|"
    r"ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG)(?![\w-])"
)
BARE_ENV = re.compile(r"(?<![\w./-])env\s*(\||$|>)")
DOCKER = re.compile(r"(?<![\w./-])docker(?![\w-])", re.IGNORECASE)
CONTAINER_KEYS = re.compile(r"\A\s*(?:container|services)\s*:")
FLOW_STEP = re.compile(r"\A\s*-\s*\{")
YAML_ALIAS = re.compile(r"(?::\s*|-\s+)[&*][A-Za-z_][\w-]*\s*$|<<\s*:")
TEST_SEAM = re.compile(r"--(?:docker-command|source|uid|gid)\b")
EXPRESSION_BLOCK = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
SECRET_WORD = re.compile(r"\bsecrets\b", re.IGNORECASE)
FORBIDDEN_TRIGGER = re.compile(
    r"(?<![\w-])(pull_request_target|workflow_run|issue_comment)(?![\w-])"
)
SECRET_WORKFLOW = "qualify.yml"
PUBLIC_ROOTS = ("public", "attestation")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _step_block(lines: list[str], index: int) -> list[str]:
    """The lines of the workflow step that contains lines[index]."""
    start = index
    while start > 0:
        stripped = lines[start].strip()
        if stripped.startswith("- ") and _indent(lines[start]) <= _indent(lines[index]):
            break
        start -= 1
    base = _indent(lines[start])
    end = start + 1
    while end < len(lines):
        stripped = lines[end].strip()
        if stripped and (
            _indent(lines[end]) < base
            or (_indent(lines[end]) == base and stripped.startswith("- "))
        ):
            break
        end += 1
    return lines[start:end]


def _upload_problems(lines: list[str], index: int, name: str) -> list[str]:
    paths = [
        match.group(1).strip("\"'")
        for line in _step_block(lines, index)
        if (match := PATH_LINE.match(line))
    ]
    number = index + 1
    if len(paths) != 1:
        return [f"{name}:{number} an upload-artifact step must name exactly one path"]
    value = paths[0]
    if not any(value == root or value.startswith(root + "/") for root in PUBLIC_ROOTS):
        return [
            f"{name}:{number} upload-artifact uploads from outside {'/ or '.join(PUBLIC_ROOTS)}/; "
            "this repository is public and its artifacts are world-readable"
        ]
    return []


def problems_in(text: str, name: str) -> list[str]:
    found: list[str] = []
    lines = text.splitlines()
    run_indent: int | None = None
    secrets_allowed = Path(name).name == SECRET_WORKFLOW

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        commented = stripped.startswith("#")

        if run_indent is not None:
            indent = _indent(line)
            if stripped and indent <= run_indent:
                run_indent = None
            else:
                if EXPRESSION.search(line):
                    found.append(
                        f"{name}:{number} a workflow expression is spliced into a run block: "
                        f"{stripped[:60]}"
                    )
                if not commented and DOCKER.search(line):
                    found.append(f"{name}:{number} docker is started outside sandbox.py")

        if "continue-on-error" in stripped and not commented:
            found.append(f"{name}:{number} continue-on-error makes a failure non-terminal")

        match = USES.match(line)
        if match:
            reference = match.group(2).split("#")[0].strip().strip("\"'")
            if not PINNED.match(reference):
                found.append(
                    f"{name}:{number} action {reference!r} is not pinned to a full commit sha"
                )
            if UPLOAD.search(reference):
                found.extend(_upload_problems(lines, number - 1, name))

        run = RUN.match(line)
        if run and run_indent is None:
            run_indent = len(run.group(1))
            if EXPRESSION.search(line):
                found.append(
                    f"{name}:{number} a workflow expression is spliced into a run block: "
                    f"{stripped[:60]}"
                )

        if commented:
            continue
        if TRACING.search(line) or BARE_ENV.search(line):
            found.append(f"{name}:{number} a step traces the shell or dumps the environment")
        if FORBIDDEN_TRIGGER.search(line):
            found.append(f"{name}:{number} a trigger that can run with secrets in reach")
        if CONTAINER_KEYS.match(line):
            found.append(f"{name}:{number} a job container or service is a runtime this lint cannot audit")
        if FLOW_STEP.match(line) or YAML_ALIAS.search(line):
            found.append(f"{name}:{number} flow-style steps and YAML aliases hide what a step does from this lint")
        if TEST_SEAM.search(line):
            found.append(f"{name}:{number} a test seam (--docker-command, --source, --uid, --gid) must not appear in a workflow")
        if re.search(r"secrets:\s*inherit", stripped):
            found.append(f"{name}:{number} secrets: inherit hands every secret to another workflow")
        if SECRET_REFERENCE.search(line) and not (secrets_allowed and SECRET_BINDING.match(line)):
            found.append(
                f"{name}:{number} a secret is referenced other than as one step's environment binding"
            )

    # An expression can span lines, so it is judged whole: `toJSON(` at the end of one
    # line with `secrets) }}` on the next is one reference, however it is folded.
    for match in EXPRESSION_BLOCK.finditer(text):
        body = " ".join(match.group(1).split())
        if SECRET_WORD.search(body) and not re.fullmatch(r"secrets\.[A-Za-z_][A-Za-z0-9_]*", body, re.IGNORECASE):
            number = text.count("\n", 0, match.start()) + 1
            found.append(f"{name}:{number} a secret is referenced in a multi-part expression")
    return found


def main(argv: list[str]) -> int:
    roots = [Path(argument) for argument in argv] or [Path(".github/workflows")]
    files = sorted(
        path
        for root in roots
        for path in (
            [root] if root.is_file()
            else [*root.rglob("*.yml"), *root.rglob("*.yaml")]
        )
    )
    if not files:
        publog.emit("PINLINT", "REFUSE", "NOTHING_TO_CHECK")
        return 2

    found: list[str] = []
    for path in files:
        found.extend(problems_in(path.read_text(encoding="utf-8"), path.as_posix()))

    for problem in found:
        publog.emit_policy_refusal("PINLINT", "LINT_PROBLEM", problem)
    publog.emit(
        "PINLINT",
        "REFUSE" if found else "PASS",
        "LINT_FAILED" if found else None,
        files=len(files),
        problems=len(found),
    )
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(publog.guarded("PINLINT", main, sys.argv[1:]))

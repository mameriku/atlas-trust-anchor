"""The trusted phase: freeze what the candidate IS, before anything looks at it.

This is the only phase that holds the credential for the target, and the only one
that reads the target's object store. Everything it learns is written once, here,
so that the sandbox which looks at the candidate cannot later be the source of any
fact about it.

Order matters and is the point:

  1. identity, trigger and governance - all before the credential is touched
  2. fetch exactly the requested commit, then destroy the credential
  3. freeze the scope from the object store (mode, size, blob id, digest)
  4. export ONLY the scope, as plain regular files, for the sandbox to read

One record comes out: `capture.json`, the full freeze, which never leaves the
trusted directory. What may be published about it is built later from an
explicit allow-list (see disclosure.py), so a field added to the freeze here is
private until someone decides otherwise.

The freeze's sha256 is published as a step output. A step outside this one cannot
write it, so the verifier can tell the file it reads from one something else put
in its place.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, Mapping

# Isolated mode puts neither the script's directory nor the user's site-packages
# on sys.path, so the trusted directory is named here from this file's own
# resolved location - never from the environment, and never from the candidate.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import disclosure
import governance_record as anchor_governance
import policy as anchor_policy
import publog
import target
from policy import PolicyError
from publog import TargetError

_REGULAR_MODES = frozenset({"100644", "100755"})


def _tree_entry(environment: Mapping[str, str], repository: Path, commit: str, path: str):
    listing = target.run_git(
        environment, repository, "ls-tree", "-z", commit, "--", path, code="TARGET_TREE_UNREADABLE"
    )
    if not listing.strip():
        return None
    meta, _, name = listing.split(b"\0")[0].decode("utf-8").partition("\t")
    fields = meta.split()
    if len(fields) < 3 or fields[1] != "blob" or name != path:
        return None
    return fields[0], fields[2]


def freeze_input(
    environment: Mapping[str, str],
    repository: Path,
    commit: str,
    relative_path: str,
    limit: int,
) -> tuple[dict[str, object], bytes] | None:
    """The object store's account of one path, or None if it is not a usable input.

    "Not usable" is one answer for every reason: absent, a directory, a symlink, a
    submodule, or larger than policy allows. A symlink in the object store is a
    blob of mode 120000 whose content is a path; freezing it as if it were a file
    would let the candidate choose what a "file" contains by pointing elsewhere.
    """
    entry = _tree_entry(environment, repository, commit, relative_path)
    if entry is None or entry[0] not in _REGULAR_MODES:
        return None
    blob = entry[1]
    size = int(
        target.run_git(
            environment, repository, "cat-file", "-s", blob, code="TARGET_TREE_UNREADABLE"
        ).strip()
    )
    if size > limit:
        return None
    content = target.run_git(
        environment, repository, "cat-file", "blob", blob, code="TARGET_TREE_UNREADABLE"
    )
    return (
        {
            "relative_path": relative_path,
            "blob": blob,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        },
        content,
    )


def _remove_tree(path: Path) -> None:
    """Remove a directory even if git made its objects read-only."""

    def make_writable_and_retry(function: Any, target_path: str, _: Any) -> None:
        os.chmod(target_path, stat.S_IWRITE)
        function(target_path)

    shutil.rmtree(path, onerror=make_writable_and_retry)


def _export(scope_dir: Path, relative_path: str, content: bytes) -> None:
    destination = (scope_dir / relative_path).resolve()
    if scope_dir.resolve() not in destination.parents:
        raise TargetError("TARGET_EXPORT_ESCAPE", "a scope path left the export directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    os.chmod(destination, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def capture(
    environment: Mapping[str, str],
    repository: Path,
    candidate: str,
    scope: list[str],
    limit: int,
    scope_dir: Path,
) -> dict[str, object]:
    resolved = (
        target.run_git(
            environment,
            repository,
            "rev-parse",
            "--verify",
            f"{candidate}^{{commit}}",
            code="TARGET_IDENTITY_MISMATCH",
        )
        .decode("ascii", errors="replace")
        .strip()
    )
    if resolved != candidate:
        raise TargetError("TARGET_IDENTITY_MISMATCH", "resolved to another commit")
    tree = (
        target.run_git(
            environment,
            repository,
            "rev-parse",
            "--verify",
            f"{resolved}^{{tree}}",
            code="TARGET_IDENTITY_MISMATCH",
        )
        .decode("ascii", errors="replace")
        .strip()
    )

    scope_dir.mkdir(parents=True, exist_ok=True)
    frozen: list[dict[str, object]] = []
    absent: list[str] = []
    for relative_path in scope:
        found = freeze_input(environment, repository, resolved, relative_path, limit)
        if found is None:
            absent.append(relative_path)
            continue
        entry, content = found
        frozen.append(entry)
        _export(scope_dir, relative_path, content)
    return {
        "capture_version": disclosure.CAPTURE_VERSION,
        "candidate_sha": resolved,
        "candidate_tree": tree,
        "scope": list(scope),
        "inputs": frozen,
        "absent": absent,
    }


def _load_governance(path: Path, policy: Mapping[str, Any]) -> dict[str, Any]:
    try:
        observation = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PolicyError(
            f"the governance observation is unreadable: {type(error).__name__}"
        ) from error
    reasons = anchor_governance.acceptable(observation, policy)
    if reasons:
        raise PolicyError(f"the governance observation does not establish protection: {reasons}")
    return observation


def main(argv: list[str]) -> int:
    anchor_policy.assert_isolated()
    parser = publog.Parser("CAPTURE", "Freeze an Atlas candidate.")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--governance", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--inputs-manifest", required=True)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--scope-dir", required=True, type=Path)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--source")
    arguments = parser.parse_args(argv)

    try:
        policy = anchor_policy.load(arguments.policy)
        anchor_policy.assert_anchor_identity(policy, os.environ)
        anchor_policy.assert_full_sha(arguments.candidate, "candidate")
        scope = anchor_policy.effective_scope(policy, arguments.inputs_manifest)
        # Bound into the freeze, so a verdict cannot exist without a positive
        # governance observation carrying the same digest as everything else.
        observation = _load_governance(arguments.governance, policy)
    except PolicyError as error:
        publog.emit_policy_refusal("CAPTURE", "CAPTURE_REFUSED", str(error))
        return 2

    try:
        repository = target.fetch_candidate(
            policy, os.environ, arguments.candidate, arguments.workdir, arguments.source
        )
        environment = target.git_environment(arguments.workdir / "home", os.environ)
        record = capture(
            environment,
            repository,
            arguments.candidate,
            scope,
            policy["limits"]["max_input_bytes"],
            arguments.scope_dir,
        )
    except TargetError as error:
        publog.emit("CAPTURE", "REFUSE", error.code)
        return 2
    finally:
        # The object store has done its job. Less private data left on disk is
        # less to reason about, whatever happens next.
        if (arguments.workdir / "repo").exists():
            _remove_tree(arguments.workdir / "repo")

    record["governance"] = observation
    # The freeze's digest is printed to the log and echoed in a step's env header, and
    # everything else in the record is public or guessable. Without a secret in it, the
    # digest confirms a guess of any input the caller added; with 256 random bits it
    # binds the file without saying anything about its content.
    record["nonce"] = secrets.token_hex(32)
    payload = json.dumps(record, indent=2, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    arguments.capture.parent.mkdir(parents=True, exist_ok=True)
    arguments.capture.write_bytes(payload)

    outputs = os.environ.get("GITHUB_OUTPUT")
    if outputs:
        with open(outputs, "a", encoding="utf-8") as handle:
            handle.write(f"capture_digest={digest}\n")
    publog.emit(
        "CAPTURE",
        "PASS",
        None,
        scope=len(scope),
        capture_digest=digest,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(publog.guarded("CAPTURE", main, sys.argv[1:]))

"""The last step before anything becomes public - and the first step after.

`audit` runs in the job that holds private bytes, immediately before upload. It
refuses unless the directory is exactly the allow-listed set of documents, each
with exactly its allow-listed keys, and none of the private files just exported
- nor any long line of them - appears in any of them. On success it publishes one
digest of the directory as a step output, which a later job cannot forge.

`check-digest` runs in the job that holds no private bytes and is about to sign
something. It recomputes that digest from what it downloaded and refuses a
mismatch, so the signature covers the directory the trusted job produced and not
whatever an artifact of the same name happens to contain by then.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import disclosure
import policy as anchor_policy
import publog
from policy import PolicyError


def _private_tokens(arguments: argparse.Namespace) -> frozenset[str] | None:
    """The hashes of every input the caller added: values that must never be public."""
    if arguments.capture is None or arguments.policy is None:
        return None
    try:
        policy = anchor_policy.load(arguments.policy)
        capture = json.loads(arguments.capture.read_text(encoding="utf-8"))
        return disclosure.extra_digests(capture, policy)
    except (PolicyError, OSError, ValueError, AttributeError):
        return None


def _audit(arguments: argparse.Namespace) -> int:
    tokens: frozenset[str] | None = frozenset()
    if arguments.private_dir is not None:
        # With a private directory to compare against, the record of what the
        # caller's extras hash to is required too: an audit that quietly skipped
        # half its comparison for want of a file would be a guard that fails open.
        tokens = _private_tokens(arguments)
    if tokens is None:
        publog.emit("PUBLISH", "REFUSE", "PRIVATE_INPUTS_INCOMPLETE")
        return 1
    problems = disclosure.audit_public_directory(arguments.public_dir, arguments.private_dir, tokens)
    for problem in problems:
        publog.emit("PUBLISH", "INFO", problem)
    if problems:
        publog.emit("PUBLISH", "REFUSE", problems[0], problems=len(problems))
        return 1
    digest = disclosure.digest_directory(arguments.public_dir)
    outputs = os.environ.get("GITHUB_OUTPUT")
    if outputs:
        with open(outputs, "a", encoding="utf-8") as handle:
            handle.write(f"public_digest={digest}" + chr(10))
    publog.emit("PUBLISH", "PASS", None, public_digest=digest)
    return 0


def _check_digest(arguments: argparse.Namespace) -> int:
    problems = disclosure.audit_public_directory(arguments.public_dir, None)
    if not problems and disclosure.digest_directory(arguments.public_dir) != arguments.digest:
        problems = ["PUBLIC_DIGEST_MISMATCH"]
    for problem in problems:
        publog.emit("PUBLISH", "REFUSE", problem)
    if not problems:
        publog.emit("PUBLISH", "PASS", None, public_digest=arguments.digest)
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    parser = publog.Parser("PUBLISH", "Audit and bind the public directory.")
    sub = parser.add_subparsers(
        dest="action", required=True, parser_class=functools.partial(publog.Parser, "PUBLISH")
    )

    audit = sub.add_parser("audit")
    audit.add_argument("--public-dir", required=True, type=Path)
    audit.add_argument("--private-dir", type=Path)
    audit.add_argument("--capture", type=Path)
    audit.add_argument("--policy", type=Path)

    check = sub.add_parser("check-digest")
    check.add_argument("--public-dir", required=True, type=Path)
    check.add_argument("--digest", required=True)

    arguments = parser.parse_args(argv)
    return _audit(arguments) if arguments.action == "audit" else _check_digest(arguments)


if __name__ == "__main__":
    raise SystemExit(publog.guarded("PUBLISH", main, sys.argv[1:]))

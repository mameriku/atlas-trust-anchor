"""The child: observes the candidate and writes evidence. It has no verdict to give.

This is the only code that ever touches candidate bytes, and it runs inside the
sandbox: no network, no credential, no host directory but the three it was
handed, one writable place. It is the anchor's own code, but it executes beside
the candidate, so nothing it says is believed on its own - the verifier compares
every claim with a freeze made earlier, outside the sandbox, from the object store.

What it must never do is decide. Neither of the two words that carry a verdict
appears anywhere in this file, and a test asserts they never will - including in
this sentence, which is why it does not name them. Every previous version of this
machinery put the answer in the child, and every one was defeated by editing the
child.

It reads regular files from a read-only tree and re-derives the git blob id of
what it read. It never opens a git repository: parsing an object store the
candidate influenced is exactly the kind of work that should not happen where the
candidate is.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

# Isolated mode puts neither the script's directory nor the user's site-packages
# on sys.path, so the trusted directory is named here from this file's own
# resolved location - never from the environment, and never from the candidate.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import policy as anchor_policy

EVIDENCE_VERSION = "atlas-anchor-evidence/2"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class ObservationError(RuntimeError):
    """One input could not be read as asked. `reason` is a fixed word, not a message."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def blob_id(content: bytes) -> str:
    """The id git gives these bytes as a blob, computed here rather than asked of git."""
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _walk_to_file(root: Path, relative_path: str) -> Path:
    """The path to a regular file under root, refusing every symlink on the way."""
    current = root
    segments = relative_path.split("/")
    for index, segment in enumerate(segments):
        current = current / segment
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            raise ObservationError("ABSENT") from None
        except OSError:
            raise ObservationError("UNREADABLE") from None
        last = index == len(segments) - 1
        if stat.S_ISLNK(status.st_mode):
            raise ObservationError("NOT_REGULAR")
        if last and not stat.S_ISREG(status.st_mode):
            raise ObservationError("NOT_REGULAR")
        if not last and not stat.S_ISDIR(status.st_mode):
            raise ObservationError("NOT_REGULAR")
    return current


def observe_input(root: Path, relative_path: str, limit: int) -> dict[str, object]:
    """One candidate file, identified by the blob id and digest of the bytes read."""
    path = _walk_to_file(root, relative_path)
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY | _NONBLOCK)
    except OSError:
        raise ObservationError("UNREADABLE") from None
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ObservationError("NOT_REGULAR")
        if status.st_size > limit:
            raise ObservationError("TOO_LARGE")
        # Until EOF: a single os.read() may return fewer bytes than the file holds.
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 16, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ObservationError("TOO_LARGE")
        content = b"".join(chunks)
    except OSError:
        raise ObservationError("UNREADABLE") from None
    finally:
        os.close(descriptor)
    return {
        "relative_path": relative_path,
        "blob": blob_id(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def observe(
    root: Path, candidate: str, tree: str, required: list[str], limit: int
) -> dict[str, object]:
    """Facts about the candidate. Note the absence of any word that decides."""
    observed: list[dict[str, object]] = []
    unreadable: list[dict[str, str]] = []
    for relative_path in required:
        try:
            observed.append(observe_input(root, relative_path, limit))
        except ObservationError as error:
            unreadable.append({"relative_path": relative_path, "reason": error.reason})
    return {
        "evidence_version": EVIDENCE_VERSION,
        "candidate_sha": candidate,
        "candidate_tree": tree,
        "inputs_requested": list(required),
        "inputs_observed": observed,
        "inputs_unreadable": unreadable,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Observe an Atlas candidate.")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--inputs-manifest", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    arguments = parser.parse_args(argv)

    anchor_policy.assert_isolated()
    try:
        policy = anchor_policy.load(arguments.policy)
        required = anchor_policy.effective_scope(policy, arguments.inputs_manifest)
    except anchor_policy.PolicyError:
        return 3
    evidence = observe(
        arguments.root,
        arguments.candidate,
        arguments.tree,
        required,
        policy["limits"]["max_input_bytes"],
    )

    # One channel, at the path the host named. Anything else this process writes
    # is not evidence, because nothing downstream reads it.
    descriptor = os.open(
        arguments.evidence,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY,
        0o644,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(json.dumps(evidence, indent=2).encode("utf-8"))
    unreadable = evidence["inputs_unreadable"]
    assert isinstance(unreadable, list)
    return 0 if not unreadable else 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

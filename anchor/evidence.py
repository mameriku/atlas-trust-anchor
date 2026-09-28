"""The evidence directory: everything the candidate side wrote, all of it a claim.

The sandbox is given exactly one place to write. What comes back from it is
hostile bytes in a hostile directory, so this module does two separate things and
keeps them separate: it decides whether the directory has the SHAPE it may have,
and it decides whether the one file inside is a document of the shape it may
carry. It decides nothing about whether the claims are TRUE - the verifier
compares them with the frozen capture for that.

Nothing here returns text taken from the evidence. Every problem is a fixed code.
A malformed field, a filename, a JSON fragment, an error message a parser was
about to quote: none of it is ever formatted into a return value, because the
return values are what end up in a public log.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVIDENCE_VERSION = "atlas-anchor-evidence/2"
FILENAME = "evidence.json"

_MAX_DIRECTORY_ENTRIES = 64
_MAX_PATH_LENGTH = 512
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_BLOB = re.compile(r"\A[0-9a-f]{40}\Z")
_FULL_SHA = re.compile(r"\A[0-9a-f]{40}\Z")

TOP_KEYS = frozenset(
    {
        "evidence_version",
        "candidate_sha",
        "candidate_tree",
        "inputs_requested",
        "inputs_observed",
        "inputs_unreadable",
    }
)
OBSERVATION_KEYS = frozenset({"relative_path", "blob", "sha256", "size"})
UNREADABLE_KEYS = frozenset({"relative_path", "reason"})
UNREADABLE_REASONS = frozenset({"ABSENT", "NOT_REGULAR", "TOO_LARGE", "UNREADABLE"})

# Fields that only the anchor may say. A candidate that supplies one is not
# confused, it is claiming an authority it does not have, and that is reported as
# its own code so a reader can tell a typo from an attempt.
AUTHORITY_KEYS = frozenset(
    {
        "verdict",
        "accept",
        "refuse",
        "result",
        "anchor",
        "governance",
        "repository_id",
        "workflow_ref",
        "workflow_sha",
        "policy",
        "capture",
        "capture_digest",
        "authority",
        "approved",
        "attestation",
        "signature",
    }
)


@dataclass(frozen=True)
class Read:
    """What the directory yielded. `evidence` is None whenever `problems` is not empty."""

    evidence: dict[str, Any] | None
    problems: tuple[str, ...]
    digest: str | None
    size: int


class _DuplicateKey(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _DuplicateKey
    return dict(pairs)


def _reject_constant(_: str) -> Any:
    raise ValueError("a non-finite number")


def _refuse(*problems: str) -> Read:
    return Read(None, tuple(dict.fromkeys(problems)), None, 0)


def _inspect_directory(directory: Path) -> list[str]:
    """Problems with the shape of the directory itself, before any file is opened."""
    try:
        status = os.lstat(directory)
    except OSError:
        return ["EVIDENCE_MISSING"]
    if stat.S_ISLNK(status.st_mode):
        return ["EVIDENCE_SYMLINK"]
    if not stat.S_ISDIR(status.st_mode):
        return ["EVIDENCE_NOT_DIRECTORY"]

    problems: list[str] = []
    seen = 0
    found = False
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                seen += 1
                if seen > _MAX_DIRECTORY_ENTRIES:
                    problems.append("EVIDENCE_TOO_MANY_FILES")
                    break
                if entry.name != FILENAME:
                    problems.append("EVIDENCE_UNEXPECTED_FILE")
                elif entry.is_symlink():
                    problems.append("EVIDENCE_SYMLINK")
                elif not entry.is_file(follow_symlinks=False):
                    problems.append("EVIDENCE_NOT_REGULAR")
                else:
                    found = True
    except OSError:
        return ["EVIDENCE_UNREADABLE"]
    if not found and not problems:
        problems.append("EVIDENCE_MISSING")
    return problems


def _read_file(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    # O_NONBLOCK: a FIFO swapped in for the file must not be able to hang the verifier
    # in open(); the S_ISREG check below then refuses it.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "EVIDENCE_UNREADABLE"
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            return None, "EVIDENCE_NOT_REGULAR"
        if status.st_size > limit:
            return None, "EVIDENCE_OVERSIZED"
        # Until EOF: one os.read() may return fewer bytes than the file holds, and a
        # truncated read is not the document.
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 16, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return None, "EVIDENCE_OVERSIZED"
        payload = b"".join(chunks)
    except OSError:
        return None, "EVIDENCE_UNREADABLE"
    finally:
        os.close(descriptor)
    return payload, None


def read_directory(directory: Path, limit: int) -> Read:
    """The evidence document, or fixed codes saying why there is none."""
    shape = _inspect_directory(directory)
    if shape:
        return _refuse(*shape)

    payload, problem = _read_file(directory / FILENAME, limit)
    if payload is None:
        return _refuse(problem or "EVIDENCE_UNREADABLE")

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return _refuse("EVIDENCE_ENCODING")
    try:
        document = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except _DuplicateKey:
        return _refuse("EVIDENCE_DUPLICATE_KEY")
    except (ValueError, RecursionError):
        return _refuse("EVIDENCE_MALFORMED")
    if not isinstance(document, dict):
        return _refuse("EVIDENCE_NOT_OBJECT")

    problems = validate(document)
    if problems:
        return _refuse(*problems)
    return Read(document, (), hashlib.sha256(payload).hexdigest(), len(payload))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bounded_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_PATH_LENGTH
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)
    )


def _validate_observation(record: Any) -> list[str]:
    if not isinstance(record, dict) or set(record) != OBSERVATION_KEYS:
        return ["EVIDENCE_OBSERVATION_SHAPE"]
    if (
        not _bounded_text(record["relative_path"])
        or not isinstance(record["blob"], str)
        or not _BLOB.match(record["blob"])
        or not isinstance(record["sha256"], str)
        or not _SHA256.match(record["sha256"])
        or not _is_int(record["size"])
        or record["size"] < 0
    ):
        return ["EVIDENCE_OBSERVATION_TYPES"]
    return []


def _validate_unreadable(record: Any) -> list[str]:
    if not isinstance(record, dict) or set(record) != UNREADABLE_KEYS:
        return ["EVIDENCE_UNREADABLE_SHAPE"]
    if not _bounded_text(record["relative_path"]) or record["reason"] not in UNREADABLE_REASONS:
        return ["EVIDENCE_UNREADABLE_SHAPE"]
    return []


def validate(document: dict[str, Any]) -> list[str]:
    """Fixed codes for every way this document is not of the shape it may have."""
    problems: list[str] = []
    keys = set(document)
    unknown = keys - TOP_KEYS
    if unknown & AUTHORITY_KEYS:
        problems.append("EVIDENCE_AUTHORITY_FIELD")
    if unknown - AUTHORITY_KEYS:
        problems.append("EVIDENCE_UNKNOWN_FIELD")
    if TOP_KEYS - keys:
        problems.append("EVIDENCE_FIELD_MISSING")
    if problems:
        return problems

    if document["evidence_version"] != EVIDENCE_VERSION:
        problems.append("EVIDENCE_VERSION")
    for name in ("candidate_sha", "candidate_tree"):
        value = document[name]
        if not isinstance(value, str) or not _FULL_SHA.match(value):
            problems.append("EVIDENCE_IDENTITY_TYPES")

    requested = document["inputs_requested"]
    if not isinstance(requested, list) or not all(_bounded_text(item) for item in requested):
        problems.append("EVIDENCE_SCOPE_TYPES")

    for name, check in (
        ("inputs_observed", _validate_observation),
        ("inputs_unreadable", _validate_unreadable),
    ):
        records = document[name]
        if not isinstance(records, list):
            problems.append("EVIDENCE_LIST_TYPES")
            continue
        for record in records:
            problems.extend(check(record))
    return list(dict.fromkeys(problems))

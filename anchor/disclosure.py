"""What may leave the runner, defined once, and checked at the door.

A public repository publishes its artifacts to anyone. The design therefore has
exactly one thing that is allowed to cross that boundary: a small directory of
JSON documents built by the anchor from fields the anchor chose. This module is
the single definition of those documents and the last check before upload.

Two mechanisms, deliberately different in kind:

  ALLOW-LIST   each public document has an exact set of top-level keys and the
               directory has an exact set of file names. A field nobody listed
               cannot be published, however it got into a record. The projection
               of a freeze is CONSTRUCTED from listed fields; nothing is filtered
               out of a private record, because a filter fails open on the field
               it did not anticipate.

  TRIPWIRE     the runner still holds the private files it just exported. Before
               upload, none of them - and none of their long lines - may appear in
               any public document, raw or JSON-escaped, and no digest of an input
               the caller added may appear at all. This is not what keeps the
               boundary; the allow-list is. It exists so that a mistake in the
               allow-list shows up as a refused run rather than as a disclosure.

One rule about what a public value may be derived from. A digest is a promise that
someone holding the content can check it, which makes it an oracle for anyone who
can GUESS the content: a small file such as a PIN or a token is confirmed, not
protected, by publishing its sha256 - or by publishing any hash of a structure that
contains its sha256. So only inputs the anchor's own public policy names (the
floor, which is source code) are ever described by digest. An input the caller
added is described by nothing but a count: no path, no digest, and not even whether
it exists, because "this path is present" is itself a fact about a private repository.

Neither mechanism returns text taken from a file. Both return fixed codes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

CAPTURE_VERSION = "atlas-anchor-capture/2"
PUBLIC_CAPTURE_VERSION = "atlas-anchor-public-capture/3"
VERDICT_VERSION = "atlas-anchor-verdict/3"
PACKAGE_VERSION = "atlas-anchor-evidence-package/3"
EVIDENCE_VIEW_VERSION = "atlas-anchor-evidence-view/1"

PUBLIC_CAPTURE_KEYS = frozenset(
    {
        "capture_version",
        "candidate_sha",
        "candidate_tree",
        "floor_scope",
        "floor_inputs",
        "floor_absent",
        "extra_scope_count",
        "governance",
    }
)
VERDICT_KEYS = frozenset(
    {
        "verdict_version",
        "verdict",
        "reasons",
        "candidate_sha",
        "candidate_tree",
        "required_floor",
        "extra_inputs_requested",
        "public_capture_digest",
        "evidence_view_digest",
        "capture_result",
        "sandbox",
        "anchor",
        "runner",
        "governance",
        "policy_digest",
        "verifier",
        "interpreter",
    }
)
PACKAGE_KEYS = frozenset(
    {
        "evidence_version",
        "verdict",
        "verdict_reasons",
        "candidate_sha",
        "candidate_tree",
        "required_floor",
        "extra_inputs_requested",
        "anchor",
        "runner",
        "sandbox",
        "public_capture_digest",
        "evidence_view_digest",
        "policy_digest",
        "verifier",
        "anchor_tree_digest",
        "governance",
        "files",
        "evidence_digest",
    }
)

MEMBERS = ("verdict.json", "public-capture.json", "policy.json", "anchor-tree.tar")

# The whole public surface. Anything else in the directory is a refusal.
PUBLIC_FILES: dict[str, frozenset[str] | None] = {
    "verdict.json": VERDICT_KEYS,
    "public-capture.json": PUBLIC_CAPTURE_KEYS,
    "evidence.json": PACKAGE_KEYS,
    "policy.json": None,  # the anchor's own policy, already public in its tree
    "anchor-tree.tar": None,  # `git archive` of this public repository
}

_MIN_TRIPWIRE = 32
_MAX_TRIPWIRE_LINES = 20000


def _canonical(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def floor_of(policy: Mapping[str, Any]) -> list[str]:
    return list(policy["required_inputs_floor"])


def split_scope(policy: Mapping[str, Any], scope: Iterable[str]) -> tuple[list[str], list[str]]:
    """The scope's floor paths (public, from policy) and its extras (the caller's)."""
    floor = set(floor_of(policy))
    scope = list(scope)
    return [path for path in scope if path in floor], [path for path in scope if path not in floor]


def public_projection(record: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """What may be published about a freeze, built from the fields policy approves.

    Nothing about an input the caller added survives except how many were asked for:
    not its path, not any digest of it, and not a count of how many were found - a
    "1 found, 0 absent" beside a single extra path would publish that path's
    existence. (The verdict itself still says whether every input was present; that
    is what a verdict is for, and it cannot be hidden without hiding the verdict.)
    The freeze's own digest is not published either, because it is a hash of a
    structure that contains every input's digest and is exactly as good an oracle
    as they are.
    """
    floor_scope, extras = split_scope(policy, record["scope"])
    floor = set(floor_of(policy))
    publish_digests = policy["disclosure"]["publish_floor_digests"]
    floor_inputs: list[dict[str, object]] = []
    for entry in record["inputs"]:
        if entry["relative_path"] in floor:
            floor_inputs.append(
                dict(entry) if publish_digests else {"relative_path": entry["relative_path"]}
            )
    absent = list(record["absent"])
    return {
        "capture_version": PUBLIC_CAPTURE_VERSION,
        "candidate_sha": record["candidate_sha"],
        "candidate_tree": record["candidate_tree"],
        "floor_scope": floor_scope,
        "floor_inputs": floor_inputs,
        "floor_absent": [path for path in absent if path in floor],
        "extra_scope_count": len(extras),
        "governance": record["governance"],
    }


def evidence_view(evidence: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """The part of the child's evidence that may be committed to publicly.

    Floor observations are described in full (their digests are public by policy);
    everything else in the evidence contributes nothing but the size of what was asked.
    """
    floor = set(floor_of(policy))
    observed = evidence["inputs_observed"]
    return {
        "view_version": EVIDENCE_VIEW_VERSION,
        "evidence_version": evidence["evidence_version"],
        "candidate_sha": evidence["candidate_sha"],
        "candidate_tree": evidence["candidate_tree"],
        "floor_observed": sorted(
            (
                dict(entry) if policy["disclosure"]["publish_floor_digests"]
                else {"relative_path": entry["relative_path"]}
                for entry in observed
                if entry["relative_path"] in floor
            ),
            key=lambda entry: entry["relative_path"],
        ),
        # Only what was ASKED for. How many were found, or unreadable, would say whether
        # a single extra input exists, exactly as the projection's counts would.
        "requested_count": len(evidence["inputs_requested"]),
    }


def evidence_view_digest(evidence: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(evidence_view(evidence, policy))).hexdigest()


def extra_digests(record: Mapping[str, Any], policy: Mapping[str, Any]) -> frozenset[str]:
    """Every hash of an input the caller added - the values that must never appear."""
    floor = set(floor_of(policy))
    tokens: set[str] = set()
    for entry in record.get("inputs", []):
        if entry.get("relative_path") not in floor:
            tokens.update(value for value in (entry.get("sha256"), entry.get("blob")) if value)
    return frozenset(tokens)


def digest_directory(directory: Path) -> str:
    """One digest over a directory's file names and content digests."""
    lines = []
    for path in sorted(directory.iterdir(), key=lambda entry: entry.name):
        lines.append(f"{path.name}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def _candidate_lines(content: bytes) -> set[bytes]:
    lines: set[bytes] = set()
    for raw in content.splitlines()[:_MAX_TRIPWIRE_LINES]:
        stripped = raw.strip()
        if len(stripped) >= _MIN_TRIPWIRE:
            lines.add(stripped)
    return lines


def _strings(value: Any) -> Iterable[str]:
    """Every string in a parsed document, keys and values, exactly as decoded.

    The tripwire compares private lines with these, not with the document's
    SERIALISED text. Serialised, a private line such as `"scripts/x.py",` is found
    inside `"relative_path": "scripts/x.py",` - punctuation that belongs to the
    document, around a value that is public by design - and a run would be refused for
    a match that discloses nothing. Decoded, a private line has to be text that the
    document actually carries; JSON escaping (a quote, a backslash, non-ASCII) is
    undone first, so it cannot be used to hide one either.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from _strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _strings(inner)


def _tripped(texts: list[str], reference: bytes, content: bytes) -> bool:
    """Does any private fragment appear in a public document?

    A fragment that also appears in the anchor's own public policy or tree is public
    already, so seeing it in a document is not a disclosure. Without that exception a
    floor file containing a line that quotes its own path - which policy.json also
    contains - would refuse every run until the file changed.
    """
    fragments = _candidate_lines(content)
    if len(content) >= _MIN_TRIPWIRE:
        fragments.add(content)
    for fragment in fragments:
        if fragment in reference:
            continue
        try:
            decoded = fragment.decode("utf-8")
        except UnicodeDecodeError:
            # Not text, so it cannot have been carried by a JSON string as itself.
            continue
        if any(decoded in text for text in texts):
            return True
    return False


def audit_public_directory(
    directory: Path,
    private_directory: Path | None,
    private_tokens: Iterable[str] = (),
) -> list[str]:
    """Fixed codes for everything wrong with what is about to be uploaded."""
    problems: list[str] = []
    if not directory.is_dir():
        return ["PUBLIC_DIRECTORY_MISSING"]
    entries = {path.name: path for path in directory.iterdir()}
    if set(entries) != set(PUBLIC_FILES):
        problems.append("PUBLIC_FILE_SET")
    documents: list[bytes] = []
    texts: list[str] = []
    reference = b""
    for name, path in entries.items():
        if name not in PUBLIC_FILES:
            continue
        if path.is_symlink() or not path.is_file():
            problems.append("PUBLIC_NOT_REGULAR")
            continue
        content = path.read_bytes()
        keys = PUBLIC_FILES[name]
        if keys is None:
            reference += content
            continue
        try:
            document = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            problems.append("PUBLIC_MALFORMED")
            continue
        if not isinstance(document, dict) or set(document) != keys:
            problems.append("PUBLIC_SCHEMA")
            continue
        documents.append(content)
        texts.append(chr(10).join(_strings(document)))

    if private_directory is not None:
        if not private_directory.is_dir():
            # The tripwire compares against the private files. With none to compare
            # against it would pass by default, and a guard that passes when it has
            # nothing to check is not one.
            problems.append("PRIVATE_DIRECTORY_MISSING")
        else:
            for private in sorted(private_directory.rglob("*")):
                if private.is_file() and _tripped(texts, reference, private.read_bytes()):
                    problems.append("DISCLOSURE_TRIPWIRE")
                    break
    for token in private_tokens:
        if any(token.encode("ascii") in document for document in documents):
            problems.append("DISCLOSURE_TRIPWIRE")
            break
    return list(dict.fromkeys(problems))

"""Bind one authoritative run into a package that outlives the workflow run.

Artifacts expire, and the anchor is only as immutable as its branch protection.
So the evidence is bound here, while it is still true, into something that does
not depend on the repository staying honest afterwards: the verdict, the run
identity that produced it, the public account of the freeze it judged, the policy
in force, the governance that was observed, the box the candidate ran in, and an
archive of the anchor tree at the exact commit that ran. Every member is carried
by content digest.

The package is built only from PUBLIC members. It never contains the private
freeze, only the projection of it that disclosure.py approves, and its schema is
the exact key set defined there.

What `check` can and cannot say. The seal is an unkeyed hash: anyone who edits the
package can recompute it, so a seal proves nothing about WHO made a package. What
`check` establishes is CONSISTENCY - the package has exactly the members it must,
each matches its recorded digest, and every field of the package agrees with the
verdict and public capture it claims to summarise, so a flipped `verdict` or a
swapped candidate is caught even after a reseal. Authenticity is the attestation
over `verdict.json`, made by GitHub's signer, and nothing in this file replaces it.

This is not a second judge. It re-decides nothing and can turn no REFUSE into an
ACCEPT, and it answers offline: no network, no repository, no GitHub.
"""

from __future__ import annotations

import functools
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

import disclosure
import policy as anchor_policy
import publog
from policy import PolicyError

_ANCHOR_FIELDS = ("repository_id", "repository", "workflow_ref", "workflow_sha", "run_id", "run_attempt")


def digest(path: Path) -> str:
    reader = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            reader.update(block)
    return reader.hexdigest()


def _load(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PolicyError(f"{what} is unreadable: {type(error).__name__}") from error


def _seal(package: Mapping[str, Any]) -> str:
    without = {key: value for key, value in package.items() if key != "evidence_digest"}
    return hashlib.sha256(
        json.dumps(without, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def build(
    verdict_path: Path,
    public_capture_path: Path,
    policy_path: Path,
    anchor_archive: Path,
) -> dict[str, Any]:
    """One package binding everything the verdict rests on."""
    verdict = _load(verdict_path, "the verdict")
    public_capture = _load(public_capture_path, "the public capture")
    if not isinstance(verdict, dict) or not isinstance(public_capture, dict):
        raise PolicyError("the verdict and the public capture must both be objects")
    if not anchor_archive.is_file():
        raise PolicyError("the anchor archive is missing")

    anchor = verdict.get("anchor") or {}
    if verdict.get("public_capture_digest") != digest(public_capture_path):
        raise PolicyError(
            "the verdict names a public capture digest that this file does not have"
        )
    if verdict.get("candidate_sha") != public_capture.get("candidate_sha"):
        raise PolicyError("the verdict and the capture describe different candidates")
    if verdict.get("policy_digest") != digest(policy_path):
        raise PolicyError("the verdict was made under a different policy than this one")

    package: dict[str, Any] = {
        "evidence_version": disclosure.PACKAGE_VERSION,
        "verdict": verdict.get("verdict"),
        "verdict_reasons": verdict.get("reasons"),
        "candidate_sha": verdict.get("candidate_sha"),
        "candidate_tree": public_capture.get("candidate_tree"),
        "required_floor": verdict.get("required_floor"),
        "extra_inputs_requested": verdict.get("extra_inputs_requested"),
        "anchor": {field: anchor.get(field) for field in _ANCHOR_FIELDS},
        "runner": verdict.get("runner"),
        "sandbox": verdict.get("sandbox"),
        "public_capture_digest": verdict.get("public_capture_digest"),
        "evidence_view_digest": verdict.get("evidence_view_digest"),
        "policy_digest": digest(policy_path),
        "verifier": verdict.get("verifier"),
        "anchor_tree_digest": digest(anchor_archive),
        "governance": public_capture.get("governance"),
        "files": [
            {"name": path.name, "sha256": digest(path), "size": path.stat().st_size}
            for path in (verdict_path, public_capture_path, policy_path, anchor_archive)
        ],
    }
    for field in ("workflow_sha", "run_id", "repository_id"):
        if not package["anchor"].get(field):
            raise PolicyError(f"the verdict does not name its {field}")
    if not package["governance"]:
        raise PolicyError(
            "the run carries no governance observation, so this verdict was never "
            "authoritative and there is nothing to preserve"
        )
    package["evidence_digest"] = _seal(package)
    return package


def _members_problems(package: Mapping[str, Any], directory: Path) -> list[str]:
    """The members are exactly the four it must have, each as recorded."""
    files = package.get("files")
    if not isinstance(files, list):
        return ["PACKAGE_FILE_RECORD"]
    names = [entry.get("name") if isinstance(entry, dict) else None for entry in files]
    if sorted(map(str, names)) != sorted(disclosure.MEMBERS):
        # Not merely "each listed member is fine": an EMPTY list checks no member at
        # all, and a name like `../x` would be hashed from outside the package.
        return ["PACKAGE_MEMBER_SET"]
    problems: list[str] = []
    for entry in files:
        path = directory / str(entry["name"])
        if set(entry) != {"name", "sha256", "size"}:
            problems.append("PACKAGE_FILE_RECORD")
        elif not path.is_file():
            problems.append("PACKAGE_MEMBER_MISSING")
        elif digest(path) != entry["sha256"] or path.stat().st_size != entry["size"]:
            problems.append("PACKAGE_MEMBER_EDITED")
    return problems


def _consistency_problems(package: Mapping[str, Any], directory: Path) -> list[str]:
    """Every package field must agree with the documents it summarises."""
    try:
        verdict = json.loads((directory / "verdict.json").read_text(encoding="utf-8"))
        capture = json.loads((directory / "public-capture.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["PACKAGE_INCONSISTENT"]
    if not isinstance(verdict, dict) or not isinstance(capture, dict):
        return ["PACKAGE_INCONSISTENT"]

    expected = {
        "verdict": verdict.get("verdict"),
        "verdict_reasons": verdict.get("reasons"),
        "candidate_sha": verdict.get("candidate_sha"),
        "candidate_tree": capture.get("candidate_tree"),
        "required_floor": verdict.get("required_floor"),
        "extra_inputs_requested": verdict.get("extra_inputs_requested"),
        "anchor": {field: (verdict.get("anchor") or {}).get(field) for field in _ANCHOR_FIELDS},
        "runner": verdict.get("runner"),
        "sandbox": verdict.get("sandbox"),
        "public_capture_digest": digest(directory / "public-capture.json"),
        "evidence_view_digest": verdict.get("evidence_view_digest"),
        "policy_digest": digest(directory / "policy.json"),
        "verifier": verdict.get("verifier"),
        "anchor_tree_digest": digest(directory / "anchor-tree.tar"),
        "governance": capture.get("governance"),
    }
    problems = ["PACKAGE_INCONSISTENT"] if any(package.get(k) != v for k, v in expected.items()) else []
    if (
        verdict.get("public_capture_digest") != expected["public_capture_digest"]
        or verdict.get("policy_digest") != expected["policy_digest"]
        or verdict.get("candidate_sha") != capture.get("candidate_sha")
        or verdict.get("governance") != capture.get("governance")
    ):
        problems.append("PACKAGE_INCONSISTENT")
    return problems


def check(package_directory: Path) -> list[str]:
    """Fixed codes for why this package is not a consistent record, offline."""
    evidence_path = package_directory / "evidence.json"
    if not evidence_path.is_file():
        return ["PACKAGE_MISSING"]
    try:
        package = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["PACKAGE_UNREADABLE"]
    if not isinstance(package, dict):
        return ["PACKAGE_NOT_OBJECT"]

    problems: list[str] = []
    if set(package) != disclosure.PACKAGE_KEYS:
        problems.append("PACKAGE_SCHEMA")
    if package.get("evidence_version") != disclosure.PACKAGE_VERSION:
        problems.append("PACKAGE_VERSION")
    if package.get("evidence_digest") != _seal(package):
        problems.append("PACKAGE_EDITED")

    member_problems = _members_problems(package, package_directory)
    problems.extend(member_problems)
    if not member_problems and not problems:
        problems.extend(_consistency_problems(package, package_directory))
    if not package.get("governance"):
        problems.append("PACKAGE_NO_GOVERNANCE")
    return list(dict.fromkeys(problems))


def main(argv: list[str]) -> int:
    anchor_policy.assert_isolated()
    parser = publog.Parser("PRESERVE", "Preserve or check one qualification run.")
    sub = parser.add_subparsers(
        dest="action", required=True, parser_class=functools.partial(publog.Parser, "PRESERVE")
    )

    builder = sub.add_parser("build")
    builder.add_argument("--verdict", required=True, type=Path)
    builder.add_argument("--public-capture", required=True, type=Path)
    builder.add_argument("--policy", required=True, type=Path)
    builder.add_argument("--anchor-archive", required=True, type=Path)
    builder.add_argument("--out", required=True, type=Path)

    checker = sub.add_parser("check")
    checker.add_argument("--package", required=True, type=Path)

    arguments = parser.parse_args(argv)
    if arguments.action == "build":
        try:
            package = build(
                arguments.verdict,
                arguments.public_capture,
                arguments.policy,
                arguments.anchor_archive,
            )
        except PolicyError as error:
            publog.emit_policy_refusal("PRESERVE", "PRESERVE_REFUSED", str(error))
            return 2
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(
            json.dumps(package, indent=2, sort_keys=True), encoding="utf-8"
        )
        publog.emit("PRESERVE", "PASS", None, evidence_digest=package["evidence_digest"])
        return 0

    problems = check(arguments.package)
    for problem in problems:
        publog.emit("PRESERVE", "INFO", problem)
    publog.emit("PRESERVE", "REFUSE" if problems else "PASS", problems[0] if problems else None)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(publog.guarded("PRESERVE", main, sys.argv[1:]))

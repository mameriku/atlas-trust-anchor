"""The verdict, computed where the candidate never was.

The verifier runs on the trusted side after the sandbox is gone. It reads exactly
four things: the anchor's own policy, the frozen capture from the trusted phase,
the sandbox's record of how it was built and how it ended, and the evidence
directory. Only the last is hostile, and it is only ever compared against the
first three - never trusted to describe them.

Two results arrive from outside any file the candidate could touch: whether the
capture step succeeded, and the sandbox record, which the trusted host wrote. A
run whose sandbox did not exit cleanly, or whose box was not the required box, is
refused whatever the evidence says, because the child's exit belongs to the host.
The record must also describe THESE directories - the scope the capture exported and
the evidence directory this verifier is about to read - so a run cannot be judged on
evidence from somewhere else.

Everything printed and everything recorded is a fixed code, or a value the verifier
computed or validated itself. The verifier is where hostile bytes and a public log
come closest, so it is the module that never formats a value it did not itself
compute - and even a value GitHub set is dropped unless it is plainly a token.

This module runs no subprocess and never contacts GitHub, and neither does
anything it imports (a test walks the import closure to keep that true). It is not
reachable from the sandbox: nothing the candidate can write is opened here except
the one evidence file, through evidence.py, which treats it as a claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

# Isolated mode puts neither the script's directory nor the user's site-packages
# on sys.path, so the trusted directory is named here from this file's own
# resolved location - never from the environment, and never from the candidate.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import disclosure
import evidence as anchor_evidence
import governance_record as anchor_governance
import policy as anchor_policy
import publog
import sandbox_spec
from policy import FULL_SHA, PolicyError

ACCEPT = "ACCEPT"
REFUSE = "REFUSE"
VERIFIER_VERSION = "atlas-anchor-verifier/3"
SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_TEXT = re.compile(r"\A[A-Za-z0-9._@:/ -]{0,200}\Z")
_NUMBER = re.compile(r"\A[0-9]{1,20}\Z")
CAPTURE_RESULTS = frozenset({"success", "failure", "cancelled", "skipped"})


def read_capture(path: Path, expected_digest: str) -> dict[str, Any]:
    """The frozen capture, or a refusal.

    The expected digest came from the capture step's outputs. No other step can
    write those, so a capture file replaced afterwards fails here rather than
    being believed.
    """
    if not SHA256_HEX.match(expected_digest or ""):
        raise PolicyError("the capture digest is not a sha256 hex digest")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise PolicyError(f"capture is unreadable: {type(error).__name__}") from error
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise PolicyError("the capture file does not match the digest the capture step published")
    try:
        record = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise PolicyError("capture is not readable JSON") from error
    if not isinstance(record, dict) or record.get("capture_version") != disclosure.CAPTURE_VERSION:
        raise PolicyError("capture is not a capture record of the expected version")
    return record


def read_sandbox_record(path: Path | None) -> Any:
    """The host's record of the sandbox run, or None if there is none to read."""
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _compare_capture(
    policy: Mapping[str, Any], scope: list[str], candidate: str, capture: Mapping[str, Any]
) -> list[str]:
    reasons: list[str] = []
    if capture.get("candidate_sha") != candidate:
        reasons.append("CAPTURE_CANDIDATE_MISMATCH")
    tree = capture.get("candidate_tree")
    if not isinstance(tree, str) or not FULL_SHA.match(tree):
        reasons.append("CAPTURE_TREE_INVALID")
    if capture.get("scope") != scope:
        reasons.append("CAPTURE_SCOPE_MISMATCH")
    # `!= []`, not truthiness: a missing or mangled `absent` is not "nothing absent".
    if capture.get("absent") != []:
        reasons.append("INPUT_ABSENT")
    # The verifier does not contact GitHub. It requires that the trusted phase
    # recorded a positive governance observation, bound by the capture digest, and
    # that the observation covers what policy demands.
    reasons.extend(anchor_governance.acceptable(capture.get("governance"), policy))
    return reasons


def _same_directory(recorded: object, actual: Path | None) -> bool:
    if actual is None:
        return True
    try:
        return isinstance(recorded, str) and Path(recorded).resolve() == actual.resolve()
    except OSError:
        return False


def _compare_sandbox(
    policy: Mapping[str, Any],
    candidate: str,
    capture: Mapping[str, Any],
    record: Any,
    docker: Sequence[str],
    evidence_dir: Path | None,
    scope_dir: Path | None,
    forbidden_roots: Sequence[Path] = (),
    child_dir: Path | None = None,
    private_roots: Sequence[Path] = (),
) -> list[str]:
    if record is None:
        return ["SANDBOX_RECORD_MISSING"]
    tree = capture.get("candidate_tree")
    reasons = sandbox_spec.acceptable(
        record, policy, docker, candidate, tree if isinstance(tree, str) else None
    )
    params = record.get("params") if isinstance(record, dict) else None
    if not isinstance(params, dict) or (
        params.get("candidate") != candidate or params.get("tree") != tree
    ):
        reasons.append("SANDBOX_BINDING")
    layout = record.get("layout") if isinstance(record, dict) else None
    if not isinstance(layout, dict) or not (
        _same_directory(layout.get("evidence"), evidence_dir)
        and _same_directory(layout.get("candidate"), scope_dir)
        and _same_directory(layout.get("child"), child_dir)
        and not _contains_forbidden(layout, forbidden_roots, private_roots)
    ):
        reasons.append("SANDBOX_LAYOUT")
    return reasons


def _contains_forbidden(
    layout: Mapping[str, Any], forbidden_roots: Sequence[Path], private_roots: Sequence[Path] = ()
) -> bool:
    """True if any mount source IS, or is an ancestor of, a directory the box must not see.

    The mount sources are compared with each other's record, and with the two
    directories this verifier reads - but a record that named `/` as the candidate
    mount, with a matching argv, would agree with itself. So the directories that hold
    the credential, the freeze and the checkout are named, and no mount may reach them.
    """
    for source in layout.values():
        try:
            resolved = Path(str(source)).resolve()
            for root in forbidden_roots:
                target = Path(root).resolve()
                if resolved == target or resolved in target.parents:
                    return True
            for root in private_roots:
                # Also anything INSIDE these: a mount of the fetched clone, or of a
                # sibling of the checkout, is a mount of something the box must not see.
                target = Path(root).resolve()
                if resolved == target or resolved in target.parents or target in resolved.parents:
                    return True
        except OSError:
            return True
    return False


def _compare_evidence(
    policy: Mapping[str, Any],
    scope: list[str],
    candidate: str,
    capture: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> list[str]:
    """Every claim in the evidence, compared with the freeze. Reasons accumulate."""
    reasons: list[str] = []
    limits = policy["limits"]
    if evidence["candidate_sha"] != candidate:
        reasons.append("EVIDENCE_CANDIDATE_MISMATCH")
    if evidence["candidate_tree"] != capture.get("candidate_tree"):
        reasons.append("EVIDENCE_TREE_MISMATCH")
    if evidence["inputs_requested"] != scope:
        reasons.append("EVIDENCE_SCOPE_MISMATCH")

    truth = {
        str(entry.get("relative_path")): entry
        for entry in capture.get("inputs", [])
        if isinstance(entry, dict)
    }
    observed = evidence["inputs_observed"]
    if len(observed) > limits["max_observations"]:
        reasons.append("EVIDENCE_FLOOD")
        observed = observed[: limits["max_observations"]]

    covered: list[str] = []
    for record in observed:
        relative_path = record["relative_path"]
        covered.append(relative_path)
        frozen = truth.get(relative_path)
        if frozen is None:
            reasons.append("OBSERVATION_NOT_FROZEN")
        elif frozen != record:
            reasons.append("OBSERVATION_MISMATCH")

    if any(path not in covered for path in scope):
        reasons.append("SCOPE_NOT_COVERED")
    if any(path not in scope for path in covered):
        reasons.append("SCOPE_EXCEEDED")
    if len(covered) != len(set(covered)):
        reasons.append("OBSERVATION_DUPLICATED")
    if evidence["inputs_unreadable"]:
        reasons.append("INPUT_UNREADABLE")
    return reasons


def verify(
    policy: Mapping[str, Any],
    scope: list[str],
    candidate: str,
    capture: Mapping[str, Any],
    evidence: anchor_evidence.Read,
    capture_result: str,
    sandbox_record: Any,
    docker: Sequence[str] = ("docker",),
    evidence_dir: Path | None = None,
    scope_dir: Path | None = None,
    forbidden_roots: Sequence[Path] = (),
    child_dir: Path | None = None,
    private_roots: Sequence[Path] = (),
) -> tuple[str, list[str]]:
    """ACCEPT, or every reason not to. Reasons accumulate; nobody fixes one blind."""
    reasons: list[str] = []
    if capture_result != "success":
        reasons.append("CAPTURE_NOT_SUCCESS")
    reasons.extend(_compare_capture(policy, scope, candidate, capture))
    reasons.extend(
        _compare_sandbox(
            policy, candidate, capture, sandbox_record, docker, evidence_dir, scope_dir,
            forbidden_roots, child_dir, private_roots,
        )
    )

    if evidence.evidence is None:
        reasons.extend(evidence.problems or ("EVIDENCE_MISSING",))
    else:
        reasons.extend(_compare_evidence(policy, scope, candidate, capture, evidence.evidence))

    unique = list(dict.fromkeys(reasons))
    return (ACCEPT if not unique else REFUSE), unique


# --------------------------------------------------------------------------
# the verdict record
# --------------------------------------------------------------------------


def _tag(value: str | None) -> str | None:
    """A GitHub-set value, kept only if it is plainly a token (and never `::`)."""
    if value is None or not _TEXT.match(value) or "::" in value:
        return None
    return value


def _number(value: str | None) -> str | None:
    """A GitHub-set identifier that is, by definition, a decimal number."""
    return value if value is not None and _NUMBER.match(value) else None


def anchor_identity(environ: Mapping[str, str]) -> dict[str, str | None]:
    return {
        "repository_id": _number(environ.get("GITHUB_REPOSITORY_ID")),
        "repository": _tag(environ.get("GITHUB_REPOSITORY")),
        "workflow_ref": _tag(environ.get("GITHUB_WORKFLOW_REF")),
        "workflow_sha": _tag(environ.get("GITHUB_WORKFLOW_SHA")),
        "run_id": _number(environ.get("GITHUB_RUN_ID")),
        "run_attempt": _number(environ.get("GITHUB_RUN_ATTEMPT")),
    }


def runner_environment(environ: Mapping[str, str]) -> dict[str, str | None]:
    return {
        "os": _tag(environ.get("RUNNER_OS")),
        "arch": _tag(environ.get("RUNNER_ARCH")),
        "environment": _tag(environ.get("RUNNER_ENVIRONMENT")),
        "image_os": _tag(environ.get("ImageOS")),
        "image_version": _tag(environ.get("ImageVersion")),
    }


def code_digest(directory: Path) -> str:
    """One digest over every anchor module: which verifier this was, in bytes."""
    lines = [
        f"{path.name}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n"
        for path in sorted(directory.glob("*.py"))
    ]
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def sandbox_summary(
    record: Any, policy: Mapping[str, Any], docker: Sequence[str] = ("docker",)
) -> dict[str, Any] | None:
    """The public account of the box. Counts and identities, never output."""
    if not isinstance(record, dict):
        return None
    argv = record.get("argv")
    layout = record.get("layout")
    hardened = (
        isinstance(argv, list)
        and isinstance(layout, dict)
        and not sandbox_spec.audit_argv(argv, policy, layout, docker)
    )
    exit_code = record.get("exit_code")
    return {
        "image": record.get("image"),
        "image_id": record.get("image_id"),
        "hardened": hardened,
        "exit_code": exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
        "timed_out": record.get("timed_out"),
        "output_exceeded": record.get("output_exceeded"),
        "stdout_bytes": record.get("stdout_bytes"),
        "stderr_bytes": record.get("stderr_bytes"),
        "record_digest": sandbox_spec.public_digest_of(record),
    }


def _parse_docker(raw: str) -> list[str]:
    try:
        command = json.loads(raw)
    except ValueError as error:
        raise PolicyError("--docker-command is not JSON") from error
    if not isinstance(command, list) or not command or not all(
        isinstance(part, str) and part for part in command
    ):
        raise PolicyError("--docker-command is not a non-empty list of strings")
    return command


def private_roots(arguments: Any, environ: Mapping[str, str]) -> list[Path]:
    """Directories the box must not see any part of: the freeze's, and the workspace."""
    roots = [arguments.capture.parent]
    if environ.get("GITHUB_WORKSPACE"):
        roots.append(Path(environ["GITHUB_WORKSPACE"]))
    return roots


def forbidden_roots(arguments: Any, environ: Mapping[str, str]) -> list[Path]:
    """The directories holding the freeze, the anchor's own code, and the checkout."""
    return [arguments.capture.parent, arguments.policy.parent, arguments.policy.parent.parent]


def main(argv: list[str]) -> int:
    anchor_policy.assert_isolated()
    parser = publog.Parser("VERIFY", "Verify an Atlas qualification run.")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--inputs-manifest", required=True)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--capture-digest", required=True)
    parser.add_argument("--capture-result", required=True)
    parser.add_argument("--sandbox-record", type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--scope-dir", required=True, type=Path)
    parser.add_argument("--child-dir", required=True, type=Path)
    parser.add_argument("--docker-command", default='["docker"]')
    parser.add_argument("--verdict", type=Path)
    parser.add_argument("--public-capture", type=Path)
    arguments = parser.parse_args(argv)

    scope: list[str] = []
    capture_record: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None
    docker: list[str] = ["docker"]
    sandbox_record = read_sandbox_record(arguments.sandbox_record)
    evidence = anchor_evidence.Read(None, (), None, 0)
    try:
        policy = anchor_policy.load(arguments.policy)
        anchor_policy.assert_anchor_identity(policy, os.environ)
        anchor_policy.assert_full_sha(arguments.candidate, "candidate")
        docker = _parse_docker(arguments.docker_command)
        scope = anchor_policy.effective_scope(policy, arguments.inputs_manifest)
        capture_record = read_capture(arguments.capture, arguments.capture_digest)
    except PolicyError as error:
        publog.emit_policy_refusal("VERIFY", "PRECONDITION_FAILED", str(error))
        verdict, reasons = REFUSE, ["PRECONDITION_FAILED"]
    else:
        evidence = anchor_evidence.read_directory(
            arguments.evidence_dir, policy["limits"]["max_evidence_bytes"]
        )
        verdict, reasons = verify(
            policy,
            scope,
            arguments.candidate,
            capture_record,
            evidence,
            arguments.capture_result,
            sandbox_record,
            docker,
            arguments.evidence_dir,
            arguments.scope_dir,
            forbidden_roots(arguments, os.environ),
            arguments.child_dir,
            private_roots(arguments, os.environ),
        )

    public_capture_digest = None
    if policy is not None and capture_record is not None and arguments.public_capture:
        projection = json.dumps(
            disclosure.public_projection(capture_record, policy), indent=2, sort_keys=True
        ).encode("utf-8")
        arguments.public_capture.parent.mkdir(parents=True, exist_ok=True)
        arguments.public_capture.write_bytes(projection)
        public_capture_digest = hashlib.sha256(projection).hexdigest()

    floor, extras = disclosure.split_scope(policy, scope) if policy is not None else ([], [])
    record = {
        "verdict_version": disclosure.VERDICT_VERSION,
        "verdict": verdict,
        "reasons": reasons,
        "candidate_sha": arguments.candidate if FULL_SHA.match(arguments.candidate) else None,
        "candidate_tree": (capture_record or {}).get("candidate_tree"),
        "required_floor": floor,
        "extra_inputs_requested": len(extras),
        "public_capture_digest": public_capture_digest,
        "evidence_view_digest": (
            disclosure.evidence_view_digest(evidence.evidence, policy)
            if evidence.evidence is not None and policy is not None
            else None
        ),
        "capture_result": arguments.capture_result
        if arguments.capture_result in CAPTURE_RESULTS
        else None,
        "sandbox": sandbox_summary(sandbox_record, policy, docker) if policy else None,
        "anchor": anchor_identity(os.environ),
        "runner": runner_environment(os.environ),
        "governance": (capture_record or {}).get("governance"),
        "policy_digest": hashlib.sha256(arguments.policy.read_bytes()).hexdigest()
        if arguments.policy.is_file()
        else None,
        "verifier": {
            "version": VERIFIER_VERSION,
            "code_digest": code_digest(Path(__file__).resolve().parent),
        },
        "interpreter": sys.version.split()[0],
    }
    if arguments.verdict:
        arguments.verdict.parent.mkdir(parents=True, exist_ok=True)
        arguments.verdict.write_text(
            json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
        )

    publog.emit(
        "VERIFY",
        "PASS" if verdict == ACCEPT else "REFUSE",
        None if verdict == ACCEPT else reasons[0],
        reasons=len(reasons),
    )
    for reason in reasons:
        publog.emit("VERIFY", "INFO", reason)
    return 0 if verdict == ACCEPT else 1


if __name__ == "__main__":
    raise SystemExit(publog.guarded("VERIFY", main, sys.argv[1:]))

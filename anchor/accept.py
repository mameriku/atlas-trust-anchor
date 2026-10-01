"""Should a consumer of a verdict believe it came from this anchor?

A verdict file is just a file. What makes it evidence is a signature over it that
GitHub's own signer made from inside this repository's workflow run, and that
anyone can check offline against a bundle. This module is the consumer's half of
that: it asks `gh attestation verify` to check the signature and then reads only
the part of the answer that the workflow which made the attestation could not have
influenced - the signing certificate.

The GitHub documentation is explicit that the attestation's PREDICATE is
user-controllable. A step that gains code execution in the run could write any
predicate it liked. So nothing is read from the predicate, and nothing the
verdict says about itself is believed. What is compared is:

  certificate                              expected from
  ---------------------------------------  -------------------------------------
  source repository (uri and numeric id)   policy anchor.repository / repository_id
  source ref                               policy anchor.ref
  subject alternative name (file@ref)      policy anchor.workflow_ref, as a URL
  workflow trigger                         policy trigger.event
  runner environment                       github-hosted
  source repository visibility at signing  public
  source digest                            the commit the verdict names as its workflow_sha
  run invocation                           the run id and attempt the verdict names

Source ref and subject-alternative-name are deliberately two separate checks,
not one: the first proves the protected ref, the second proves the exact
workflow *file* (and, redundantly, its ref again) - collapsing them would let a
certificate that merely shares a ref but names a different workflow file pass.
`subjectAlternativeName` is the certificate's own X.509 SAN, the field the
signature is actually over; `buildSignerURI` and `buildConfigURI` carry the
same value as OIDC-claim-derived copies of it and are not checked separately.

`githubWorkflowRef` is deliberately NOT one of the checks: on a real GitHub
certificate (confirmed against a live attestation from run 36810852859, not
assumed from documentation) it carries only the bare ref ("refs/heads/main"),
identical to sourceRepositoryRef for a workflow that is not called as a
reusable workflow from another repository, as this one is not. An earlier
version of this function compared it against the full "owner/repo/path@ref"
form of policy anchor.workflow_ref instead - a shape no real certificate ever
has, which refused every genuine attestation this anchor could ever produce.
It went undetected because the unit tests built their own fabricated
certificate dictionary carrying that same wrong shape, rather than one copied
from a real attestation's JSON. The field it actually named, and the ones it
omitted (`subjectAlternativeName`/`buildSignerURI`/`buildConfigURI`), were
never exercised against the real thing. `githubWorkflowName` is also
deliberately never checked: it is the workflow's human-readable `name:` key,
not a security-asserted identity, and must not become one.

This is not a second judge and re-decides nothing about the candidate. It answers
"did this anchor, running its protected workflow, make this file" - and only then
reports what the file says. It is a check on provenance, so it does not recurse:
there is no verifier of this verifier, because a signature made by GitHub's signer
is the thing being trusted, and that is an infrastructure assumption stated in the
README.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import disclosure
import policy as anchor_policy
import publog
from policy import FULL_SHA, PolicyError

_GH_TIMEOUT_SECONDS = 120


def _normalise(certificate: Mapping[str, Any]) -> dict[str, str]:
    """Certificate fields by lower-cased name, so a change of casing is not a bypass."""
    return {
        str(key).lower(): str(value) for key, value in certificate.items() if value is not None
    }


def check_certificate(
    certificate: Mapping[str, Any], policy: Mapping[str, Any], verdict: Mapping[str, Any]
) -> list[str]:
    """Fixed codes for every way this certificate does not name this anchor's run."""
    anchor = policy["anchor"]
    named = verdict.get("anchor") if isinstance(verdict.get("anchor"), dict) else {}
    cert = _normalise(certificate)
    run_url = (
        f"https://github.com/{anchor['repository']}/actions/runs/"
        f"{named.get('run_id')}/attempts/{named.get('run_attempt')}"
    )
    expected = {
        "sourcerepositoryuri": f"https://github.com/{anchor['repository']}",
        "sourcerepositoryidentifier": str(anchor["repository_id"]),
        "sourcerepositoryref": anchor["ref"],
        "subjectalternativename": f"https://github.com/{anchor['workflow_ref']}",
        "githubworkflowtrigger": policy["trigger"]["event"],
        "runnerenvironment": "github-hosted",
        "sourcerepositoryvisibilityatsigning": "public",
        "sourcerepositorydigest": str(named.get("workflow_sha")),
        "runinvocationuri": run_url,
    }
    problems = []
    for field, wanted in expected.items():
        if field not in cert:
            problems.append("ATTESTATION_FIELD_MISSING")
        elif cert[field].casefold() != wanted.casefold():
            problems.append("ATTESTATION_IDENTITY_MISMATCH")
    return list(dict.fromkeys(problems))


def signer_workflow(policy: Mapping[str, Any]) -> str:
    return policy["anchor"]["workflow_ref"].split("@", 1)[0]


def verify_command(
    gh: Sequence[str], verdict_path: Path, bundle: Path, policy: Mapping[str, Any]
) -> list[str]:
    anchor = policy["anchor"]
    return [
        *gh,
        "attestation",
        "verify",
        str(verdict_path),
        "--bundle",
        str(bundle),
        "--repo",
        anchor["repository"],
        "--signer-workflow",
        signer_workflow(policy),
        "--source-ref",
        anchor["ref"],
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]


def _verified_certificates(output: str) -> list[Mapping[str, Any]]:
    try:
        entries = json.loads(output)
    except ValueError:
        return []
    certificates = []
    for entry in entries if isinstance(entries, list) else []:
        result = entry.get("verificationResult") if isinstance(entry, dict) else None
        signature = result.get("signature") if isinstance(result, dict) else None
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        if isinstance(certificate, dict):
            certificates.append(certificate)
    return certificates


def accept(
    verdict_path: Path,
    bundle: Path,
    policy: Mapping[str, Any],
    gh: Sequence[str],
    candidate: str,
    policy_sha256: str | None = None,
) -> tuple[str | None, list[str]]:
    """The verdict the file states, if and only if this anchor's signer made the file
    AND it is a verdict about the commit the caller is asking about.

    A validly signed ACCEPT for commit X is not evidence about commit Y. Without the
    candidate, every genuine ACCEPT ever issued would be usable as proof of any
    other commit, so the caller must say which one they are relying on.
    """
    if not FULL_SHA.match(candidate or ""):
        return None, ["CANDIDATE_INVALID"]
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, ["VERDICT_UNREADABLE"]
    if not isinstance(verdict, dict):
        return None, ["VERDICT_UNREADABLE"]

    try:
        completed = subprocess.run(  # noqa: S603 - argv, not a shell string
            verify_command(gh, verdict_path, bundle, policy),
            capture_output=True,
            check=False,
            timeout=_GH_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, ["ATTESTATION_TOOL_FAILED"]
    if completed.returncode != 0:
        return None, ["ATTESTATION_NOT_VERIFIED"]

    certificates = _verified_certificates(completed.stdout.decode("utf-8", errors="replace"))
    if not certificates:
        return None, ["ATTESTATION_NO_CERTIFICATE"]
    problems: list[str] = []
    for certificate in certificates:
        problems.extend(check_certificate(certificate, policy, verdict))

    # What the (now authentic) file says, checked for what it must say.
    if verdict.get("verdict_version") != disclosure.VERDICT_VERSION:
        problems.append("VERDICT_VERSION")
    if verdict.get("candidate_sha") != candidate:
        problems.append("VERDICT_CANDIDATE_MISMATCH")
    if policy_sha256 is not None and verdict.get("policy_digest") != policy_sha256:
        # Made under a different policy than the one the consumer holds - an older
        # floor, perhaps, or an older evaluator. Accepting it needs a decision, not a
        # default.
        problems.append("VERDICT_POLICY_MISMATCH")
    stated = verdict.get("verdict")
    if stated not in ("ACCEPT", "REFUSE"):
        problems.append("VERDICT_UNKNOWN")
    elif (stated == "ACCEPT") != (verdict.get("reasons") == []):
        # An ACCEPT with reasons, or a REFUSE with none, is not something the
        # verifier produces; it is a file that has been edited or mis-built.
        problems.append("VERDICT_INCONSISTENT")
    if problems:
        return None, list(dict.fromkeys(problems))
    return str(stated), []


def main(argv: list[str]) -> int:
    anchor_policy.assert_isolated()
    parser = publog.Parser("ACCEPT", "Check a verdict's attestation offline.")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--verdict", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--allow-older-policy", action="store_true")
    parser.add_argument("--gh", default="gh")
    arguments = parser.parse_args(argv)
    try:
        policy = anchor_policy.load(arguments.policy)
    except PolicyError as error:
        publog.emit_policy_refusal("ACCEPT", "POLICY_REFUSED", str(error))
        return 2

    current_policy = (
        None if arguments.allow_older_policy else hashlib.sha256(arguments.policy.read_bytes()).hexdigest()
    )
    stated, problems = accept(
        arguments.verdict, arguments.bundle, policy, [arguments.gh], arguments.candidate,
        current_policy,
    )
    for problem in problems:
        publog.emit("ACCEPT", "REFUSE", problem)
    if problems:
        return 1
    digest = hashlib.sha256(arguments.verdict.read_bytes()).hexdigest()
    publog.emit("ACCEPT", "PASS" if stated == "ACCEPT" else "INFO", None, verdict_sha256=digest)
    return 0 if stated == "ACCEPT" else 1


if __name__ == "__main__":
    raise SystemExit(publog.guarded("ACCEPT", main, sys.argv[1:]))

"""The identity gate, run before the target credential is used for anything.

Separate from capture.py so that it can be its own workflow step: if this step
fails, no later step runs, and the credential is never spent on a dispatch that
did not come from the anchor's protected default branch, started by a named
principal, on a GitHub-hosted runner, with governance in force.

It asks two different questions and they have different answers to "who is
asking?". Identity is read from the environment GitHub sets for this run.
Governance is read from GitHub's API and is what says the protection on the
branch is real. The observation is written for capture to bind; capture does not
repeat the network calls, so the step that holds the credential does not also
hold a token that can read this repository's administration.

`--identity-only` is for a job that has no credential and no need of one - the
attestation job - which still must not run from anywhere but the protected ref.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Isolated mode puts neither the script's directory nor the user's site-packages
# on sys.path, so the trusted directory is named here from this file's own
# resolved location - never from the environment, and never from the candidate.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import governance as anchor_governance
import policy as anchor_policy
import publog
from policy import PolicyError


def main(argv: list[str]) -> int:
    anchor_policy.assert_isolated()
    parser = publog.Parser("GATE", "Assert this run is the anchor's own.")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--observation-out", type=Path)
    arguments = parser.parse_args(argv)
    if not arguments.identity_only and arguments.observation_out is None:
        parser.error("--observation-out is required unless --identity-only")

    try:
        policy = anchor_policy.load(arguments.policy)
        anchor_policy.assert_anchor_identity(policy, os.environ)
        if arguments.identity_only:
            publog.emit("GATE", "PASS", "IDENTITY_ONLY")
            return 0
        # Before the target credential is spent: is this anchor actually
        # protected? Every other signal can stay identical while the enforcement
        # behind it is removed, so the question has to be asked rather than assumed.
        observed = anchor_governance.observe(policy, os.environ)
    except PolicyError as error:
        publog.emit_policy_refusal("GATE", "GATE_REFUSED", str(error))
        return 2

    arguments.observation_out.parent.mkdir(parents=True, exist_ok=True)
    arguments.observation_out.write_text(
        json.dumps(observed, indent=2, sort_keys=True), encoding="utf-8"
    )
    publog.emit(
        "GATE",
        "PASS",
        None,
        rulesets=len(observed["rulesets"]),
        observation_digest=observed["observation_digest"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(publog.guarded("GATE", main, sys.argv[1:]))

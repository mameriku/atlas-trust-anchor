"""The anchor's own identity, and the scope floor a caller cannot go under.

Two things live here because both are answers to the same question: which parts
of a run does the caller get to choose? The caller chooses a candidate commit and
may ask for extra inputs to be covered. It does not choose which repository is
judged, which evaluator revision runs, which principals may start a run, or the
minimum scope of the run.

Everything is fail-closed. An unreadable policy, a policy field that is absent,
and an environment that does not match are all refusals, because "could not
check" must never read as "nothing was wrong".

The topology is fixed and stated here rather than configurable: a PUBLIC anchor
judging a PRIVATE target. That pair is only safe because no private byte is ever
transported through a public artifact - the private repository is fetched, frozen,
sandboxed and judged on one ephemeral runner, and only an allow-listed projection
leaves it. `disclosure.private_transport` therefore has exactly one legal value.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

POLICY_VERSION = "atlas-anchor-policy/2"
FULL_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
PINNED_IMAGE = re.compile(r"\A[a-z0-9][a-z0-9./_-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z")
HOST_KEY = re.compile(r"\Assh-ed25519 AAAA[A-Za-z0-9+/=]{40,200}\Z")
ACTOR = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z")
TRIGGER_EVENT = "workflow_dispatch"
CANONICAL_RULES = ("deletion", "non_fast_forward", "pull_request", "required_status_checks")


class PolicyError(RuntimeError):
    """The run may not proceed. The message names every reason, not the first.

    A PolicyError is a fact about the anchor - its policy, identity, governance or
    a dispatch input - and is public by construction. Anything learned from the
    private target is a `publog.TargetError`, whose text is never shown.
    """


def assert_isolated() -> None:
    """Refuse unless CPython was started with -I -S -B.

    Checked rather than documented: under -I the interpreter ignores PYTHONPATH and
    the user site directory, so a candidate cannot shadow a trusted module by name;
    -S keeps sitecustomize out; -B keeps a planted __pycache__ entry from ever being
    loaded.
    """
    problems = []
    if not sys.flags.isolated:
        problems.append("interpreter is not isolated (-I)")
    if not sys.flags.no_site:
        problems.append("site is enabled (-S missing)")
    if not sys.dont_write_bytecode:
        problems.append("bytecode writing is enabled (-B missing)")
    if problems:
        raise PolicyError("; ".join(problems))


def _require_str(section: Mapping[str, Any], name: str, where: str) -> str:
    value = section.get(name)
    if not isinstance(value, str) or not value:
        raise PolicyError(f"policy {where}.{name} is not a non-empty string")
    return value


def _require_positive(section: Mapping[str, Any], name: str, where: str) -> int:
    value = section.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyError(f"policy {where}.{name} is not a positive integer")
    return value


def _load_sides(raw: Mapping[str, Any]) -> None:
    anchor = raw.get("anchor")
    target = raw.get("target")
    if not isinstance(anchor, dict) or not isinstance(target, dict):
        raise PolicyError("policy is missing an 'anchor' or 'target' object")
    for field in ("repository", "workflow_ref", "ref"):
        _require_str(anchor, field, "anchor")
    identity = anchor.get("repository_id")
    if isinstance(identity, bool) or not isinstance(identity, int):
        raise PolicyError(
            "policy anchor.repository_id is not set to this repository's numeric id; "
            "an anchor that does not know its own identity cannot assert it "
            "(see GOVERNANCE.md, bootstrap step 3)"
        )
    _require_str(target, "repository", "target")
    _require_positive(target, "repository_id", "target")
    if anchor.get("visibility") != "public" or target.get("visibility") != "private":
        raise PolicyError(
            "the supported topology is a public anchor judging a private target; "
            f"got anchor={anchor.get('visibility')!r} target={target.get('visibility')!r}"
        )


def _load_trigger_and_credential(raw: Mapping[str, Any]) -> None:
    trigger = raw.get("trigger")
    if not isinstance(trigger, dict) or trigger.get("event") != TRIGGER_EVENT:
        raise PolicyError(f"policy trigger.event is not {TRIGGER_EVENT!r}")
    actors = trigger.get("actors")
    if not isinstance(actors, list) or not actors or not all(
        isinstance(actor, str) and ACTOR.match(actor) for actor in actors
    ):
        raise PolicyError(
            "policy trigger.actors is empty or malformed; a run nobody is named to "
            "start would accept anybody"
        )

    credential = raw.get("credential")
    if not isinstance(credential, dict) or credential.get("kind") != "deploy-key":
        raise PolicyError("policy credential.kind is not 'deploy-key'")
    _require_str(credential, "environment", "credential")
    if not re.match(r"\A[A-Z][A-Z0-9_]{2,63}\Z", str(credential.get("secret", ""))):
        raise PolicyError("policy credential.secret is not an environment variable name")
    if not HOST_KEY.match(str(credential.get("host_key", ""))):
        raise PolicyError(
            "policy credential.host_key is not a pinned ssh-ed25519 host key; a fetch "
            "that does not know whom it is talking to would hand the key to anybody"
        )


def _load_sandbox(raw: Mapping[str, Any]) -> None:
    sandbox = raw.get("sandbox")
    if not isinstance(sandbox, dict):
        raise PolicyError("policy is missing a 'sandbox' object")
    if not PINNED_IMAGE.match(str(sandbox.get("image", ""))):
        raise PolicyError(
            "policy sandbox.image is not pinned by sha256 digest; a moved tag would "
            "change what the candidate runs inside"
        )
    for field in (
        "timeout_seconds",
        "memory_mb",
        "cpus",
        "pids_limit",
        "max_output_bytes",
        "max_file_bytes",
        "tmpfs_mb",
    ):
        _require_positive(sandbox, field, "sandbox")


def _load_governance(raw: Mapping[str, Any]) -> None:
    governance = raw.get("governance")
    if not isinstance(governance, dict):
        raise PolicyError("policy is missing a 'governance' object")
    _require_str(governance, "required_ref", "governance")
    rules = governance.get("required_rules")
    if not isinstance(rules, list) or not rules or not all(
        isinstance(rule, str) and rule for rule in rules
    ):
        raise PolicyError(
            "policy governance.required_rules is empty; a run that requires no rule "
            "would accept an unprotected anchor"
        )
    approvals = governance.get("required_approvals")
    if isinstance(approvals, bool) or not isinstance(approvals, int) or approvals < 1:
        raise PolicyError("policy governance.required_approvals is not a positive integer")
    for flag in ("require_dismiss_stale_reviews", "require_empty_bypass"):
        if not isinstance(governance.get(flag), bool):
            raise PolicyError(f"policy governance.{flag} is not a boolean")
    contexts = governance.get("required_status_checks")
    if not isinstance(contexts, list) or not contexts or not all(
        isinstance(context, str) and context for context in contexts
    ):
        raise PolicyError(
            "policy governance.required_status_checks is empty; a merge nobody has to "
            "test would change the judge unexamined"
        )
    missing = sorted(set(CANONICAL_RULES) - set(rules))
    if missing:
        raise PolicyError(
            f"policy governance.required_rules omits {missing}; dropping a rule from policy "
            "would drop the protection it names and leave its parameters as dead config"
        )
    _require_positive(governance, "required_status_check_integration_id", "governance")
    environment = governance.get("environment")
    if not isinstance(environment, dict):
        raise PolicyError("policy governance.environment is not an object")
    only = environment.get("environment_only_secrets")
    if not isinstance(only, list) or not only or not all(isinstance(n, str) and n for n in only):
        raise PolicyError("policy governance.environment.environment_only_secrets is empty")
    _require_str(environment, "name", "governance.environment")
    branches = environment.get("deployment_branches")
    if not isinstance(branches, list) or not branches or not all(
        isinstance(branch, str) and branch for branch in branches
    ):
        raise PolicyError("policy governance.environment.deployment_branches is empty")


def load(path: Path) -> dict[str, Any]:
    """Read the anchor policy, refusing any shape this module cannot check."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"policy at {path} is unreadable: {error}") from error
    if not isinstance(raw, dict):
        raise PolicyError("policy is not an object")
    if raw.get("policy_version") != POLICY_VERSION:
        raise PolicyError(
            f"policy version {raw.get('policy_version')!r} is not {POLICY_VERSION!r}"
        )

    _load_sides(raw)
    _load_trigger_and_credential(raw)
    _load_sandbox(raw)
    _load_governance(raw)

    disclosure = raw.get("disclosure")
    if not isinstance(disclosure, dict) or disclosure.get("private_transport") != "none":
        raise PolicyError(
            "policy disclosure.private_transport is not 'none'; no private byte may "
            "cross a public artifact, and there is no setting that permits it"
        )
    if not isinstance(disclosure.get("publish_floor_digests"), bool):
        raise PolicyError("policy disclosure.publish_floor_digests is not a boolean")

    limits = raw.get("limits")
    if not isinstance(limits, dict):
        raise PolicyError("policy is missing a 'limits' object")
    for field in ("max_evidence_bytes", "max_observations", "max_input_bytes"):
        _require_positive(limits, field, "limits")

    floor = raw.get("required_inputs_floor")
    if not isinstance(floor, list) or not floor:
        raise PolicyError("policy required_inputs_floor is empty; a run under it would establish nothing")
    for entry in floor:
        if entry != _check_path(entry):
            raise PolicyError(f"policy required_inputs_floor entry {entry!r} is not normalised")
    return raw


def _check_path(candidate: object) -> str:
    """A candidate-relative path this anchor is willing to name."""
    if not isinstance(candidate, str) or not candidate.strip():
        raise PolicyError(f"input path {candidate!r} is not a non-empty string")
    path = candidate.strip()
    if path != candidate.strip().strip("/"):
        raise PolicyError(f"input path {candidate!r} is not relative")
    if path.startswith("/") or path.startswith("\\") or ":" in path:
        raise PolicyError(f"input path {path!r} is absolute")
    if "\\" in path:
        raise PolicyError(f"input path {path!r} uses backslashes")
    segments = path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise PolicyError(f"input path {path!r} is not normalised")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        raise PolicyError("an input path contains a control character")
    return path


def assert_anchor_identity(policy: Mapping[str, Any], environ: Mapping[str, str]) -> None:
    """Refuse unless this run is the anchor's own protected workflow, started by
    someone the policy names, on a GitHub-hosted runner.

    GITHUB_WORKFLOW_REF names the workflow file *and the ref it was dispatched
    at*, so a dispatch against a side branch is refused here even though the file
    also exists on the default branch. GITHUB_REPOSITORY_ID survives a rename; the
    repository name is checked as well, so a rename is a refusal that needs a
    reviewed policy change rather than a silent continuation.
    """
    anchor = policy["anchor"]
    trigger = policy["trigger"]
    problems: list[str] = []

    observed_id = environ.get("GITHUB_REPOSITORY_ID", "")
    if observed_id != str(anchor["repository_id"]):
        problems.append(
            f"repository id {observed_id!r} is not this anchor's {anchor['repository_id']}"
        )
    if environ.get("GITHUB_REPOSITORY", "").casefold() != anchor["repository"].casefold():
        problems.append(
            f"repository {environ.get('GITHUB_REPOSITORY')!r} is not {anchor['repository']!r}"
        )
    observed_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    if observed_ref != anchor["workflow_ref"]:
        problems.append(
            f"workflow ref {observed_ref!r} is not {anchor['workflow_ref']!r}"
        )
    if environ.get("GITHUB_REF", "") != anchor["ref"]:
        problems.append(f"ref {environ.get('GITHUB_REF')!r} is not {anchor['ref']!r}")

    workflow_sha = environ.get("GITHUB_WORKFLOW_SHA", "")
    head_sha = environ.get("GITHUB_SHA", "")
    if not FULL_SHA.match(workflow_sha):
        problems.append(f"workflow sha {workflow_sha!r} is not a full commit sha")
    if workflow_sha != head_sha:
        problems.append(
            f"the workflow came from {workflow_sha[:12]} but the run is at {head_sha[:12]}"
        )

    if environ.get("GITHUB_EVENT_NAME", "") != trigger["event"]:
        problems.append(
            f"event {environ.get('GITHUB_EVENT_NAME')!r} is not {trigger['event']!r}"
        )
    for variable in ("GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR"):
        if environ.get(variable, "") not in trigger["actors"]:
            problems.append(f"{variable} {environ.get(variable)!r} is not a named principal")
    if environ.get("RUNNER_ENVIRONMENT", "") != "github-hosted":
        problems.append(
            f"runner environment {environ.get('RUNNER_ENVIRONMENT')!r} is not 'github-hosted'"
        )
    if problems:
        raise PolicyError("; ".join(problems))


def effective_scope(policy: Mapping[str, Any], manifest: str) -> list[str]:
    """The floor, plus whatever else the caller asked for. Never less than the floor.

    A caller may widen a run. Narrowing is not expressible: the floor is unioned
    in after the manifest is parsed, so a manifest of one trivial path still
    qualifies against every path the anchor requires.
    """
    requested = [_check_path(line) for line in manifest.splitlines() if line.strip()]
    if len(set(requested)) != len(requested):
        raise PolicyError("the manifest repeats an input")
    floor = [_check_path(entry) for entry in policy["required_inputs_floor"]]
    return sorted(set(requested) | set(floor))


def assert_full_sha(value: str, what: str) -> str:
    if not FULL_SHA.match(value or ""):
        raise PolicyError(f"{what} {value!r} is not a full lowercase 40-hex commit sha")
    return value

"""Does this anchor actually have the protection it claims? Asked, not assumed.

The anchor checks its own identity - which repository, which workflow, which ref,
which principal - and takes nothing about its *protection* on faith. Whoever can
change the default branch can change the judge, so the property that matters is
enforced protection of that branch, and it is asked for directly:

  * the repository is who policy says, by numeric id and by name, and is PUBLIC
  * its default branch is the branch policy names
  * deletion and force-push are blocked, a reviewed pull request is required, and
    the required status checks include the anchor's own test job
  * nobody can bypass any of it: the bypass list must be READABLE and EMPTY
  * the environment that holds the target credential releases it to the default
    branch and to nothing else

Rulesets are the authority. Nothing here asks which plan the account is on; a
plan name is a proxy, and the only thing a proxy can do is be wrong. What is
checked is the enforced property, on GitHub Free, on a public repository.

A rule that cannot be read is a refusal, not an absence. In particular a ruleset
response WITHOUT a `bypass_actors` field is not "an empty bypass list": GitHub
omits the field from callers that are not allowed to see it, and treating omission
as emptiness would turn a token's lack of permission into a passing check.

This is not a second judge. It is the same anchor asserting one more precondition
about itself, exactly as it already asserts GITHUB_WORKFLOW_REF. If the anchor is
unprotected, someone with write access can delete this file; that residual is the
trust assumption recorded in the README, and no amount of checking from inside
closes it. What this closes is the SILENT case: a setting changes, nobody notices,
and runs keep producing verdicts.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

from governance_record import GOVERNANCE_VERSION, _digest, acceptable  # noqa: E402,F401
from policy import PolicyError  # noqa: E402

_API = "https://api.github.com"
_TIMEOUT_SECONDS = 30

Fetch = Callable[[str], "tuple[int, Any]"]


def _default_fetch(path: str) -> tuple[int, Any]:
    """One GET against the GitHub API, with every failure turned into a status.

    The governance token is separate from the target credential on purpose. The
    target credential is a read-only deploy key that cannot speak to this API at
    all; ANCHOR_GOVERNANCE_TOKEN, when present, is scoped to THIS repository and
    reads its administration, nothing else.
    """
    token = os.environ.get("ANCHOR_GOVERNANCE_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        return 0, "no governance token is available to this job"
    request = urllib.request.Request(
        f"{_API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "atlas-trust-anchor",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read().decode("utf-8"))
        except (ValueError, OSError):
            body = {}
        return error.code, body
    except (urllib.error.URLError, OSError, ValueError) as error:
        # A network failure is not an absence of rules. It is an inability to
        # establish them, which is a refusal.
        return 0, str(error)


def _get(fetch: Fetch, path: str, what: str) -> Any:
    status, payload = fetch(path)
    if status == 403:
        message = payload.get("message") if isinstance(payload, dict) else payload
        raise PolicyError(
            f"{what} is not readable (403): {message!r}. The token this job holds is "
            "not allowed to read it, so governance cannot be established; supply "
            "ANCHOR_GOVERNANCE_TOKEN (see GOVERNANCE.md)"
        )
    if status in {401, 404}:
        raise PolicyError(
            f"{what} is not readable ({status}); governance cannot be established"
        )
    if status != 200:
        raise PolicyError(f"{what} could not be read (status {status}): {payload!r}")
    return payload


def _rule_index(rules: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(rules, list):
        raise PolicyError("the branch rules response is not a list")
    index: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            raise PolicyError(f"unreadable rule entry: {rule!r}")
        index.setdefault(rule["type"], []).append(rule)
    return index


def _check_repository(described: Any, policy: Mapping[str, Any], branch: str) -> list[str]:
    anchor = policy["anchor"]
    if not isinstance(described, dict):
        raise PolicyError("the anchor repository is not readable as an object")
    problems: list[str] = []
    if described.get("id") != anchor["repository_id"]:
        raise PolicyError(
            f"{anchor['repository']} reports id {described.get('id')!r}, and this "
            f"anchor is {anchor['repository_id']}"
        )
    if str(described.get("full_name", "")).casefold() != anchor["repository"].casefold():
        problems.append(
            f"the repository is named {described.get('full_name')!r}, not {anchor['repository']!r}"
        )
    if described.get("private") is not False or described.get("visibility") not in (
        None,
        "public",
    ):
        problems.append("the anchor repository is not public")
    if described.get("default_branch") != branch:
        problems.append(
            f"the default branch is {described.get('default_branch')!r}, not {branch!r}"
        )
    return problems


def _check_rules(
    index: dict[str, list[dict[str, Any]]], policy: Mapping[str, Any], branch: str
) -> list[str]:
    required = policy["governance"]
    problems: list[str] = []
    for rule_type in required["required_rules"]:
        if rule_type not in index:
            problems.append(f"{rule_type} is not enforced on {branch}")

    for rule in index.get("pull_request", []):
        parameters = rule.get("parameters") or {}
        approvals = parameters.get("required_approving_review_count")
        if isinstance(approvals, bool) or not isinstance(approvals, int) or (
            approvals < required["required_approvals"]
        ):
            problems.append(
                f"pull requests require {approvals!r} approvals, policy requires "
                f"{required['required_approvals']}"
            )
        if required["require_dismiss_stale_reviews"] and not parameters.get(
            "dismiss_stale_reviews_on_push"
        ):
            problems.append("stale approvals are not dismissed when new commits are pushed")
        if parameters.get("require_last_push_approval") is not True:
            problems.append(
                "the last pusher may approve their own change; a second reviewer is not required"
            )

    integration = required["required_status_check_integration_id"]
    contexts = _status_check_contexts(index, integration)
    for context in required["required_status_checks"]:
        if context not in contexts:
            problems.append(
                f"the status check {context!r} from integration {integration} is not required "
                f"on {branch}; a check of that name posted by any other app would satisfy it"
            )
    for rule in index.get("required_status_checks", []):
        if (rule.get("parameters") or {}).get("strict_required_status_checks_policy") is not True:
            problems.append("status checks are not required to be up to date with the base branch")
    return problems


def _pull_request_facts(
    index: dict[str, list[dict[str, Any]]],
) -> tuple[int | None, bool, bool]:
    """The weakest pull-request rule in force: fewest approvals, any lax stale or last-push rule."""
    counts: list[int] = []
    dismiss = True
    last_push = True
    for rule in index.get("pull_request", []):
        parameters = rule.get("parameters") or {}
        count = parameters.get("required_approving_review_count")
        counts.append(count if isinstance(count, int) and not isinstance(count, bool) else -1)
        if parameters.get("dismiss_stale_reviews_on_push") is not True:
            dismiss = False
        if parameters.get("require_last_push_approval") is not True:
            last_push = False
    present = bool(counts)
    return (min(counts) if counts else None), dismiss and present, last_push and present


def _status_check_contexts(index: dict[str, list[dict[str, Any]]], integration: int) -> list[str]:
    """Contexts whose required check must come from THE integration - GitHub Actions.

    A check identified only by name can be satisfied by anyone who can post a commit
    status of that name. Pinned to the integration that runs this repository's own
    test job, only that job can.
    """
    contexts: set[str] = set()
    for rule in index.get("required_status_checks", []):
        checks = (rule.get("parameters") or {}).get("required_status_checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if (
                isinstance(check, dict)
                and isinstance(check.get("context"), str)
                and check.get("integration_id") == integration
                and not isinstance(check.get("integration_id"), bool)
            ):
                contexts.add(check["context"])
    return sorted(contexts)


def _inspect_rulesets(
    fetch: Fetch,
    repository: str,
    index: dict[str, list[dict[str, Any]]],
    policy: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    required = policy["governance"]
    problems: list[str] = []
    sources = {
        rule.get("ruleset_id")
        for rules_of_type in index.values()
        for rule in rules_of_type
        if rule.get("ruleset_id") is not None
    }
    if not sources:
        problems.append("no ruleset could be attributed to the rules in force")

    inspected: list[dict[str, Any]] = []
    for ruleset_id in sorted(sources):
        detail = _get(
            fetch, f"/repos/{repository}/rulesets/{ruleset_id}", f"ruleset {ruleset_id}"
        )
        if not isinstance(detail, dict):
            raise PolicyError(f"ruleset {ruleset_id} is not readable as an object")
        enforcement = detail.get("enforcement")
        if enforcement != "active":
            problems.append(f"ruleset {ruleset_id} is {enforcement!r}, not 'active'")
        if detail.get("target") != "branch":
            problems.append(f"ruleset {ruleset_id} targets {detail.get('target')!r}, not a branch")

        bypass = detail.get("bypass_actors")
        if required["require_empty_bypass"]:
            if not isinstance(bypass, list):
                problems.append(
                    f"ruleset {ruleset_id} does not disclose its bypass list to this token; "
                    "an unreadable bypass list cannot be assumed empty"
                )
            elif bypass:
                problems.append(
                    f"ruleset {ruleset_id} lets {len(bypass)} actor(s) bypass it; "
                    "policy requires none"
                )
        inspected.append(
            {
                "id": ruleset_id,
                "name": detail.get("name"),
                "enforcement": enforcement,
                "bypass_actor_count": len(bypass) if isinstance(bypass, list) else None,
                "target": detail.get("target"),
            }
        )
    return inspected, problems


def _inspect_environment(
    fetch: Fetch, repository: str, policy: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """The environment that holds the credential must release it to main only.

    Without this, a workflow on ANY branch that names the environment - or that
    names none, if the secret were repository-level - could read the deploy key,
    and every check above would be a check the attacker simply did not run.
    """
    spec = policy["governance"]["environment"]
    name = spec["name"]
    problems: list[str] = []
    environment = _get(fetch, f"/repos/{repository}/environments/{name}", f"environment {name}")
    if not isinstance(environment, dict):
        raise PolicyError(f"environment {name} is not readable as an object")
    restriction = environment.get("deployment_branch_policy")
    if not isinstance(restriction, dict) or restriction.get("custom_branch_policies") is not True:
        problems.append(f"environment {name} does not restrict deployment to named branches")
    if environment.get("can_admins_bypass") is not False:
        problems.append(f"environment {name} lets administrators bypass its protection rules")

    listing = _get(
        fetch,
        f"/repos/{repository}/environments/{name}/deployment-branch-policies",
        f"the deployment branches of {name}",
    )
    entries = listing.get("branch_policies") if isinstance(listing, dict) else None
    if not isinstance(entries, list):
        raise PolicyError(f"the deployment branches of {name} are not readable as a list")
    named = sorted(
        entry["name"]
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("name"), str)
        and entry.get("type", "branch") == "branch"
    )
    if len(named) != len(entries) or named != sorted(spec["deployment_branches"]):
        problems.append(
            f"environment {name} releases to {named!r}, policy requires "
            f"{sorted(spec['deployment_branches'])!r} and nothing else"
        )
    return {
        "name": name,
        "deployment_branches": named,
        "admins_can_bypass": environment.get("can_admins_bypass"),
    }, problems


def _secret_names(fetch: Fetch, path: str, what: str) -> tuple[set[str], bool]:
    """The names in one secrets listing, and whether the listing was complete."""
    listing = _get(fetch, path, what)
    entries = listing.get("secrets") if isinstance(listing, dict) else None
    total = listing.get("total_count") if isinstance(listing, dict) else None
    if not isinstance(entries, list) or isinstance(total, bool) or not isinstance(total, int):
        raise PolicyError(f"{what} are not readable as a list")
    return {entry.get("name") for entry in entries if isinstance(entry, dict)}, total == len(entries)


def _owner_type(described: Mapping[str, Any]) -> object:
    owner = described.get("owner")
    return owner.get("type") if isinstance(owner, dict) else None


def _inspect_secrets(
    fetch: Fetch, repository: str, policy: Mapping[str, Any], owner_type: object
) -> tuple[bool, list[str]]:
    """The credential must exist ONLY as a secret of the one environment.

    A repository-level secret of the same name is released to every workflow on every
    branch. A copy in ANOTHER environment is released to any branch that names that
    environment and that environment's own policy allows. An organisation secret is
    released to the repository's workflows too. Any of these, and a write collaborator
    could push a branch whose test workflow (which runs on any push) binds the value to a
    variable and prints it, with no review - and with the lint that would catch it inside
    the very file they edited. The environment's branch policy protects nothing if a
    second copy of the key is not behind it.
    """
    spec = policy["governance"]["environment"]
    forbidden = set(spec["environment_only_secrets"])
    problems: list[str] = []

    names, complete = _secret_names(fetch, f"/repos/{repository}/actions/secrets", "the repository's secrets")
    if not complete:
        problems.append("the repository's secrets could not be listed in full")
    if forbidden & names:
        problems.append(f"{sorted(forbidden & names)} exist as repository secrets, released to every branch")

    listing = _get(fetch, f"/repos/{repository}/environments", "the repository's environments")
    environments = listing.get("environments") if isinstance(listing, dict) else None
    total = listing.get("total_count") if isinstance(listing, dict) else None
    if not isinstance(environments, list) or isinstance(total, bool) or not isinstance(total, int):
        raise PolicyError("the repository's environments are not readable as a list")
    if total != len(environments):
        problems.append("the repository's environments could not be listed in full")
    for environment in environments:
        name = environment.get("name") if isinstance(environment, dict) else None
        if not isinstance(name, str):
            raise PolicyError("an environment is not readable as an object")
        if name == spec["name"]:
            continue
        others, others_complete = _secret_names(
            fetch, f"/repos/{repository}/environments/{name}/secrets", f"the secrets of environment {name}"
        )
        if not others_complete:
            problems.append(f"the secrets of environment {name} could not be listed in full")
        if forbidden & others:
            problems.append(f"{sorted(forbidden & others)} also exist in environment {name}")

    if owner_type != "User":
        # An organisation can share its own secrets with the repository. A user account
        # has none, so the listing is skipped there rather than made to fail.
        org, org_complete = _secret_names(
            fetch, f"/repos/{repository}/actions/organization-secrets", "the organisation secrets"
        )
        if not org_complete or forbidden & org:
            problems.append("the credential is shared from the organisation, or the listing was incomplete")
    return not problems, problems


def observe(
    policy: Mapping[str, Any],
    environ: Mapping[str, str],
    fetch: Fetch | None = None,
) -> dict[str, Any]:
    """The anchor's enforced governance, or a refusal naming what is missing.

    Returns a record meant to travel inside the capture, so that a verdict
    cannot exist without a positive governance observation bound to the same
    digest as everything else the run establishes.
    """
    fetch = fetch or _default_fetch
    required = policy["governance"]
    repository = environ.get("GITHUB_REPOSITORY", "")
    if not repository or repository.count("/") != 1:
        raise PolicyError(f"GITHUB_REPOSITORY {repository!r} is not owner/name")
    branch = required["required_ref"].rsplit("/", 1)[-1]

    # 1. Identity first. The rules below mean nothing if they describe another repository.
    described = _get(fetch, f"/repos/{repository}", "the anchor repository")
    problems = _check_repository(described, policy, branch)

    rules = _get(
        fetch,
        f"/repos/{repository}/rules/branches/{branch}",
        f"the rules in force on {branch}",
    )
    index = _rule_index(rules)
    if not index:
        raise PolicyError(
            f"no rule is in force on {branch}; an unprotected branch is not a trust root"
        )
    problems.extend(_check_rules(index, policy, branch))

    # 2. Who can step around all of it. A rule with an open bypass list is a rule
    #    for everyone except the people most able to misuse it.
    inspected, ruleset_problems = _inspect_rulesets(fetch, repository, index, policy)
    problems.extend(ruleset_problems)

    # 3. Who can read the credential.
    environment, environment_problems = _inspect_environment(fetch, repository, policy)
    problems.extend(environment_problems)
    secrets_only_in_environment, secret_problems = _inspect_secrets(
        fetch, repository, policy, _owner_type(described)
    )
    problems.extend(secret_problems)

    if problems:
        raise PolicyError("; ".join(problems))

    approvals, dismiss, last_push = _pull_request_facts(index)
    observation: dict[str, Any] = {
        "governance_version": GOVERNANCE_VERSION,
        "repository": repository,
        "repository_id": described["id"],
        # What GitHub reported, not what policy wished: the check above refused unless
        # these satisfied policy, and recording policy's own numbers here would make
        # the verifier compare policy with itself.
        "repository_private": described.get("private"),
        "default_branch": described.get("default_branch"),
        "ref": required["required_ref"],
        "rules_in_force": sorted(index),
        "rulesets": inspected,
        "observed_approvals": approvals,
        "dismiss_stale_reviews": dismiss,
        "last_push_approval": last_push,
        "strict_status_checks": all(
            (rule.get("parameters") or {}).get("strict_required_status_checks_policy") is True
            for rule in index.get("required_status_checks", [])
        ),
        "status_check_contexts": _status_check_contexts(
            index, required["required_status_check_integration_id"]
        ),
        "credential_only_in_environment": secrets_only_in_environment,
        "environment": environment,
    }
    observation["observation_digest"] = _digest(observation)
    return observation

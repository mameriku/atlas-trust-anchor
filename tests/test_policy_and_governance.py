"""Identity, policy, scope, and the anchor's own governance - asked, never assumed.

Governance is the property that makes this repository a trust root: whoever can
change the default branch can change the judge. It is checked as the enforced
property (rules, approvals, checks, bypass, who can read the credential), on a
public repository, on GitHub Free. Nothing here keys on a plan name, and the
first thing several of these tests establish is that an answer GitHub could not
give is a refusal - most importantly a ruleset that does not DISCLOSE its bypass
list, which is not the same thing as an empty one.
"""

from __future__ import annotations

import ast
import copy
import json

import pytest

from support import (
    ANCHOR,
    ANCHOR_ID,
    ANCHOR_REPO,
    HOST_KEY,
    IMAGE,
    SHA_A,
    SHA_B,
    WORKFLOW_REF,
    good_environment,
    governed_observation,
    make_policy,
    policy_document,
    run_entry,
)

import governance as governance_module  # noqa: E402
import governance_record  # noqa: E402
import policy as policy_module  # noqa: E402
from policy import PolicyError  # noqa: E402


def loaded(tmp_path, **overrides):
    return policy_module.load(make_policy(tmp_path, **overrides))


# ==========================================================================
# identity: the caller selects what is judged, never who judges
# ==========================================================================


def test_the_expected_environment_is_accepted(tmp_path):
    policy_module.assert_anchor_identity(loaded(tmp_path), good_environment())


@pytest.mark.parametrize(
    "override, expected",
    [
        ({"GITHUB_WORKFLOW_REF": WORKFLOW_REF.replace("heads/main", "heads/evil")}, "workflow ref"),
        ({"GITHUB_WORKFLOW_REF": WORKFLOW_REF.replace("refs/heads/main", "refs/tags/v1")}, "workflow ref"),
        ({"GITHUB_WORKFLOW_REF": WORKFLOW_REF.replace("qualify.yml", "other.yml")}, "workflow ref"),
        ({"GITHUB_WORKFLOW_REF": ""}, "workflow ref"),
        ({"GITHUB_REF": "refs/heads/feature"}, "ref"),
        ({"GITHUB_REPOSITORY_ID": "1"}, "repository id"),
        ({"GITHUB_REPOSITORY_ID": ""}, "repository id"),
        ({"GITHUB_REPOSITORY": "someone-else/renamed"}, "repository 'someone-else/renamed'"),
        ({"GITHUB_REPOSITORY": ""}, "repository ''"),
        ({"GITHUB_WORKFLOW_SHA": SHA_B}, "the workflow came from"),
        ({"GITHUB_WORKFLOW_SHA": "abc"}, "not a full commit sha"),
        ({"GITHUB_EVENT_NAME": "pull_request"}, "event"),
        ({"GITHUB_EVENT_NAME": "push"}, "event"),
        ({"GITHUB_EVENT_NAME": ""}, "event"),
        ({"GITHUB_ACTOR": "intruder"}, "GITHUB_ACTOR"),
        ({"GITHUB_TRIGGERING_ACTOR": "intruder"}, "GITHUB_TRIGGERING_ACTOR"),
        ({"GITHUB_TRIGGERING_ACTOR": ""}, "GITHUB_TRIGGERING_ACTOR"),
        ({"RUNNER_ENVIRONMENT": "self-hosted"}, "github-hosted"),
        ({"RUNNER_ENVIRONMENT": ""}, "github-hosted"),
    ],
)
def test_a_run_that_is_not_the_protected_workflow_started_by_a_named_principal_is_refused(
    tmp_path, override, expected
):
    """workflow_dispatch lets the caller supply a ref, and anyone with write access
    can dispatch. GITHUB_WORKFLOW_REF names the workflow file *and the ref it ran
    at*; the actor lists say who started it; RUNNER_ENVIRONMENT says whose machine."""
    with pytest.raises(PolicyError) as error:
        policy_module.assert_anchor_identity(loaded(tmp_path), good_environment(**override))
    assert expected in str(error.value)


def test_a_renamed_repository_is_a_refusal_not_a_silent_continuation(tmp_path):
    """The numeric id survives a rename and the name does not, so a rename must go
    through a reviewed policy change rather than being followed."""
    environment = good_environment(GITHUB_REPOSITORY="mameriku/renamed-anchor")
    with pytest.raises(PolicyError, match="repository 'mameriku/renamed-anchor'"):
        policy_module.assert_anchor_identity(loaded(tmp_path), environment)


def test_repository_name_case_is_not_identity(tmp_path):
    environment = good_environment(GITHUB_REPOSITORY=ANCHOR_REPO.upper())
    policy_module.assert_anchor_identity(loaded(tmp_path), environment)


def test_every_problem_is_reported_not_just_the_first(tmp_path):
    with pytest.raises(PolicyError) as error:
        policy_module.assert_anchor_identity(
            loaded(tmp_path),
            good_environment(GITHUB_REF="refs/heads/x", GITHUB_ACTOR="nobody", GITHUB_EVENT_NAME="push"),
        )
    text = str(error.value)
    assert "ref" in text and "GITHUB_ACTOR" in text and "event" in text


def test_the_gate_entry_point_refuses_a_side_branch(tmp_path):
    completed = run_entry(
        "gate.py", "--policy", str(make_policy(tmp_path)),
        "--observation-out", str(tmp_path / "observation.json"),
        env=good_environment(GITHUB_REF="refs/heads/side"),
    )
    assert completed.returncode == 2
    assert "REFUSE" in completed.stdout and "GATE_REFUSED" in completed.stdout
    assert not (tmp_path / "observation.json").exists()


def test_the_identity_only_gate_still_refuses_an_unnamed_principal(tmp_path):
    completed = run_entry(
        "gate.py", "--policy", str(make_policy(tmp_path)), "--identity-only",
        env=good_environment(GITHUB_ACTOR="intruder"),
    )
    assert completed.returncode == 2


def test_the_identity_only_gate_passes_the_expected_run(tmp_path):
    completed = run_entry(
        "gate.py", "--policy", str(make_policy(tmp_path)), "--identity-only", env=good_environment()
    )
    assert completed.returncode == 0, completed.stdout


def test_a_trusted_entry_point_refuses_an_unisolated_interpreter(tmp_path):
    """Without -I -S -B the evaluator stops rather than running degraded."""
    import os
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, str(ANCHOR / "gate.py"), "--policy", str(make_policy(tmp_path)),
         "--identity-only"],
        capture_output=True, text=True, env={**os.environ, **good_environment()}, check=False,
    )
    assert completed.returncode != 0
    assert "isolated" in completed.stdout + completed.stderr


def test_isolation_is_asserted_not_assumed():
    with pytest.raises(PolicyError, match="isolated"):
        policy_module.assert_isolated()


# ==========================================================================
# policy: the shape it must have, and the shapes it must never have
# ==========================================================================


def test_an_anchor_that_does_not_know_its_own_id_refuses_to_run(tmp_path):
    document = policy_document()
    document["anchor"]["repository_id"] = None
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="numeric id"):
        policy_module.load(path)


SHIPPED_ANCHOR_REPOSITORY = "mameriku/atlas-trust-anchor"
SHIPPED_ANCHOR_ID = 1392950051  # read from GitHub for the public repository above


def test_the_shipped_policy_is_bound_to_the_real_public_anchor_repository():
    """The first public commit already names the repository it lives in, so there is
    never a public `main` whose policy refuses to run for want of its own id."""
    document = json.loads((ANCHOR / "policy.json").read_text(encoding="utf-8"))
    identity = document["anchor"]["repository_id"]
    assert identity == SHIPPED_ANCHOR_ID and type(identity) is int
    assert document["anchor"]["repository"] == SHIPPED_ANCHOR_REPOSITORY


def test_the_shipped_policy_loads_and_is_valid_as_shipped():
    policy = policy_module.load(ANCHOR / "policy.json")
    assert policy["anchor"]["repository_id"] == SHIPPED_ANCHOR_ID
    assert policy["anchor"]["visibility"] == "public"
    assert policy["target"]["visibility"] == "private"
    assert policy["disclosure"]["private_transport"] == "none"
    assert policy["credential"]["host_key"] == HOST_KEY


def test_the_shipped_policy_accepts_its_own_repository_and_refuses_any_other_id():
    policy = policy_module.load(ANCHOR / "policy.json")
    own = good_environment(
        GITHUB_REPOSITORY_ID=str(SHIPPED_ANCHOR_ID),
        GITHUB_REPOSITORY=SHIPPED_ANCHOR_REPOSITORY,
        GITHUB_WORKFLOW_REF=policy["anchor"]["workflow_ref"],
    )
    policy_module.assert_anchor_identity(policy, own)
    for other in (str(SHIPPED_ANCHOR_ID + 1), "1", "", "null"):
        with pytest.raises(PolicyError, match="repository id"):
            policy_module.assert_anchor_identity(policy, {**own, "GITHUB_REPOSITORY_ID": other})


@pytest.mark.parametrize(
    "anchor, target",
    [("private", "private"), ("public", "public"), ("private", "public"), ("internal", "private"), ("", "private")],
)
def test_only_a_public_anchor_judging_a_private_target_is_a_supported_topology(tmp_path, anchor, target):
    document = policy_document()
    document["anchor"]["visibility"] = anchor
    document["target"]["visibility"] = target
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="topology"):
        policy_module.load(path)


@pytest.mark.parametrize("value", ["upload", "artifact", True, False, None, "", "NONE"])
def test_there_is_no_setting_that_permits_private_bytes_to_cross_a_public_boundary(tmp_path, value):
    document = policy_document()
    document["disclosure"] = {"private_transport": value, "publish_floor_digests": True}
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="private_transport"):
        policy_module.load(path)


def test_the_old_escape_hatch_is_not_honoured(tmp_path):
    """The private-anchor policy had `candidate_bytes_may_be_published`. It is gone,
    and setting it does not reopen anything."""
    document = policy_document()
    document["disclosure"]["candidate_bytes_may_be_published"] = True
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert policy_module.load(path)["disclosure"]["private_transport"] == "none"


def test_a_policy_without_a_disclosure_statement_is_refused(tmp_path):
    document = policy_document()
    del document["disclosure"]
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="private_transport"):
        policy_module.load(path)


@pytest.mark.parametrize(
    "image",
    [
        "python:3.12-slim",
        "python:latest",
        "python@sha256:abc",
        "python:3.12@sha256:" + "G" * 64,
        "python:3.12@sha512:" + "1" * 64,
        "",
        None,
    ],
)
def test_a_sandbox_image_that_is_not_pinned_by_digest_is_refused(tmp_path, image):
    document = policy_document()
    document["sandbox"]["image"] = image
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="pinned"):
        policy_module.load(path)


@pytest.mark.parametrize(
    "field", ["timeout_seconds", "memory_mb", "cpus", "pids_limit", "max_output_bytes", "max_file_bytes", "tmpfs_mb"]
)
@pytest.mark.parametrize("value", [0, -1, "many", None, True])
def test_a_sandbox_limit_that_is_not_a_positive_integer_is_refused(tmp_path, field, value):
    """An unbounded box is not a box."""
    document = policy_document()
    document["sandbox"][field] = value
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match=field):
        policy_module.load(path)


@pytest.mark.parametrize(
    "host_key",
    ["", None, "ssh-rsa AAAAB3NzaC1yc2E", "github.com ssh-ed25519 AAAA", "ssh-ed25519 notbase64!!", HOST_KEY + " extra"],
)
def test_a_missing_or_unpinned_host_key_is_refused(tmp_path, host_key):
    document = policy_document()
    document["credential"]["host_key"] = host_key
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="host_key"):
        policy_module.load(path)


@pytest.mark.parametrize("actors", [[], None, "mameriku", [""], ["a b"], [1], ["-lead"], ["x" * 40]])
def test_a_policy_that_names_nobody_who_may_start_a_run_is_refused(tmp_path, actors):
    document = policy_document()
    document["trigger"]["actors"] = actors
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="actors"):
        policy_module.load(path)


@pytest.mark.parametrize("event", ["pull_request", "push", "pull_request_target", "schedule", ""])
def test_a_policy_that_allows_any_trigger_but_dispatch_is_refused(tmp_path, event):
    document = policy_document()
    document["trigger"]["event"] = event
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="trigger.event"):
        policy_module.load(path)


@pytest.mark.parametrize("kind", ["pat", "token", "app", "", None])
def test_only_a_deploy_key_is_a_supported_credential(tmp_path, kind):
    document = policy_document()
    document["credential"]["kind"] = kind
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="deploy-key"):
        policy_module.load(path)


@pytest.mark.parametrize(
    "section", ["anchor", "target", "limits", "required_inputs_floor", "trigger", "credential", "sandbox", "governance", "disclosure"]
)
def test_a_policy_missing_a_section_is_refused(tmp_path, section):
    document = policy_document()
    del document[section]
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError):
        policy_module.load(path)


def test_a_policy_of_an_unknown_version_is_refused(tmp_path):
    with pytest.raises(PolicyError, match="policy version"):
        loaded(tmp_path, policy_version="atlas-anchor-policy/1")


def test_a_policy_with_an_empty_floor_is_refused(tmp_path):
    with pytest.raises(PolicyError, match="establish nothing"):
        loaded(tmp_path, required_inputs_floor=[])


def test_a_policy_that_requires_no_rule_is_refused(tmp_path):
    document = policy_document()
    document["governance"]["required_rules"] = []
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="required_rules"):
        policy_module.load(path)


def test_a_policy_that_requires_no_status_check_is_refused(tmp_path):
    document = policy_document()
    document["governance"]["required_status_checks"] = []
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="required_status_checks"):
        policy_module.load(path)


def test_status_checks_cannot_be_required_by_name_only(tmp_path):
    document = policy_document()
    document["governance"]["required_rules"] = ["deletion", "non_fast_forward", "pull_request"]
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="omits"):
        policy_module.load(path)


@pytest.mark.parametrize("value", [-1, "1", "0", 0.0, 1.5, True, False, None])
def test_a_policy_whose_approval_requirement_is_not_a_non_negative_integer_is_refused(tmp_path, value):
    document = policy_document()
    document["governance"]["required_approvals"] = value
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="required_approvals"):
        policy_module.load(path)


@pytest.mark.parametrize(
    "flag", ["require_last_push_approval", "require_dismiss_stale_reviews", "require_empty_bypass"]
)
@pytest.mark.parametrize("value", ["yes", 1, None])
def test_a_malformed_governance_flag_is_refused(tmp_path, flag, value):
    document = policy_document()
    document["governance"][flag] = value
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match=flag):
        policy_module.load(path)


# ==========================================================================
# scope: a caller may widen a run, never narrow it
# ==========================================================================


def test_an_empty_manifest_still_qualifies_the_whole_floor(tmp_path):
    assert policy_module.effective_scope(loaded(tmp_path), "") == ["scripts/one.py", "scripts/two.py"]


def test_a_manifest_naming_one_trivial_path_cannot_shrink_the_run(tmp_path):
    assert policy_module.effective_scope(loaded(tmp_path), "README.md") == [
        "README.md", "scripts/one.py", "scripts/two.py",
    ]


def test_a_manifest_may_widen_the_run(tmp_path):
    assert policy_module.effective_scope(loaded(tmp_path), "extra/a.py\nextra/b.py\n") == [
        "extra/a.py", "extra/b.py", "scripts/one.py", "scripts/two.py",
    ]


def test_a_manifest_that_repeats_an_input_is_refused(tmp_path):
    with pytest.raises(PolicyError, match="repeats"):
        policy_module.effective_scope(loaded(tmp_path), "a.py\na.py\n")


@pytest.mark.parametrize(
    "path",
    ["../escape.py", "/etc/passwd", "scripts\\one.py", "a//b.py", "./a.py", "C:/x.py", "a/../b.py", "a\x00b.py", "a\nb\x07.py"],
)
def test_a_manifest_path_that_leaves_the_candidate_or_hides_in_it_is_refused(tmp_path, path):
    with pytest.raises(PolicyError):
        policy_module.effective_scope(loaded(tmp_path), path)


def test_a_whitespace_only_manifest_is_the_floor_not_an_error(tmp_path):
    assert policy_module.effective_scope(loaded(tmp_path), "\n   \n\t\n") == [
        "scripts/one.py", "scripts/two.py",
    ]


@pytest.mark.parametrize("value", ["abc123", SHA_A.upper(), "", "z" * 40, SHA_A + "0"])
def test_a_candidate_that_is_not_a_full_lowercase_sha_is_refused(value):
    with pytest.raises(PolicyError):
        policy_module.assert_full_sha(value, "candidate")


# ==========================================================================
# governance: a fake GitHub that can be made to say anything
# ==========================================================================

REPO = ANCHOR_REPO
ENV = "atlas-qualification"


def base_answers():
    return {
        f"/repos/{REPO}": {
            "id": ANCHOR_ID, "full_name": REPO, "private": False, "visibility": "public",
            "default_branch": "main", "owner": {"type": "User"},
        },
        f"/repos/{REPO}/rules/branches/main": [
            {"type": "deletion", "ruleset_id": 1},
            {"type": "non_fast_forward", "ruleset_id": 1},
            {
                "type": "pull_request", "ruleset_id": 1,
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_last_push_approval": True,
                },
            },
            {
                "type": "required_status_checks", "ruleset_id": 1,
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [{"context": "test", "integration_id": 15368}],
                },
            },
        ],
        f"/repos/{REPO}/rulesets/1": {
            "id": 1, "name": "anchor", "enforcement": "active", "target": "branch", "bypass_actors": [],
        },
        f"/repos/{REPO}/environments/{ENV}": {
            "name": ENV,
            "can_admins_bypass": False,
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        },
        f"/repos/{REPO}/actions/secrets": {"total_count": 0, "secrets": []},
        f"/repos/{REPO}/environments": {"total_count": 1, "environments": [{"name": ENV}]},
        f"/repos/{REPO}/environments/{ENV}/deployment-branch-policies": {
            "total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}],
        },
    }


def fetcher(mutate=None, statuses=None):
    """A GitHub that answers from `base_answers`, edited by `mutate`, failing where told."""
    answers = copy.deepcopy(base_answers())
    if mutate:
        mutate(answers)
    failing = statuses or {}

    def fetch(path):
        for fragment, status in failing.items():
            if path.endswith(fragment):
                return status, {"message": "synthetic"}
        if path not in answers:
            return 404, {}
        return 200, answers[path]

    return fetch


def observe(tmp_path, mutate=None, statuses=None):
    return governance_module.observe(
        loaded(tmp_path), good_environment(), fetcher(mutate, statuses)
    )


def rules(answers):
    return answers[f"/repos/{REPO}/rules/branches/main"]


def ruleset(answers):
    return answers[f"/repos/{REPO}/rulesets/1"]


def refused(tmp_path, mutate=None, statuses=None, match=None):
    with pytest.raises(PolicyError, match=match) as error:
        observe(tmp_path, mutate, statuses)
    return str(error.value)


def test_a_protected_public_anchor_produces_a_bound_observation(tmp_path):
    observation = observe(tmp_path)
    assert observation["repository_private"] is False
    assert observation["environment"] == {
        "name": ENV, "deployment_branches": ["main"], "admins_can_bypass": False,
    }
    assert observation["observed_approvals"] == 1 and observation["last_push_approval"] is True
    assert observation["credential_only_in_environment"] is True
    assert observation["status_check_contexts"] == ["test"]
    assert sorted(observation["rules_in_force"]) == [
        "deletion", "non_fast_forward", "pull_request", "required_status_checks",
    ]
    assert governance_record.acceptable(observation, loaded(tmp_path)) == []


@pytest.mark.parametrize("status", [401, 403, 404, 500, 502, 0])
@pytest.mark.parametrize(
    "endpoint",
    [
        f"/repos/{REPO}", "/rules/branches/main", "/rulesets/1", f"/environments/{ENV}",
        "/deployment-branch-policies", "/actions/secrets",
    ],
)
def test_every_endpoint_that_cannot_be_read_is_a_refusal(tmp_path, endpoint, status):
    refused(tmp_path, statuses={endpoint: status})


def test_a_403_says_what_it_probably_means_and_never_names_a_plan(tmp_path):
    message = refused(tmp_path, statuses={"/rulesets/1": 403})
    assert "ANCHOR_GOVERNANCE_TOKEN" in message
    for word in ("Pro", "upgrade", "Upgrade", "plan", "paid"):
        assert word not in message


def test_no_rule_in_force_is_a_refusal(tmp_path):
    refused(tmp_path, lambda a: a.__setitem__(f"/repos/{REPO}/rules/branches/main", []), match="no rule is in force")


@pytest.mark.parametrize("missing", ["deletion", "non_fast_forward", "pull_request", "required_status_checks"])
def test_a_missing_required_rule_is_a_refusal(tmp_path, missing):
    def mutate(answers):
        answers[f"/repos/{REPO}/rules/branches/main"] = [r for r in rules(answers) if r["type"] != missing]

    refused(tmp_path, mutate, match=missing)


@pytest.mark.parametrize("approvals", [0, None, "1", True])
def test_too_few_or_unreadable_required_approvals_is_a_refusal(tmp_path, approvals):
    def mutate(answers):
        rules(answers)[2]["parameters"]["required_approving_review_count"] = approvals

    refused(tmp_path, mutate, match="approvals")


def test_stale_approvals_that_survive_a_push_are_a_refusal(tmp_path):
    def mutate(answers):
        rules(answers)[2]["parameters"]["dismiss_stale_reviews_on_push"] = False

    refused(tmp_path, mutate, match="stale")


def test_a_required_status_check_that_is_not_the_anchors_own_test_is_a_refusal(tmp_path):
    def mutate(answers):
        rules(answers)[3]["parameters"]["required_status_checks"] = [{"context": "lint"}]

    refused(tmp_path, mutate, match="'test'")


def test_a_status_check_rule_with_no_checks_is_a_refusal(tmp_path):
    def mutate(answers):
        rules(answers)[3]["parameters"] = {"required_status_checks": []}

    refused(tmp_path, mutate, match="'test'")


def test_a_non_empty_bypass_list_is_a_refusal(tmp_path):
    def mutate(answers):
        ruleset(answers)["bypass_actors"] = [{"actor_id": 5, "actor_type": "RepositoryRole"}]

    refused(tmp_path, mutate, match="bypass")


@pytest.mark.parametrize("value", [None, "none", {}, 0, False])
def test_a_bypass_list_that_is_not_disclosed_is_not_an_empty_one(tmp_path, value):
    """GitHub omits `bypass_actors` from callers not allowed to see it. Reading a
    missing field as [] would turn a token's lack of permission into a passing check."""

    def mutate(answers):
        if value is None:
            del ruleset(answers)["bypass_actors"]
        else:
            ruleset(answers)["bypass_actors"] = value

    message = refused(tmp_path, mutate, match="bypass")
    assert "does not disclose" in message


@pytest.mark.parametrize("enforcement", ["evaluate", "disabled", "", None])
def test_a_ruleset_that_is_not_active_is_a_refusal(tmp_path, enforcement):
    def mutate(answers):
        ruleset(answers)["enforcement"] = enforcement

    refused(tmp_path, mutate, match="not 'active'")


def test_a_ruleset_that_does_not_target_a_branch_is_a_refusal(tmp_path):
    def mutate(answers):
        ruleset(answers)["target"] = "tag"

    refused(tmp_path, mutate, match="not a branch")


def test_rules_attributable_to_no_ruleset_are_a_refusal(tmp_path):
    def mutate(answers):
        for rule in rules(answers):
            rule.pop("ruleset_id")

    refused(tmp_path, mutate, match="no ruleset")


def test_a_repository_identity_mismatch_is_a_refusal(tmp_path):
    refused(tmp_path, lambda a: a[f"/repos/{REPO}"].__setitem__("id", 7), match="reports id")


def test_a_repository_that_has_been_renamed_is_a_refusal(tmp_path):
    refused(tmp_path, lambda a: a[f"/repos/{REPO}"].__setitem__("full_name", "mameriku/other"), match="is named")


@pytest.mark.parametrize("field, value", [("private", True), ("private", None), ("visibility", "private"), ("visibility", "internal")])
def test_an_anchor_that_is_not_public_is_a_refusal(tmp_path, field, value):
    refused(tmp_path, lambda a: a[f"/repos/{REPO}"].__setitem__(field, value), match="not public")


@pytest.mark.parametrize("branch", ["master", "develop", "", None])
def test_a_default_branch_that_is_not_the_protected_one_is_a_refusal(tmp_path, branch):
    refused(tmp_path, lambda a: a[f"/repos/{REPO}"].__setitem__("default_branch", branch), match="default branch")


def test_an_environment_that_does_not_restrict_deployment_is_a_refusal(tmp_path):
    def mutate(answers):
        answers[f"/repos/{REPO}/environments/{ENV}"]["deployment_branch_policy"] = None

    refused(tmp_path, mutate, match="does not restrict")


@pytest.mark.parametrize(
    "policies",
    [
        [],
        [{"name": "main", "type": "branch"}, {"name": "feature/*", "type": "branch"}],
        [{"name": "*", "type": "branch"}],
        [{"name": "release", "type": "branch"}],
        [{"name": "main", "type": "tag"}],
        [{"name": "main", "type": "branch"}, {"name": "v1", "type": "tag"}],
    ],
)
def test_an_environment_that_releases_its_secrets_to_anything_but_main_is_a_refusal(tmp_path, policies):
    """Otherwise a workflow on any other branch could read the deploy key, and
    every check above would be one the attacker simply did not run."""

    def mutate(answers):
        answers[f"/repos/{REPO}/environments/{ENV}/deployment-branch-policies"] = {
            "total_count": len(policies), "branch_policies": policies,
        }

    refused(tmp_path, mutate, match="releases to")


@pytest.mark.parametrize("payload", [{}, [], "text", None, {"branch_policies": "x"}])
def test_an_unreadable_deployment_policy_payload_is_a_refusal(tmp_path, payload):
    refused(tmp_path, lambda a: a.__setitem__(f"/repos/{REPO}/environments/{ENV}/deployment-branch-policies", payload))


@pytest.mark.parametrize("payload", [{}, "text", None, {"type": "x"}, [1], [{"no": "type"}]])
def test_an_unreadable_rules_payload_is_a_refusal(tmp_path, payload):
    refused(tmp_path, lambda a: a.__setitem__(f"/repos/{REPO}/rules/branches/main", payload))


@pytest.mark.parametrize("value", ["", "no-slash", "a/b/c"])
def test_a_malformed_repository_name_is_a_refusal(tmp_path, value):
    with pytest.raises(PolicyError, match="owner/name"):
        governance_module.observe(loaded(tmp_path), good_environment(GITHUB_REPOSITORY=value), fetcher())


def test_no_token_at_all_is_an_inability_to_establish_governance_not_an_absence_of_rules(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("ANCHOR_GOVERNANCE_TOKEN", raising=False)
    status, _ = governance_module._default_fetch("/repos/x/y")
    assert status == 0


def test_the_governance_token_is_preferred_over_the_job_token(monkeypatch):
    seen = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b"{}"

    def fake_open(request, timeout):
        seen["authorization"] = request.get_header("Authorization")
        return Response()

    monkeypatch.setenv("GITHUB_TOKEN", "job-token")
    monkeypatch.setenv("ANCHOR_GOVERNANCE_TOKEN", "governance-token")
    monkeypatch.setattr(governance_module.urllib.request, "urlopen", fake_open)
    governance_module._default_fetch("/repos/x/y")
    assert seen["authorization"] == "Bearer governance-token"


def test_governance_is_never_keyed_on_a_plan_name():
    """A plan name is a proxy, and the only thing a proxy can do is be wrong."""
    for name in ("governance.py", "governance_record.py"):
        tree = ast.parse((ANCHOR / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) < 40:
                assert node.value.lower() not in {"plan", "pro", "free", "team", "enterprise"}, name


def test_the_governance_token_is_never_the_target_credential():
    text = (ANCHOR / "governance.py").read_text(encoding="utf-8")
    assert "ATLAS_DEPLOY_KEY" not in text and "ATLAS_READ_TOKEN" not in text


# ==========================================================================
# a recorded observation: what the verifier will and will not believe
# ==========================================================================


def acceptable(tmp_path, observation):
    return governance_record.acceptable(observation, loaded(tmp_path))


def test_a_well_formed_observation_is_acceptable(tmp_path):
    assert acceptable(tmp_path, governed_observation()) == []


@pytest.mark.parametrize("observation", [None, {}, [], "text", 7])
def test_a_run_with_no_observation_is_refused(tmp_path, observation):
    assert acceptable(tmp_path, observation)


@pytest.mark.parametrize(
    "override, code",
    [
        ({"governance_version": "atlas-anchor-governance/1"}, "GOVERNANCE_VERSION"),
        ({"repository_id": 1}, "GOVERNANCE_OTHER_REPOSITORY"),
        ({"repository_private": True}, "GOVERNANCE_NOT_PUBLIC"),
        ({"repository_private": None}, "GOVERNANCE_NOT_PUBLIC"),
        ({"default_branch": "master"}, "GOVERNANCE_WRONG_REF"),
        ({"ref": "refs/heads/other"}, "GOVERNANCE_WRONG_REF"),
        ({"rules_in_force": []}, "GOVERNANCE_NO_RULES"),
        ({"rules_in_force": ["deletion"]}, "GOVERNANCE_RULE_MISSING"),
        ({"observed_approvals": 0}, "GOVERNANCE_APPROVALS"),
        ({"observed_approvals": None}, "GOVERNANCE_APPROVALS"),
        ({"observed_approvals": True}, "GOVERNANCE_APPROVALS"),
        ({"dismiss_stale_reviews": False}, "GOVERNANCE_STALE_REVIEWS"),
        ({"last_push_approval": False}, "GOVERNANCE_LAST_PUSH"),
        ({"last_push_approval": None}, "GOVERNANCE_LAST_PUSH"),
        ({"strict_status_checks": False}, "GOVERNANCE_STRICT_CHECKS"),
        ({"credential_only_in_environment": False}, "GOVERNANCE_SECRET_SCOPE"),
        ({"credential_only_in_environment": "yes"}, "GOVERNANCE_SECRET_SCOPE"),
        ({"status_check_contexts": []}, "GOVERNANCE_STATUS_CHECKS"),
        ({"status_check_contexts": ["lint"]}, "GOVERNANCE_STATUS_CHECKS"),
        ({"rulesets": []}, "GOVERNANCE_NO_RULESET"),
        ({"rulesets": [{"id": 1, "enforcement": "evaluate", "bypass_actor_count": 0}]}, "GOVERNANCE_RULESET_INACTIVE"),
        ({"rulesets": [{"id": 1, "enforcement": "active", "bypass_actor_count": 2}]}, "GOVERNANCE_BYPASS"),
        ({"rulesets": [{"id": 1, "enforcement": "active", "bypass_actor_count": None}]}, "GOVERNANCE_BYPASS"),
        ({"rulesets": [{"id": 1, "enforcement": "active", "bypass_actor_count": False}]}, "GOVERNANCE_BYPASS"),
        ({"rulesets": [{"id": 1, "enforcement": "active", "bypass_actor_count": 0.0}]}, "GOVERNANCE_BYPASS"),
        ({"rulesets": [{"id": 1, "enforcement": "active", "bypass_actor_count": "0"}]}, "GOVERNANCE_BYPASS"),
        ({"rulesets": ["not a dict"]}, "GOVERNANCE_RULESET_INACTIVE"),
        ({"environment": None}, "GOVERNANCE_ENVIRONMENT"),
        (
            {"environment": {"name": ENV, "deployment_branches": ["main"], "admins_can_bypass": True}},
            "GOVERNANCE_ENVIRONMENT",
        ),
        ({"environment": {"name": ENV, "deployment_branches": ["main"]}}, "GOVERNANCE_ENVIRONMENT"),
        ({"environment": {"name": ENV, "deployment_branches": ["main", "dev"], "admins_can_bypass": False}}, "GOVERNANCE_ENVIRONMENT"),
        ({"environment": {"name": "other", "deployment_branches": ["main"], "admins_can_bypass": False}}, "GOVERNANCE_ENVIRONMENT"),
    ],
)
def test_an_observation_that_does_not_establish_protection_is_refused_with_a_fixed_code(
    tmp_path, override, code
):
    assert code in acceptable(tmp_path, governed_observation(**override))


def test_an_observation_edited_after_it_was_made_is_refused(tmp_path):
    observation = governed_observation()
    observation["required_approvals"] = 9
    assert "GOVERNANCE_DIGEST" in acceptable(tmp_path, observation)


def test_the_verifier_never_contacts_github_itself():
    """Not by its own imports, and not by anything those import."""
    seen: set[str] = set()

    def closure(name: str) -> None:
        path = ANCHOR / f"{name}.py"
        if name in seen or not path.exists():
            return
        seen.add(name)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    closure(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                closure(node.module.split(".")[0])

    closure("verify")
    external: set[str] = set()
    for name in seen:
        for node in ast.walk(ast.parse((ANCHOR / f"{name}.py").read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                external.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                external.add(node.module.split(".")[0])
    assert not external & {"subprocess", "urllib", "socket", "http", "ssl", "requests", "ftplib", "smtplib"}
    assert "governance" not in seen and "sandbox" not in seen and "target" not in seen


# ==========================================================================
# the credential must exist only behind the environment, and every review
# rule must be one a second person - not a name anyone can post - satisfies
# ==========================================================================


@pytest.mark.parametrize("secret", ["ATLAS_DEPLOY_KEY", "ANCHOR_GOVERNANCE_TOKEN"])
def test_a_credential_that_also_exists_as_a_repository_secret_is_a_refusal(tmp_path, secret):
    """A repository-level copy is released to every workflow on every branch, so any write
    collaborator could print it from a branch of their own - the environment's branch
    policy protects nothing if a second copy is not behind it."""

    def mutate(answers):
        answers[f"/repos/{REPO}/actions/secrets"] = {"total_count": 1, "secrets": [{"name": secret}]}

    message = refused(tmp_path, mutate, match="repository secrets")
    assert secret in message


def test_a_secrets_listing_that_is_not_complete_is_a_refusal(tmp_path):
    def mutate(answers):
        answers[f"/repos/{REPO}/actions/secrets"] = {"total_count": 5, "secrets": []}

    refused(tmp_path, mutate, match="in full")


def test_unrelated_repository_secrets_are_not_a_problem(tmp_path):
    def mutate(answers):
        answers[f"/repos/{REPO}/actions/secrets"] = {"total_count": 1, "secrets": [{"name": "OTHER"}]}

    assert observe(tmp_path, mutate)["credential_only_in_environment"] is True


@pytest.mark.parametrize("payload", [{}, [], "text", None, {"secrets": "x", "total_count": 0}, {"secrets": [], "total_count": True}])
def test_an_unreadable_secrets_payload_is_a_refusal(tmp_path, payload):
    refused(tmp_path, lambda a: a.__setitem__(f"/repos/{REPO}/actions/secrets", payload))


@pytest.mark.parametrize("value", [True, None, "false", 0])
def test_an_environment_that_lets_administrators_bypass_it_is_a_refusal(tmp_path, value):
    def mutate(answers):
        if value is None:
            del answers[f"/repos/{REPO}/environments/{ENV}"]["can_admins_bypass"]
        else:
            answers[f"/repos/{REPO}/environments/{ENV}"]["can_admins_bypass"] = value

    refused(tmp_path, mutate, match="administrators")


@pytest.mark.parametrize("integration", [None, 1, 15369, "15368", True])
def test_a_required_check_from_any_other_integration_does_not_count(tmp_path, integration):
    """Without the integration pinned, anyone who can post a commit status named `test`
    satisfies the check, and the pull request merges with the tests never having run."""

    def mutate(answers):
        check = {"context": "test"}
        if integration is not None:
            check["integration_id"] = integration
        rules(answers)[3]["parameters"]["required_status_checks"] = [check]

    refused(tmp_path, mutate, match="integration")


def test_a_pull_request_rule_that_lets_the_last_pusher_approve_is_a_refusal(tmp_path):
    def mutate(answers):
        rules(answers)[2]["parameters"]["require_last_push_approval"] = False

    refused(tmp_path, mutate, match="last pusher")


def test_status_checks_that_need_not_be_up_to_date_are_a_refusal(tmp_path):
    def mutate(answers):
        rules(answers)[3]["parameters"]["strict_required_status_checks_policy"] = False

    refused(tmp_path, mutate, match="up to date")


def test_the_weakest_pull_request_rule_is_the_one_recorded(tmp_path):
    """Two rulesets can both apply. The observation records what the loosest of them
    allows, so a strict one cannot hide a lax one."""

    def mutate(answers):
        second = copy.deepcopy(rules(answers)[2])
        second["parameters"]["required_approving_review_count"] = 0
        rules(answers).append(second)

    refused(tmp_path, mutate, match="approvals")


def test_the_policy_must_name_every_rule_the_protection_depends_on(tmp_path):
    for dropped in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        document = policy_document()
        document["governance"]["required_rules"] = [
            rule for rule in document["governance"]["required_rules"] if rule != dropped
        ]
        path = tmp_path / f"{dropped}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(PolicyError, match="omits"):
            policy_module.load(path)


@pytest.mark.parametrize("value", [0, -1, True, None, "15368"])
def test_a_policy_must_pin_the_status_check_to_an_integration(tmp_path, value):
    document = policy_document()
    document["governance"]["required_status_check_integration_id"] = value
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="required_status_check_integration_id"):
        policy_module.load(path)


@pytest.mark.parametrize("value", [[], None, "ATLAS_DEPLOY_KEY", [1]])
def test_a_policy_must_name_the_secrets_that_may_only_live_in_the_environment(tmp_path, value):
    document = policy_document()
    document["governance"]["environment"]["environment_only_secrets"] = value
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="environment_only_secrets"):
        policy_module.load(path)


@pytest.mark.parametrize("field", ["max_evidence_bytes", "max_observations", "max_input_bytes"])
def test_a_limit_that_is_a_boolean_is_refused(tmp_path, field):
    document = policy_document()
    document["limits"][field] = True
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match=field):
        policy_module.load(path)


@pytest.mark.parametrize("entry", [" scripts/one.py", "scripts/one.py ", "/scripts/one.py", "scripts//one.py"])
def test_a_floor_entry_that_is_not_already_normalised_is_refused(tmp_path, entry):
    """The floor is compared by string with the freeze, and whitespace around an entry
    would make it look like an extra input whose digests are then hidden."""
    document = policy_document(floor=[entry])
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError):
        policy_module.load(path)

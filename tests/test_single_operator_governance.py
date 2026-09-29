"""The single-operator governance model, checked against the bytes that ship.

The repository is run by one person, so the ruleset asks for no approval and no
last-push approval. Nothing else about the protection of `main` changes. These tests
pin both halves: the two values that were relaxed, and everything that must still
refuse - most of all that a zero approval count does not turn the pull-request rule
into an optional one.

They use the SHIPPED policy and the SHIPPED ruleset, so a change to either file that
loosens more than the two values fails here, not in production.
"""

from __future__ import annotations

import copy
import json

import pytest

from support import ANCHOR, ROOT, good_environment, governed_observation

import governance as governance_module  # noqa: E402
import governance_record  # noqa: E402
import policy as policy_module  # noqa: E402
from policy import PolicyError  # noqa: E402
from test_policy_and_governance import REPO, base_answers  # noqa: E402

SHIPPED_POLICY = ANCHOR / "policy.json"
RULESET = json.loads((ROOT / "governance" / "ruleset-main.json").read_text(encoding="utf-8"))
REQUIRED_RULES = {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}


def shipped_policy():
    return policy_module.load(SHIPPED_POLICY)


def rule_of(kind):
    return next(rule for rule in RULESET["rules"] if rule["type"] == kind)


def shipped_answers(mutate=None):
    """A GitHub that reports exactly what the shipped ruleset would make it report."""
    policy = shipped_policy()
    answers = copy.deepcopy(base_answers())
    answers[f"/repos/{REPO}"]["id"] = policy["anchor"]["repository_id"]
    answers[f"/repos/{REPO}/rules/branches/main"] = [
        {**copy.deepcopy(rule), "ruleset_id": 1} for rule in RULESET["rules"]
    ]
    answers[f"/repos/{REPO}/rulesets/1"] = {
        "id": 1,
        "name": RULESET["name"],
        "enforcement": RULESET["enforcement"],
        "target": RULESET["target"],
        "bypass_actors": copy.deepcopy(RULESET["bypass_actors"]),
    }
    if mutate:
        mutate(answers)
    return answers


def observe_shipped(mutate=None, statuses=None, policy=None):
    answers = shipped_answers(mutate)
    failing = statuses or {}

    def fetch(path):
        for fragment, status in failing.items():
            if path.endswith(fragment):
                return status, {"message": "synthetic"}
        if path not in answers:
            return 404, {}
        return 200, answers[path]

    return governance_module.observe(policy or shipped_policy(), good_environment(), fetch)


def rules(answers):
    return answers[f"/repos/{REPO}/rules/branches/main"]


def pull_request(answers):
    return next(rule for rule in rules(answers) if rule["type"] == "pull_request")


# ==========================================================================
# what ships: the two relaxed values, and everything that is not relaxed
# ==========================================================================


def test_the_shipped_policy_is_the_single_operator_model_and_nothing_looser():
    governance = shipped_policy()["governance"]
    assert governance["required_approvals"] == 0 and type(governance["required_approvals"]) is int
    assert governance["require_last_push_approval"] is False
    assert governance["require_review_thread_resolution"] is True
    assert governance["require_dismiss_stale_reviews"] is True
    assert governance["require_empty_bypass"] is True
    assert set(governance["required_rules"]) == REQUIRED_RULES
    assert governance["required_status_checks"] == ["test"]
    assert governance["required_status_check_integration_id"] == 15368
    assert governance["required_ref"] == "refs/heads/main"
    assert governance["environment"]["deployment_branches"] == ["main"]
    assert governance["environment"]["name"] == "atlas-qualification"


def test_the_shipped_ruleset_still_protects_main_in_every_other_way():
    assert RULESET["enforcement"] == "active" and RULESET["target"] == "branch"
    assert RULESET["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert RULESET["conditions"]["ref_name"]["exclude"] == []
    assert RULESET["bypass_actors"] == []
    assert {rule["type"] for rule in RULESET["rules"]} == REQUIRED_RULES
    assert len(RULESET["rules"]) == len(REQUIRED_RULES), "no rule may be listed twice or added"

    request = rule_of("pull_request")["parameters"]
    assert request["required_approving_review_count"] == 0
    assert request["require_last_push_approval"] is False
    assert request["dismiss_stale_reviews_on_push"] is True
    assert request["required_review_thread_resolution"] is True
    assert request["require_code_owner_review"] is False

    checks = rule_of("required_status_checks")["parameters"]
    assert checks["strict_required_status_checks_policy"] is True
    assert checks["required_status_checks"] == [{"context": "test", "integration_id": 15368}]

    assert "parameters" not in rule_of("deletion") and "parameters" not in rule_of("non_fast_forward")


# ==========================================================================
# the gate accepts the intended ruleset
# ==========================================================================


def test_the_gate_accepts_the_shipped_ruleset_and_records_what_github_reported():
    policy = shipped_policy()
    observation = observe_shipped()
    assert observation["observed_approvals"] == 0
    assert observation["last_push_approval"] is False
    assert observation["review_thread_resolution_required"] is True
    assert observation["dismiss_stale_reviews"] is True
    assert observation["strict_status_checks"] is True
    assert observation["status_check_contexts"] == ["test"]
    assert sorted(observation["rules_in_force"]) == sorted(REQUIRED_RULES)
    assert governance_record.acceptable(observation, policy) == []


@pytest.mark.parametrize("count", [1, 2, 6])
def test_a_stricter_approval_count_than_policy_asks_for_is_accepted(count):
    def stricter(answers):
        pull_request(answers)["parameters"]["required_approving_review_count"] = count

    observation = observe_shipped(stricter)
    assert observation["observed_approvals"] == count
    assert governance_record.acceptable(observation, shipped_policy()) == []


@pytest.mark.parametrize("value", [True, None, "absent"])
def test_a_last_push_rule_that_policy_does_not_require_is_not_required_of_github(value):
    def lax_or_strict(answers):
        parameters = pull_request(answers)["parameters"]
        if value == "absent":
            parameters.pop("require_last_push_approval", None)
        else:
            parameters["require_last_push_approval"] = value

    observation = observe_shipped(lax_or_strict)
    assert governance_record.acceptable(observation, shipped_policy()) == []


@pytest.mark.parametrize("value", [False, None, "absent"])
def test_a_ruleset_that_does_not_require_thread_resolution_is_a_refusal(value):
    def mutate(answers):
        parameters = pull_request(answers)["parameters"]
        if value == "absent":
            parameters.pop("required_review_thread_resolution", None)
        else:
            parameters["required_review_thread_resolution"] = value

    with pytest.raises(PolicyError, match="open review threads"):
        observe_shipped(mutate)


@pytest.mark.parametrize("value", [True, None, "absent"])
def test_a_thread_resolution_rule_that_policy_does_not_require_is_not_required_of_github(tmp_path, value):
    """`require_review_thread_resolution` is a configurable policy flag like
    `require_last_push_approval`, not a hard-coded constant, even though the shipped
    policy always asks for it. A policy that turns it off must actually turn it off."""
    document = json.loads(SHIPPED_POLICY.read_text(encoding="utf-8"))
    document["governance"]["require_review_thread_resolution"] = False
    path = tmp_path / "lax.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    lax = policy_module.load(path)

    def lax_or_strict(answers):
        parameters = pull_request(answers)["parameters"]
        if value == "absent":
            parameters.pop("required_review_thread_resolution", None)
        else:
            parameters["required_review_thread_resolution"] = value

    observation = observe_shipped(lax_or_strict, policy=lax)
    assert governance_record.acceptable(observation, lax) == []


def test_a_recorded_thread_resolution_fact_that_is_not_true_is_refused():
    policy = shipped_policy()
    observation = governed_observation(
        repository_id=policy["anchor"]["repository_id"],
        review_thread_resolution_required=False,
    )
    assert "GOVERNANCE_REVIEW_THREAD_RESOLUTION" in governance_record.acceptable(observation, policy)


# ==========================================================================
# zero approvals must not switch the pull-request requirement off
# ==========================================================================


def test_a_zero_approval_count_still_requires_the_pull_request_rule_to_exist():
    def no_pull_request(answers):
        answers[f"/repos/{REPO}/rules/branches/main"] = [
            rule for rule in rules(answers) if rule["type"] != "pull_request"
        ]

    with pytest.raises(PolicyError, match="pull_request is not enforced"):
        observe_shipped(no_pull_request)


def test_a_recorded_observation_without_the_pull_request_rule_is_refused_at_zero_approvals():
    policy = shipped_policy()
    without = sorted(REQUIRED_RULES - {"pull_request"})
    observation = governed_observation(
        repository_id=policy["anchor"]["repository_id"],
        rules_in_force=without,
        observed_approvals=None,
    )
    reasons = governance_record.acceptable(observation, policy)
    assert "GOVERNANCE_RULE_MISSING" in reasons
    assert "GOVERNANCE_APPROVALS" in reasons


@pytest.mark.parametrize("count", [-1, None, "0", True, False, 0.0, 0.5])
def test_an_unreadable_or_malformed_approval_count_is_refused_even_when_policy_asks_for_zero(count):
    def malformed(answers):
        pull_request(answers)["parameters"]["required_approving_review_count"] = count

    with pytest.raises(PolicyError, match="approvals"):
        observe_shipped(malformed)


@pytest.mark.parametrize("count", [-1, None, "0", True, False, 0.0])
def test_a_recorded_approval_count_that_is_not_an_integer_is_refused_at_zero_approvals(count):
    policy = shipped_policy()
    observation = governed_observation(
        repository_id=policy["anchor"]["repository_id"], observed_approvals=count
    )
    assert "GOVERNANCE_APPROVALS" in governance_record.acceptable(observation, policy)


def test_the_weakest_pull_request_rule_in_force_is_the_one_recorded():
    def second_rule_with_a_higher_count(answers):
        rules(answers).append(
            {
                "type": "pull_request",
                "ruleset_id": 1,
                "parameters": {
                    "required_approving_review_count": 9,
                    "dismiss_stale_reviews_on_push": True,
                    "required_review_thread_resolution": True,
                },
            }
        )

    observation = observe_shipped(second_rule_with_a_higher_count)
    assert observation["observed_approvals"] == 0


# ==========================================================================
# the gate refuses anything weaker than the shipped ruleset
# ==========================================================================


def dropped(kind):
    def mutate(answers):
        answers[f"/repos/{REPO}/rules/branches/main"] = [
            rule for rule in rules(answers) if rule["type"] != kind
        ]

    return mutate


@pytest.mark.parametrize("kind", sorted(REQUIRED_RULES))
def test_dropping_any_required_rule_is_a_refusal(kind):
    with pytest.raises(PolicyError, match=f"{kind} is not enforced"):
        observe_shipped(dropped(kind))


def test_a_status_check_of_the_right_name_from_another_integration_is_a_refusal():
    def other_app(answers):
        for rule in rules(answers):
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"] = [{"context": "test", "integration_id": 1}]

    with pytest.raises(PolicyError, match="integration"):
        observe_shipped(other_app)


def test_status_checks_that_need_not_be_up_to_date_are_a_refusal():
    def lax(answers):
        for rule in rules(answers):
            if rule["type"] == "required_status_checks":
                rule["parameters"]["strict_required_status_checks_policy"] = False

    with pytest.raises(PolicyError, match="up to date"):
        observe_shipped(lax)


def test_stale_approvals_that_survive_a_push_are_a_refusal():
    def lax(answers):
        pull_request(answers)["parameters"]["dismiss_stale_reviews_on_push"] = False

    with pytest.raises(PolicyError, match="stale"):
        observe_shipped(lax)


@pytest.mark.parametrize(
    "bypass",
    [
        [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
        [{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"}],
        None,
        "none",
    ],
)
def test_a_non_empty_or_unreadable_bypass_list_is_a_refusal(bypass):
    def with_bypass(answers):
        answers[f"/repos/{REPO}/rulesets/1"]["bypass_actors"] = bypass

    with pytest.raises(PolicyError):
        observe_shipped(with_bypass)


@pytest.mark.parametrize("enforcement", ["evaluate", "disabled", None])
def test_a_ruleset_that_is_not_active_is_a_refusal(enforcement):
    def inactive(answers):
        answers[f"/repos/{REPO}/rulesets/1"]["enforcement"] = enforcement

    with pytest.raises(PolicyError):
        observe_shipped(inactive)


def test_a_policy_that_asks_for_more_than_the_ruleset_gives_is_refused(tmp_path):
    document = json.loads(SHIPPED_POLICY.read_text(encoding="utf-8"))
    document["governance"]["required_approvals"] = 1
    document["governance"]["require_last_push_approval"] = True
    path = tmp_path / "stricter.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    stricter = policy_module.load(path)
    with pytest.raises(PolicyError, match="approvals"):
        observe_shipped(policy=stricter)


# ==========================================================================
# zero approvals is a value, not a way to drop a rule from policy
# ==========================================================================


def test_a_policy_cannot_drop_the_pull_request_rule_by_asking_for_zero_approvals(tmp_path):
    document = json.loads(SHIPPED_POLICY.read_text(encoding="utf-8"))
    document["governance"]["required_rules"] = [
        rule for rule in document["governance"]["required_rules"] if rule != "pull_request"
    ]
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="omits"):
        policy_module.load(path)


def test_the_last_push_flag_is_required_to_be_stated_in_policy(tmp_path):
    document = json.loads(SHIPPED_POLICY.read_text(encoding="utf-8"))
    del document["governance"]["require_last_push_approval"]
    path = tmp_path / "p.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError, match="require_last_push_approval"):
        policy_module.load(path)


# ==========================================================================
# qualification still fails closed when governance cannot be established
# ==========================================================================


@pytest.mark.parametrize("status", [401, 403, 404, 500, 0])
@pytest.mark.parametrize(
    "endpoint",
    [f"/repos/{REPO}", "/rules/branches/main", "/rulesets/1", "/environments/atlas-qualification", "/actions/secrets"],
)
def test_governance_that_cannot_be_read_refuses_under_the_shipped_policy(endpoint, status):
    with pytest.raises(PolicyError):
        observe_shipped(statuses={endpoint: status})


def test_a_recorded_observation_that_is_absent_or_altered_is_not_accepted():
    policy = shipped_policy()
    assert governance_record.acceptable(None, policy) == ["GOVERNANCE_ABSENT"]
    observation = observe_shipped()
    observation["observed_approvals"] = 5
    assert "GOVERNANCE_DIGEST" in governance_record.acceptable(observation, policy)

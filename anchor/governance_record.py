"""The shape of a governance observation, and the pure check of one.

Split from governance.py so that the verifier can judge a recorded observation
without importing anything that can speak to the network. governance.py OBSERVES:
it asks GitHub, and so imports urllib. This module only READS what was observed,
and imports nothing that could ask.

A recorded observation must (1) exist, (2) be the version this anchor writes, (3)
carry a digest that matches its own content, (4) describe this repository, on the
ref policy names, publicly, and (5) cover every rule, approval count, status check
and environment restriction policy requires. Every failure is a fixed code.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

GOVERNANCE_VERSION = "atlas-anchor-governance/3"


def _digest(observation: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in observation.items() if key != "observation_digest"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def acceptable(observation: Any, policy: Mapping[str, Any]) -> list[str]:
    """Fixed reason codes for why a recorded observation does not establish governance.

    Read by the verifier, which never contacts GitHub itself. It checks that a
    positive observation exists, is of the expected shape, describes this anchor,
    and covers what policy requires - not that the observation be re-performed.
    """
    if not isinstance(observation, dict):
        return ["GOVERNANCE_ABSENT"]
    reasons: list[str] = []
    required = policy["governance"]
    anchor = policy["anchor"]

    if observation.get("governance_version") != GOVERNANCE_VERSION:
        reasons.append("GOVERNANCE_VERSION")
    if observation.get("observation_digest") != _digest(observation):
        reasons.append("GOVERNANCE_DIGEST")
    if observation.get("repository_id") != anchor["repository_id"]:
        reasons.append("GOVERNANCE_OTHER_REPOSITORY")
    if observation.get("repository_private") is not False:
        reasons.append("GOVERNANCE_NOT_PUBLIC")
    if observation.get("default_branch") != required["required_ref"].rsplit("/", 1)[-1]:
        reasons.append("GOVERNANCE_WRONG_REF")
    if observation.get("ref") != required["required_ref"]:
        reasons.append("GOVERNANCE_WRONG_REF")

    in_force = observation.get("rules_in_force")
    if not isinstance(in_force, list) or not in_force:
        reasons.append("GOVERNANCE_NO_RULES")
        in_force = []
    if any(rule not in in_force for rule in required["required_rules"]):
        reasons.append("GOVERNANCE_RULE_MISSING")

    approvals = observation.get("observed_approvals")
    if isinstance(approvals, bool) or not isinstance(approvals, int) or (
        approvals < required["required_approvals"]
    ):
        reasons.append("GOVERNANCE_APPROVALS")
    if required["require_dismiss_stale_reviews"] and observation.get("dismiss_stale_reviews") is not True:
        reasons.append("GOVERNANCE_STALE_REVIEWS")
    if required["require_last_push_approval"] and observation.get("last_push_approval") is not True:
        reasons.append("GOVERNANCE_LAST_PUSH")
    if observation.get("strict_status_checks") is not True:
        reasons.append("GOVERNANCE_STRICT_CHECKS")
    if observation.get("credential_only_in_environment") is not True:
        reasons.append("GOVERNANCE_SECRET_SCOPE")

    contexts = observation.get("status_check_contexts")
    if not isinstance(contexts, list) or any(
        context not in contexts for context in required["required_status_checks"]
    ):
        reasons.append("GOVERNANCE_STATUS_CHECKS")

    rulesets = observation.get("rulesets")
    if not isinstance(rulesets, list) or not rulesets:
        reasons.append("GOVERNANCE_NO_RULESET")
        rulesets = []
    for entry in rulesets:
        if not isinstance(entry, dict) or entry.get("enforcement") != "active":
            reasons.append("GOVERNANCE_RULESET_INACTIVE")
        elif required["require_empty_bypass"] and (
            # False == 0 and 0.0 == 0, so equality alone reads a boolean or a float as
            # "nobody can bypass". Only an actual integer zero is that.
            type(entry.get("bypass_actor_count")) is not int
            or entry.get("bypass_actor_count") != 0
        ):
            reasons.append("GOVERNANCE_BYPASS")

    environment = observation.get("environment")
    expected = required["environment"]
    if (
        not isinstance(environment, dict)
        or environment.get("name") != expected["name"]
        or environment.get("deployment_branches") != sorted(expected["deployment_branches"])
        or environment.get("admins_can_bypass") is not False
    ):
        reasons.append("GOVERNANCE_ENVIRONMENT")
    return list(dict.fromkeys(reasons))

"""Findings of the second independent review, each with the attack it named.

  * a digest printed to the log is an oracle unless it contains a secret
  * the box audit must pin the group and refuse a mount that contains the docker socket
  * the verifier must tie every mount to a directory it knows, and refuse mounts inside
    the freeze's or the workspace's directories
  * the lint must see .yaml workflows and multi-line expressions, and refuse the test
    seams that would let a workflow choose its own source or identity
  * a secret must not exist in ANY other environment, or in the organisation
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from support import (
    IMAGE, SHA_A, good_environment, make_policy, policy_document, run_entry, sha256_hex,
)
from pipeline import run_pipeline
from test_policy_and_governance import ENV, REPO, base_answers, loaded, observe, refused
from test_sandbox_and_evidence import audit, good_argv, layout

import disclosure  # noqa: E402
import pinlint  # noqa: E402
import sandbox  # noqa: E402
import sandbox_spec  # noqa: E402
import verify as verify_module  # noqa: E402

PIN_PATH = "secret/pin.txt"
FLOOR = ["scripts/one.py", "scripts/two.py"]
FILES = {FLOOR[0]: "ONE = 1\n", FLOOR[1]: "TWO = 2\n", PIN_PATH: "PIN=4821\n"}


# ==========================================================================
# the capture digest is printed to the log, so it must contain a secret
# ==========================================================================


def pin_run(tmp_path):
    return run_pipeline(tmp_path, files=FILES, floor=FLOOR, manifest=PIN_PATH)


def test_the_capture_digest_cannot_be_recomputed_from_a_guess_of_an_extra_input(tmp_path):
    """The reproduction: every field of the capture record but the extra's own content is
    public, so 10,000 guesses against the digest the log prints recovered `PIN=4821`."""
    run = pin_run(tmp_path)
    printed = run.output("capture_digest")
    assert printed and printed in run.console
    record = json.loads((run.private / "capture.json").read_text(encoding="utf-8"))
    assert re.fullmatch(r"[0-9a-f]{64}", record["nonce"])

    without_nonce = {key: value for key, value in record.items() if key != "nonce"}
    for guess in range(10000):
        body = f"PIN={guess:04d}\n".encode()
        candidate = json.loads(json.dumps(without_nonce))
        for entry in candidate["inputs"]:
            if entry["relative_path"] == PIN_PATH:
                entry.update(
                    sha256=hashlib.sha256(body).hexdigest(),
                    size=len(body),
                    blob=hashlib.sha1(b"blob %d\0" % len(body) + body, usedforsecurity=False).hexdigest(),
                )
        forged = json.dumps(candidate, indent=2, sort_keys=True).encode("utf-8")
        assert hashlib.sha256(forged).hexdigest() != printed, f"guess {guess} reproduces the digest"


def test_two_captures_of_the_same_candidate_have_different_digests(tmp_path):
    first = pin_run(tmp_path / "first")
    second = pin_run(tmp_path / "second")
    assert first.output("capture_digest") != second.output("capture_digest")


def test_the_nonce_never_reaches_a_public_file(tmp_path):
    run = pin_run(tmp_path)
    nonce = json.loads((run.private / "capture.json").read_text(encoding="utf-8"))["nonce"]
    for path in run.public.iterdir():
        assert nonce.encode() not in path.read_bytes(), path.name
    assert nonce not in run.console


def test_the_console_reports_no_count_that_would_say_whether_an_extra_exists(tmp_path):
    run = pin_run(tmp_path)
    assert "absent" not in run.steps["capture"].stdout


def test_the_public_sandbox_digest_does_not_depend_on_the_manifest():
    policy = policy_document()
    base = {"argv": ["docker", "run", "--inputs-manifest=secret/a.txt"], "exit_code": 0}
    other = {"argv": ["docker", "run", "--inputs-manifest=secret/b.txt"], "exit_code": 0}
    assert sandbox_spec.public_digest_of(base) == sandbox_spec.public_digest_of(other)
    assert sandbox_spec.digest_of(base) != sandbox_spec.digest_of(other)
    assert sandbox_spec.public_digest_of(base) != sandbox_spec.public_digest_of({**base, "exit_code": 1})
    assert policy


def test_the_published_verdict_uses_the_redacted_digest(tmp_path):
    run = pin_run(tmp_path)
    record = json.loads((run.private / "sandbox.json").read_text(encoding="utf-8"))
    assert run.verdict["sandbox"]["record_digest"] == sandbox_spec.public_digest_of(record)
    assert run.verdict["sandbox"]["record_digest"] != sandbox_spec.digest_of(record)


def test_the_evidence_view_honours_a_policy_that_withholds_floor_digests():
    policy = policy_document(floor=FLOOR)
    policy["disclosure"]["publish_floor_digests"] = False
    evidence = {
        "evidence_version": "atlas-anchor-evidence/2", "candidate_sha": "a" * 40, "candidate_tree": "b" * 40,
        "inputs_requested": FLOOR, "inputs_unreadable": [],
        "inputs_observed": [{"relative_path": FLOOR[0], "blob": "1" * 40, "sha256": "2" * 64, "size": 3}],
    }
    assert disclosure.evidence_view(evidence, policy)["floor_observed"] == [{"relative_path": FLOOR[0]}]


# ==========================================================================
# the box: the group, the socket, and the directories the verifier knows
# ==========================================================================


@pytest.mark.parametrize("user", ["1001:118", "1001:1001", "1001:0", "0:65534", "1001", "root:root"])
def test_a_box_whose_group_is_not_the_pinned_unprivileged_one_is_refused(tmp_path, user):
    argv = good_argv(tmp_path)
    tampered = [user if token.startswith("1001:") else token for token in argv]
    assert "SANDBOX_USER" in audit(tampered, tmp_path)


@pytest.mark.parametrize("source", ["/var/run", "/run", "/", "/var", "/var/run/docker.sock", "/run/docker.sock", "/var/run/"])
def test_a_mount_that_is_or_contains_the_docker_socket_is_refused(tmp_path, source):
    the_layout = layout(tmp_path)
    argv = [t.replace(str(the_layout.child), source) for t in good_argv(tmp_path)]
    record = the_layout.as_record()
    record["child"] = source
    assert "SANDBOX_DOCKER_SOCKET" in sandbox_spec.audit_argv(argv, policy_document(), record)


@pytest.mark.parametrize("source", ["/var/lib", "/tmp/work", "/home/runner/work/_temp/anchor-sandbox/child"])
def test_a_mount_that_merely_sits_near_the_socket_is_not_refused_for_it(tmp_path, source):
    the_layout = layout(tmp_path)
    argv = [t.replace(str(the_layout.child), source) for t in good_argv(tmp_path)]
    record = the_layout.as_record()
    record["child"] = source
    assert "SANDBOX_DOCKER_SOCKET" not in sandbox_spec.audit_argv(argv, policy_document(), record)


def base_sandbox(policy_layout):
    from test_verify_and_preserve import good_sandbox

    return good_sandbox()


def run_verify(agreeing_policy, **keywords):
    from test_verify_and_preserve import SCOPE, good_capture, good_evidence_document, read_of, good_sandbox

    return verify_module.verify(
        agreeing_policy, list(SCOPE), SHA_A, good_capture(), read_of(good_evidence_document()),
        "success", good_sandbox(), **keywords,
    )


@pytest.fixture()
def the_policy(tmp_path):
    return loaded(tmp_path)


def test_a_child_mount_that_is_not_the_directory_the_verifier_expects_is_refused(the_policy):
    verdict, reasons = run_verify(
        the_policy, evidence_dir=Path("/host/evidence"), scope_dir=Path("/host/candidate"),
        child_dir=Path("/elsewhere/child"),
    )
    assert verdict == "REFUSE" and "SANDBOX_LAYOUT" in reasons


def test_the_matching_directories_are_accepted(the_policy):
    assert run_verify(
        the_policy, evidence_dir=Path("/host/evidence"), scope_dir=Path("/host/candidate"),
        child_dir=Path("/host/child"),
    )[0] == "ACCEPT"


@pytest.mark.parametrize("private", [Path("/host"), Path("/host/candidate"), Path("/host/child/inner"), Path("/host/evidence")])
def test_a_mount_inside_or_equal_to_a_private_directory_is_refused(the_policy, private):
    """A mount of the fetched clone (inside the freeze's directory) passed while only
    ancestors were refused."""
    verdict, reasons = run_verify(
        the_policy, evidence_dir=Path("/host/evidence"), scope_dir=Path("/host/candidate"),
        child_dir=Path("/host/child"), private_roots=[private],
    )
    assert verdict == "REFUSE" and "SANDBOX_LAYOUT" in reasons


def test_the_verifier_cannot_be_run_without_being_told_the_scope_and_child_directories(tmp_path):
    process = run_entry(
        "verify.py", f"--policy={make_policy(tmp_path)}", f"--candidate={'a' * 40}", "--inputs-manifest=",
        f"--capture={tmp_path / 'c.json'}", f"--capture-digest={'0' * 64}", "--capture-result=success",
        f"--evidence-dir={tmp_path / 'e'}", env=good_environment(),
    )
    assert process.returncode == 2 and "USAGE_ERROR" in process.stdout


def test_an_argument_with_a_nul_byte_is_a_result_not_a_crash():
    result = sandbox.execute(["docker\0x"], {}, timeout=5, cap=100)
    assert result.returncode is None


# ==========================================================================
# the lint: .yaml files, multi-line expressions, and the test seams
# ==========================================================================

BAD = "name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"


def test_a_yaml_workflow_is_linted_like_a_yml_one(tmp_path):
    (tmp_path / "sneaky.yaml").write_text(BAD, encoding="utf-8")
    assert pinlint.main([str(tmp_path)]) == 1


def test_a_yml_workflow_is_still_linted(tmp_path):
    (tmp_path / "plain.yml").write_text(BAD, encoding="utf-8")
    assert pinlint.main([str(tmp_path)]) == 1


def step(expression):
    """A well-formed step whose ONLY suspect content is one expression in an env binding."""
    return f"      - name: probe\n        env:\n          J: {expression}\n        run: echo done\n"


@pytest.mark.parametrize(
    "text",
    [
        step("${{ toJSON(\n            secrets) }}"),
        step("${{ join(secrets, ',') }}"),
        step("${{ format('{0}', secrets.ATLAS_DEPLOY_KEY) }}"),
        step("${{\n            secrets['X'] }}"),
        step("${{ fromJSON(toJSON(secrets)).X }}"),
    ],
)
def test_the_lint_refuses_a_secret_hidden_in_a_multi_part_or_multi_line_expression(text):
    assert pinlint.problems_in(text, "qualify.yml"), text
    assert pinlint.problems_in(text, "test.yml"), text


def test_the_lint_still_allows_the_one_step_binding_and_the_job_token():
    ok = "      - name: p\n        env:\n          A: ${{ secrets.ATLAS_DEPLOY_KEY }}\n          B: ${{ secrets.GITHUB_TOKEN }}\n        run: echo\n"
    assert pinlint.problems_in(ok, "qualify.yml") == []


@pytest.mark.parametrize("flag", ["--source", "--uid", "--gid", "--docker-command"])
def test_a_workflow_cannot_use_a_seam_that_chooses_the_source_or_the_identity(flag):
    line = f"      - run: |\n          $PY anchor/anchor/capture.py {flag}=x\n"
    assert any("test seam" in problem for problem in pinlint.problems_in(line, "probe.yml")), flag


def test_the_real_workflows_use_none_of_the_seams():
    for path in sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.y*ml")):
        text = "\n".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.strip().startswith("#"))
        for flag in ("--source", "--uid", "--gid", "--docker-command"):
            assert flag not in text, (path.name, flag)


# ==========================================================================
# the credential must exist nowhere but its own environment
# ==========================================================================


def with_environments(answers, environments, secrets):
    answers[f"/repos/{REPO}/environments"] = {"total_count": len(environments), "environments": [{"name": n} for n in environments]}
    for name, names in secrets.items():
        answers[f"/repos/{REPO}/environments/{name}/secrets"] = {"total_count": len(names), "secrets": [{"name": n} for n in names]}


def test_an_environment_with_no_secrets_of_the_names_is_fine(tmp_path):
    def mutate(answers):
        with_environments(answers, [ENV, "staging"], {"staging": ["UNRELATED"]})

    assert observe(tmp_path, mutate)["credential_only_in_environment"] is True


@pytest.mark.parametrize("secret", ["ATLAS_DEPLOY_KEY", "ANCHOR_GOVERNANCE_TOKEN"])
def test_the_credential_in_another_environment_is_a_refusal(tmp_path, secret):
    """Released to any branch that names that environment, under that environment's rules."""

    def mutate(answers):
        with_environments(answers, [ENV, "staging"], {"staging": [secret]})

    assert secret in refused(tmp_path, mutate, match="also exist in environment")


def test_an_environment_secret_listing_that_is_incomplete_is_a_refusal(tmp_path):
    def mutate(answers):
        with_environments(answers, [ENV, "staging"], {})
        answers[f"/repos/{REPO}/environments/staging/secrets"] = {"total_count": 3, "secrets": []}

    refused(tmp_path, mutate, match="in full")


def test_an_environment_list_that_is_incomplete_is_a_refusal(tmp_path):
    def mutate(answers):
        answers[f"/repos/{REPO}/environments"] = {"total_count": 4, "environments": [{"name": ENV}]}

    refused(tmp_path, mutate, match="in full")


@pytest.mark.parametrize("payload", [{}, [], None, {"environments": "x", "total_count": 1}, {"environments": [{"no": "name"}], "total_count": 1}])
def test_an_unreadable_environment_list_is_a_refusal(tmp_path, payload):
    refused(tmp_path, lambda answers: answers.__setitem__(f"/repos/{REPO}/environments", payload))


def as_organisation(answers, org_secrets):
    answers[f"/repos/{REPO}"]["owner"] = {"type": "Organization"}
    answers[f"/repos/{REPO}/actions/organization-secrets"] = {"total_count": len(org_secrets), "secrets": [{"name": n} for n in org_secrets]}


def test_an_organisation_repository_with_no_shared_secret_of_the_names_is_fine(tmp_path):
    assert observe(tmp_path, lambda a: as_organisation(a, ["OTHER"]))["credential_only_in_environment"] is True


def test_the_credential_shared_from_an_organisation_is_a_refusal(tmp_path):
    refused(tmp_path, lambda a: as_organisation(a, ["ATLAS_DEPLOY_KEY"]), match="organisation")


def test_an_organisation_listing_that_cannot_be_read_is_a_refusal(tmp_path):
    def mutate(answers):
        as_organisation(answers, [])
        del answers[f"/repos/{REPO}/actions/organization-secrets"]

    refused(tmp_path, mutate)


@pytest.mark.parametrize("owner", [None, {}, {"type": None}, {"type": "Organization"}, "User"])
def test_an_owner_that_is_not_plainly_a_user_is_treated_as_an_organisation(tmp_path, owner):
    """Absence must not skip the check: only an owner that IS a user does."""

    def mutate(answers):
        if owner is None:
            answers[f"/repos/{REPO}"].pop("owner")
        else:
            answers[f"/repos/{REPO}"]["owner"] = owner

    with pytest.raises(PolicyError):
        observe(tmp_path, mutate)


from policy import PolicyError  # noqa: E402


def test_each_capture_carries_its_own_fresh_nonce(tmp_path):
    """A constant would make the digest a function of public values again."""
    nonces = {
        json.loads((run_pipeline(tmp_path / str(i), files=FILES, floor=FLOOR).private / "capture.json").read_text(encoding="utf-8"))["nonce"]
        for i in range(3)
    }
    assert len(nonces) == 3 and all(re.fullmatch(r"[0-9a-f]{64}", n) for n in nonces)
    assert "0" * 64 not in nonces

"""The verdict, every way to be refused by it, and the package that outlives the run.

The verifier compares claims with a freeze and a record it did not make, and reports
in fixed codes. Preservation answers one narrower question offline - are these the
files the verdict was made from - and can turn no REFUSE into an ACCEPT.
"""

from __future__ import annotations

import ast
import hashlib
import json
import shutil

import pytest

from support import (
    ANCHOR,
    IMAGE,
    IMAGE_ID,
    SHA_A,
    SHA_B,
    WORKFLOW_REF,
    good_environment,
    governed_observation,
    make_policy,
    policy_document,
    run_entry,
)

import disclosure  # noqa: E402
import evidence as evidence_module  # noqa: E402
import policy as policy_module  # noqa: E402
import preserve as preserve_module  # noqa: E402
import publog  # noqa: E402
import sandbox_spec  # noqa: E402
import verify as verify_module  # noqa: E402
from pipeline import run_pipeline  # noqa: E402
from policy import PolicyError  # noqa: E402

SCOPE = ["scripts/one.py", "scripts/two.py"]
TREE = "e" * 40


def make_inputs():
    return [
        {"relative_path": path, "blob": "0" * 40, "sha256": hashlib.sha256(path.encode()).hexdigest(), "size": 9}
        for path in SCOPE
    ]


def good_capture(**overrides):
    capture = {
        "capture_version": "atlas-anchor-capture/2",
        "candidate_sha": SHA_A,
        "candidate_tree": TREE,
        "scope": list(SCOPE),
        "inputs": make_inputs(),
        "absent": [],
        "governance": governed_observation(),
    }
    capture.update(overrides)
    return capture


def good_evidence_document(**overrides):
    document = {
        "evidence_version": evidence_module.EVIDENCE_VERSION,
        "candidate_sha": SHA_A,
        "candidate_tree": TREE,
        "inputs_requested": list(SCOPE),
        "inputs_observed": make_inputs(),
        "inputs_unreadable": [],
    }
    document.update(overrides)
    return document


def read_of(document):
    return evidence_module.Read(document, (), "f" * 64, 100)


def good_sandbox(**overrides):
    from support import policy_document as pd

    tmp = overrides.pop("_layout", None)
    layout = sandbox_spec.Layout(*[__import__("pathlib").Path(f"/host/{n}") for n in ("candidate", "child", "evidence")])
    record = {
        "sandbox_version": sandbox_spec.SANDBOX_VERSION,
        "image": IMAGE,
        "image_id": IMAGE_ID,
        "params": {"name": "n", "uid": 1001, "gid": 65534, "candidate": SHA_A, "tree": TREE},
        "layout": layout.as_record(),
        "argv": sandbox_spec.build_argv(
            pd(), docker=["docker"], name="n", uid=1001, gid=65534, layout=layout,
            candidate=SHA_A, tree=TREE, manifest="",
        ),
        "pull_ok": True, "started": True, "exit_code": 0, "timed_out": False,
        "output_exceeded": False, "stdout_bytes": 0, "stderr_bytes": 0,
    }
    record.update(overrides)
    return record


@pytest.fixture()
def agreeing(tmp_path):
    return policy_module.load(make_policy(tmp_path)), list(SCOPE)


def decide(agreeing, capture=None, evidence=None, capture_result="success", sandbox=...):
    policy, scope = agreeing
    return verify_module.verify(
        policy, scope, SHA_A,
        good_capture() if capture is None else capture,
        read_of(good_evidence_document()) if evidence is None else evidence,
        capture_result,
        good_sandbox() if sandbox is ... else sandbox,
    )


def hostile_evidence(**overrides):
    return read_of(good_evidence_document(**overrides))


# ==========================================================================
# the verdict
# ==========================================================================


def test_an_agreeing_run_is_accepted(agreeing):
    assert decide(agreeing) == ("ACCEPT", [])


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "", "success "])
def test_a_capture_that_did_not_succeed_cannot_be_accepted(agreeing, result):
    verdict, reasons = decide(agreeing, capture_result=result)
    assert verdict == "REFUSE" and "CAPTURE_NOT_SUCCESS" in reasons


@pytest.mark.parametrize(
    "override, code",
    [
        ({"exit_code": 1}, "SANDBOX_EXIT_NONZERO"),
        ({"exit_code": 137}, "SANDBOX_EXIT_NONZERO"),
        ({"exit_code": None}, "SANDBOX_EXIT_NONZERO"),
        ({"timed_out": True}, "SANDBOX_TIMEOUT"),
        ({"output_exceeded": True}, "SANDBOX_OUTPUT_LIMIT"),
        ({"started": False}, "SANDBOX_NOT_STARTED"),
        ({"pull_ok": False}, "SANDBOX_IMAGE_UNAVAILABLE"),
    ],
)
def test_a_sandbox_that_did_not_end_cleanly_cannot_be_accepted(agreeing, override, code):
    """D4. The child's exit belongs to the host, not to the child."""
    verdict, reasons = decide(agreeing, sandbox=good_sandbox(**override))
    assert verdict == "REFUSE" and code in reasons


def test_a_child_failure_is_terminal_even_with_flawless_evidence(agreeing):
    """The attack this closes: pass every content check, then exit non-zero."""
    assert decide(agreeing, sandbox=good_sandbox(exit_code=1)) == ("REFUSE", ["SANDBOX_EXIT_NONZERO"])


def test_no_sandbox_record_at_all_cannot_be_accepted(agreeing):
    verdict, reasons = decide(agreeing, sandbox=None)
    assert verdict == "REFUSE" and "SANDBOX_RECORD_MISSING" in reasons


@pytest.mark.parametrize(
    "params",
    [
        {"candidate": SHA_B, "tree": TREE},
        {"candidate": SHA_A, "tree": "c" * 40},
        {"candidate": SHA_A},
        None,
        "not a dict",
    ],
)
def test_a_sandbox_run_for_a_different_commit_or_tree_is_refused(agreeing, params):
    verdict, reasons = decide(agreeing, sandbox=good_sandbox(params=params))
    assert verdict == "REFUSE" and "SANDBOX_BINDING" in reasons


def test_a_sandbox_that_was_not_hardened_cannot_be_accepted_however_it_ended(agreeing):
    argv = [t for t in good_sandbox()["argv"] if t != "--read-only"]
    verdict, reasons = decide(agreeing, sandbox=good_sandbox(argv=argv))
    assert verdict == "REFUSE" and "SANDBOX_WRITABLE_ROOT" in reasons


def test_absent_evidence_is_a_refusal_not_an_absence_of_problems(agreeing):
    """'Found nothing' must never read as 'nothing was wrong'."""
    verdict, reasons = decide(agreeing, evidence=evidence_module.Read(None, (), None, 0))
    assert verdict == "REFUSE" and "EVIDENCE_MISSING" in reasons


def test_evidence_the_boundary_refused_is_refused_with_the_boundarys_own_codes(agreeing):
    refused = evidence_module.Read(None, ("EVIDENCE_OVERSIZED", "EVIDENCE_UNEXPECTED_FILE"), None, 0)
    verdict, reasons = decide(agreeing, evidence=refused)
    assert verdict == "REFUSE"
    assert {"EVIDENCE_OVERSIZED", "EVIDENCE_UNEXPECTED_FILE"} <= set(reasons)


def test_evidence_that_contradicts_the_capture_is_refused(agreeing):
    observed = make_inputs()
    observed[0]["sha256"] = "f" * 64
    verdict, reasons = decide(agreeing, evidence=hostile_evidence(inputs_observed=observed))
    assert verdict == "REFUSE" and "OBSERVATION_MISMATCH" in reasons


@pytest.mark.parametrize("field", ["blob", "size", "sha256"])
def test_every_field_of_an_observation_must_match_the_freeze(agreeing, field):
    observed = make_inputs()
    observed[1][field] = {"blob": "1" * 40, "size": 10, "sha256": "2" * 64}[field]
    assert "OBSERVATION_MISMATCH" in decide(agreeing, evidence=hostile_evidence(inputs_observed=observed))[1]


def test_c3_evidence_that_narrows_its_own_scope_is_refused(agreeing):
    """C3 regression. The previous verifier read the required scope out of the
    evidence, so a child covering one of three inputs could declare that one was
    all that had ever been asked for, and be accepted."""
    verdict, reasons = decide(
        agreeing,
        evidence=hostile_evidence(inputs_requested=[SCOPE[0]], inputs_observed=make_inputs()[:1]),
    )
    assert verdict == "REFUSE"
    assert "EVIDENCE_SCOPE_MISMATCH" in reasons and "SCOPE_NOT_COVERED" in reasons


def test_evidence_that_observes_one_input_twice_is_refused(agreeing):
    observed = make_inputs() + [make_inputs()[0]]
    assert "OBSERVATION_DUPLICATED" in decide(agreeing, evidence=hostile_evidence(inputs_observed=observed))[1]


def test_evidence_that_covers_an_input_nobody_asked_for_is_refused(agreeing):
    observed = make_inputs() + [{"relative_path": "extra.py", "blob": "0" * 40, "sha256": "a" * 64, "size": 1}]
    reasons = decide(agreeing, evidence=hostile_evidence(inputs_observed=observed))[1]
    assert "SCOPE_EXCEEDED" in reasons and "OBSERVATION_NOT_FROZEN" in reasons


def test_evidence_describing_a_different_commit_is_refused(agreeing):
    assert "EVIDENCE_CANDIDATE_MISMATCH" in decide(agreeing, evidence=hostile_evidence(candidate_sha=SHA_B))[1]


def test_evidence_claiming_a_tree_the_capture_does_not_have_is_refused(agreeing):
    assert "EVIDENCE_TREE_MISMATCH" in decide(agreeing, evidence=hostile_evidence(candidate_tree="c" * 40))[1]


def test_evidence_flooding_the_verifier_with_observations_is_refused(agreeing):
    flood = [{"relative_path": f"x{i}.py", "blob": "0" * 40, "sha256": "a" * 64, "size": 1} for i in range(600)]
    assert "EVIDENCE_FLOOD" in decide(agreeing, evidence=hostile_evidence(inputs_observed=flood))[1]


def test_an_input_the_child_could_not_read_is_reported_not_skipped(agreeing):
    unreadable = [{"relative_path": SCOPE[1], "reason": "UNREADABLE"}]
    assert "INPUT_UNREADABLE" in decide(agreeing, evidence=hostile_evidence(inputs_unreadable=unreadable))[1]


def test_a_candidate_missing_a_floor_input_cannot_be_accepted(agreeing):
    verdict, reasons = decide(agreeing, capture=good_capture(absent=[SCOPE[1]]))
    assert verdict == "REFUSE" and "INPUT_ABSENT" in reasons


def test_a_capture_frozen_for_a_different_commit_is_refused(agreeing):
    assert "CAPTURE_CANDIDATE_MISMATCH" in decide(agreeing, capture=good_capture(candidate_sha=SHA_B))[1]


def test_a_capture_frozen_for_a_different_scope_is_refused(agreeing):
    assert "CAPTURE_SCOPE_MISMATCH" in decide(agreeing, capture=good_capture(scope=[SCOPE[0]]))[1]


@pytest.mark.parametrize("tree", ["", "short", None, 7, "E" * 40])
def test_a_capture_with_no_usable_tree_is_refused(agreeing, tree):
    assert "CAPTURE_TREE_INVALID" in decide(agreeing, capture=good_capture(candidate_tree=tree))[1]


def test_a_capture_carrying_no_governance_cannot_be_accepted(agreeing):
    """A verdict cannot exist without a positive governance observation."""
    capture = good_capture()
    del capture["governance"]
    verdict, reasons = decide(agreeing, capture=capture)
    assert verdict == "REFUSE" and "GOVERNANCE_ABSENT" in reasons


@pytest.mark.parametrize(
    "override, code",
    [
        ({"observed_approvals": 0}, "GOVERNANCE_APPROVALS"),
        ({"repository_private": True}, "GOVERNANCE_NOT_PUBLIC"),
        ({"environment": {"name": "atlas-qualification", "deployment_branches": ["*"]}}, "GOVERNANCE_ENVIRONMENT"),
        ({"rulesets": [{"id": 1, "enforcement": "active", "bypass_actor_count": 1}]}, "GOVERNANCE_BYPASS"),
    ],
)
def test_a_governance_observation_that_does_not_establish_protection_is_refused(agreeing, override, code):
    verdict, reasons = decide(agreeing, capture=good_capture(governance=governed_observation(**override)))
    assert verdict == "REFUSE" and code in reasons


def test_every_reason_is_reported_not_just_the_first(agreeing):
    verdict, reasons = decide(
        agreeing,
        evidence=hostile_evidence(candidate_sha=SHA_B, candidate_tree="c" * 40),
        sandbox=good_sandbox(exit_code=1),
    )
    assert verdict == "REFUSE" and len(reasons) >= 3


def test_every_reason_is_a_unique_fixed_code(agreeing):
    _, reasons = decide(
        agreeing,
        capture=good_capture(candidate_sha=SHA_B, scope=[], absent=["a"]),
        evidence=hostile_evidence(candidate_sha=SHA_B, inputs_unreadable=[{"relative_path": "a", "reason": "ABSENT"}]),
        capture_result="failure",
        sandbox=None,
    )
    assert len(reasons) == len(set(reasons)) >= 5
    assert all(publog.CODE.match(reason) for reason in reasons)


# ==========================================================================
# the capture the verifier is handed
# ==========================================================================


def test_a_capture_file_that_does_not_match_the_published_digest_is_refused(tmp_path):
    """D-A16. Something replaced the capture after the capture step made it."""
    path = tmp_path / "capture.json"
    path.write_bytes(json.dumps({"capture_version": "atlas-anchor-capture/2"}).encode())
    with pytest.raises(PolicyError, match="does not match"):
        verify_module.read_capture(path, hashlib.sha256(b"something else").hexdigest())


@pytest.mark.parametrize("digest", ["", "deadbeef", "g" * 64, "A" * 64, "0" * 63])
def test_a_capture_digest_that_is_not_a_sha256_is_refused(tmp_path, digest):
    path = tmp_path / "capture.json"
    path.write_bytes(b"{}")
    with pytest.raises(PolicyError, match="sha256"):
        verify_module.read_capture(path, digest)


def test_a_missing_capture_is_refused(tmp_path):
    with pytest.raises(PolicyError, match="unreadable"):
        verify_module.read_capture(tmp_path / "absent.json", "0" * 64)


@pytest.mark.parametrize("version", ["someone-elses/9", "atlas-anchor-capture/1", None])
def test_a_capture_of_an_unknown_version_is_refused(tmp_path, version):
    payload = json.dumps({"capture_version": version}).encode()
    path = tmp_path / "capture.json"
    path.write_bytes(payload)
    with pytest.raises(PolicyError, match="expected version"):
        verify_module.read_capture(path, hashlib.sha256(payload).hexdigest())


def test_a_capture_that_is_not_json_is_refused_without_quoting_it(tmp_path):
    payload = b"PRIVATE_SENTINEL not json"
    path = tmp_path / "capture.json"
    path.write_bytes(payload)
    with pytest.raises(PolicyError) as error:
        verify_module.read_capture(path, hashlib.sha256(payload).hexdigest())
    assert "PRIVATE_SENTINEL" not in str(error.value)


def test_an_unreadable_sandbox_record_is_none_not_a_crash(tmp_path):
    (tmp_path / "r.json").write_text("{broken", encoding="utf-8")
    assert verify_module.read_sandbox_record(tmp_path / "r.json") is None
    assert verify_module.read_sandbox_record(tmp_path / "absent.json") is None
    assert verify_module.read_sandbox_record(None) is None


# ==========================================================================
# the verdict record
# ==========================================================================


def verify_cli(tmp_path, **environment):
    return run_entry(
        "verify.py", "--policy", str(make_policy(tmp_path)), "--candidate", SHA_A,
        "--inputs-manifest", "", "--capture", str(tmp_path / "absent.json"),
        "--capture-digest", "0" * 64, "--capture-result", "success",
        "--scope-dir", str(tmp_path / "s"), "--child-dir", str(tmp_path / "c"), "--evidence-dir", str(tmp_path / "absent-evidence"),
        "--verdict", str(tmp_path / "verdict.json"),
        env=good_environment(**environment),
    )


def test_the_verdict_record_carries_the_identity_of_the_run_that_made_it(tmp_path):
    process = verify_cli(tmp_path, GITHUB_RUN_ID="4242", GITHUB_RUN_ATTEMPT="2")
    assert process.returncode == 1
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert record["verdict"] == "REFUSE" and record["reasons"] == ["PRECONDITION_FAILED"]
    assert record["anchor"]["run_id"] == "4242" and record["anchor"]["run_attempt"] == "2"
    assert record["anchor"]["workflow_ref"] == WORKFLOW_REF
    assert record["anchor"]["repository_id"] == "987654321"
    assert "capture_digest" not in record and record["public_capture_digest"] is None


def test_the_verdict_has_exactly_the_allow_listed_keys(tmp_path):
    verify_cli(tmp_path)
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert set(record) == disclosure.VERDICT_KEYS


def test_the_verdict_names_the_verifier_by_the_bytes_that_ran(tmp_path):
    verify_cli(tmp_path)
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert record["verifier"]["code_digest"] == verify_module.code_digest(ANCHOR)
    assert record["verifier"]["version"] == verify_module.VERIFIER_VERSION


def test_editing_any_anchor_module_changes_the_verifier_digest(tmp_path):
    copy = tmp_path / "anchor"
    shutil.copytree(ANCHOR, copy, ignore=shutil.ignore_patterns("__pycache__"))
    before = verify_module.code_digest(copy)
    (copy / "policy.py").write_text((copy / "policy.py").read_text(encoding="utf-8") + "\n# x\n", encoding="utf-8")
    assert verify_module.code_digest(copy) != before


@pytest.mark.parametrize("value", ["4242; rm -rf /", "a" * 300, "line\nbreak", "::error::x", "12 34", "-5", "1e9"])
def test_a_run_identifier_that_is_not_plainly_a_token_is_dropped_not_recorded(tmp_path, value):
    verify_cli(tmp_path, GITHUB_RUN_ID=value)
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert record["anchor"]["run_id"] is None


def test_the_runner_environment_is_recorded_from_github_set_values(tmp_path):
    verify_cli(tmp_path, ImageOS="ubuntu24", ImageVersion="20260901.1.0")
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert record["runner"] == {
        "os": "Linux", "arch": "X64", "environment": "github-hosted",
        "image_os": "ubuntu24", "image_version": "20260901.1.0",
    }


def test_a_run_that_is_not_the_protected_workflow_is_refused_by_the_verifier_too(tmp_path):
    process = verify_cli(tmp_path, GITHUB_REF="refs/heads/side")
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert process.returncode == 1 and record["verdict"] == "REFUSE"


def test_the_exit_status_is_zero_only_for_an_accept(tmp_path):
    run = run_pipeline(tmp_path)
    assert run.steps["verify"].returncode == 0 and run.verdict["verdict"] == "ACCEPT"
    other = run_pipeline(tmp_path / "second", docker_config={"pull_fails": True})
    assert other.steps["verify"].returncode == 1 and other.verdict["verdict"] == "REFUSE"


def test_the_public_account_of_the_sandbox_carries_identities_and_counts_never_paths_or_output(tmp_path):
    run = run_pipeline(tmp_path)
    summary = run.verdict["sandbox"]
    assert set(summary) == {
        "image", "image_id", "hardened", "exit_code", "timed_out", "output_exceeded",
        "stdout_bytes", "stderr_bytes", "record_digest",
    }
    assert str(run.root).replace("\\", "/") not in json.dumps(run.verdict).replace("\\\\", "/")


def imported(path):
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_the_verifier_cannot_run_a_subprocess():
    """D3. No subprocess import means no git, which means no way to read the target."""
    assert "subprocess" not in imported(ANCHOR / "verify.py")


def test_the_verifier_never_derives_a_fact_from_the_target():
    source = (ANCHOR / "verify.py").read_text(encoding="utf-8")
    for forbidden in ["cat-file", "ls-tree", "rev-parse", "git "]:
        assert forbidden not in source


def test_the_verifier_has_no_way_to_be_told_a_verdict():
    """No argument carries a verdict, a decision or a child result."""
    source = (ANCHOR / "verify.py").read_text(encoding="utf-8")
    for forbidden in ("--child-result", "--verdict-in", "--accept", "--force"):
        assert forbidden not in source


# ==========================================================================
# preservation
# ==========================================================================


@pytest.fixture()
def sealed(tmp_path):
    run = run_pipeline(tmp_path)
    assert run.steps["seal"].returncode == 0, run.steps["seal"].stdout
    return run


def package_of(run):
    return json.loads((run.public / "evidence.json").read_text(encoding="utf-8"))


def reseal(run, package):
    package["evidence_digest"] = preserve_module._seal(package)
    (run.public / "evidence.json").write_text(json.dumps(package), encoding="utf-8")


def test_a_run_seals_into_a_package_that_checks_itself(sealed):
    assert preserve_module.check(sealed.public) == []
    assert set(package_of(sealed)) == disclosure.PACKAGE_KEYS


def test_the_package_binds_the_anchor_tree_the_policy_and_the_verifier(sealed):
    package = package_of(sealed)
    assert package["anchor_tree_digest"] == preserve_module.digest(sealed.public / "anchor-tree.tar")
    assert package["policy_digest"] == preserve_module.digest(sealed.public / "policy.json")
    assert package["verifier"]["code_digest"] == verify_module.code_digest(ANCHOR)
    assert package["governance"]["repository_private"] is False


def test_a_package_notices_when_the_anchor_tree_is_swapped(sealed):
    (sealed.public / "anchor-tree.tar").write_bytes(b"another evaluator")
    assert "PACKAGE_MEMBER_EDITED" in preserve_module.check(sealed.public)


@pytest.mark.parametrize("name", ["verdict.json", "public-capture.json", "policy.json"])
def test_a_package_notices_an_edited_member(sealed, name):
    path = sealed.public / name
    path.write_bytes(path.read_bytes() + b" ")
    assert "PACKAGE_MEMBER_EDITED" in preserve_module.check(sealed.public)


def test_a_package_notices_an_edited_seal(sealed):
    package = package_of(sealed)
    package["verdict"] = "ACCEPT" if package["verdict"] != "ACCEPT" else "REFUSE"
    (sealed.public / "evidence.json").write_text(json.dumps(package), encoding="utf-8")
    assert "PACKAGE_EDITED" in preserve_module.check(sealed.public)


def test_a_package_with_an_extra_field_is_refused_even_if_resealed(sealed):
    package = package_of(sealed)
    package["extra"] = "PRIVATE"
    reseal(sealed, package)
    assert "PACKAGE_SCHEMA" in preserve_module.check(sealed.public)


def test_a_missing_package_is_broken_not_intact(tmp_path):
    (tmp_path / "package").mkdir()
    assert preserve_module.check(tmp_path / "package") == ["PACKAGE_MISSING"]
    assert run_entry("preserve.py", "check", "--package", str(tmp_path / "package")).returncode == 1


def test_a_missing_member_is_broken_not_intact(sealed):
    (sealed.public / "anchor-tree.tar").unlink()
    assert "PACKAGE_MEMBER_MISSING" in preserve_module.check(sealed.public)


def test_a_package_that_is_not_json_is_broken(sealed):
    (sealed.public / "evidence.json").write_text("{nope", encoding="utf-8")
    assert preserve_module.check(sealed.public) == ["PACKAGE_UNREADABLE"]


def build_args(run, **paths):
    return dict(
        verdict_path=paths.get("verdict", run.public / "verdict.json"),
        public_capture_path=paths.get("capture", run.public / "public-capture.json"),
        policy_path=paths.get("policy", run.public / "policy.json"),
        anchor_archive=paths.get("archive", run.public / "anchor-tree.tar"),
    )


def rewrite(path, **changes):
    document = json.loads(path.read_text(encoding="utf-8"))
    document.update(changes)
    path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")


def test_a_run_with_no_governance_cannot_be_preserved(sealed):
    rewrite(sealed.public / "public-capture.json", governance=None)
    rewrite(sealed.public / "verdict.json", public_capture_digest=preserve_module.digest(sealed.public / "public-capture.json"))
    with pytest.raises(PolicyError, match="governance"):
        preserve_module.build(**build_args(sealed))


def test_a_verdict_that_names_another_public_capture_cannot_be_preserved(sealed):
    rewrite(sealed.public / "verdict.json", public_capture_digest="0" * 64)
    with pytest.raises(PolicyError, match="public capture digest"):
        preserve_module.build(**build_args(sealed))


def test_a_public_capture_that_was_edited_after_the_verdict_cannot_be_preserved(sealed):
    rewrite(sealed.public / "public-capture.json", candidate_tree="9" * 40)
    with pytest.raises(PolicyError, match="public capture digest"):
        preserve_module.build(**build_args(sealed))


def test_a_verdict_and_capture_about_different_candidates_cannot_be_preserved(sealed):
    rewrite(sealed.public / "verdict.json", candidate_sha=SHA_B)
    with pytest.raises(PolicyError, match="different candidates"):
        preserve_module.build(**build_args(sealed))


def test_a_verdict_made_under_another_policy_cannot_be_preserved(sealed):
    (sealed.public / "policy.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PolicyError, match="different policy"):
        preserve_module.build(**build_args(sealed))


@pytest.mark.parametrize("field", ["workflow_sha", "run_id", "repository_id"])
def test_a_verdict_that_cannot_name_its_own_run_cannot_be_preserved(sealed, field):
    verdict = json.loads((sealed.public / "verdict.json").read_text(encoding="utf-8"))
    verdict["anchor"][field] = None
    (sealed.public / "verdict.json").write_text(json.dumps(verdict, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(PolicyError, match=field):
        preserve_module.build(**build_args(sealed))


def test_a_missing_anchor_archive_cannot_be_preserved(sealed):
    with pytest.raises(PolicyError, match="archive"):
        preserve_module.build(**build_args(sealed, archive=sealed.public / "none.tar"))


def test_preservation_re_decides_nothing(tmp_path):
    """A REFUSE is preserved as a REFUSE. Nothing here can turn one into an ACCEPT."""
    run = run_pipeline(tmp_path, docker_config={"pull_fails": True})
    assert run.verdict["verdict"] == "REFUSE"
    assert package_of(run)["verdict"] == "REFUSE"
    assert package_of(run)["verdict_reasons"] == run.verdict["reasons"]


def test_the_preserver_never_contacts_github():
    for forbidden in ("urllib", "subprocess", "socket", "http", "requests"):
        assert forbidden not in imported(ANCHOR / "preserve.py")


def test_the_preserver_builds_only_from_public_members(sealed):
    names = {entry["name"] for entry in package_of(sealed)["files"]}
    assert names == {"verdict.json", "public-capture.json", "policy.json", "anchor-tree.tar"}
    assert not (sealed.public / "capture.json").exists()


# ==========================================================================
# the digest that binds the upload to the signature
# ==========================================================================


def test_the_public_digest_binds_every_name_and_every_byte(sealed):
    before = disclosure.digest_directory(sealed.public)
    (sealed.public / "policy.json").write_bytes((sealed.public / "policy.json").read_bytes() + b" ")
    assert disclosure.digest_directory(sealed.public) != before


def test_a_package_that_does_not_match_the_published_digest_is_refused(sealed):
    process = run_entry("publish.py", "check-digest", "--public-dir", str(sealed.public), "--digest", "0" * 64)
    assert process.returncode == 1 and "PUBLIC_DIGEST_MISMATCH" in process.stdout


def test_a_package_that_matches_the_published_digest_passes(sealed):
    digest = sealed.output("public_digest")
    process = run_entry("publish.py", "check-digest", "--public-dir", str(sealed.public), "--digest", digest)
    assert process.returncode == 0, process.stdout


def test_a_package_with_a_planted_extra_file_fails_the_digest_check_before_it_can_be_signed(sealed):
    digest = sealed.output("public_digest")
    (sealed.public / "extra.txt").write_text("planted", encoding="utf-8")
    process = run_entry("publish.py", "check-digest", "--public-dir", str(sealed.public), "--digest", digest)
    assert process.returncode == 1


# ==========================================================================
# what an independent review found: the verifier checking the box it was told
# about, and a package that is consistent, not merely self-sealed
# ==========================================================================

from pathlib import Path  # noqa: E402


def with_directories(agreeing, **keywords):
    policy, scope = agreeing
    return verify_module.verify(
        policy, scope, SHA_A, good_capture(), read_of(good_evidence_document()), "success",
        good_sandbox(), **keywords,
    )


def test_evidence_and_scope_directories_that_match_the_record_are_accepted(agreeing):
    assert with_directories(
        agreeing, evidence_dir=Path("/host/evidence"), scope_dir=Path("/host/candidate")
    ) == ("ACCEPT", [])


@pytest.mark.parametrize(
    "keywords",
    [
        {"evidence_dir": Path("/elsewhere/evidence")},
        {"scope_dir": Path("/elsewhere/candidate")},
        {"evidence_dir": Path("/host/candidate"), "scope_dir": Path("/host/candidate")},
    ],
)
def test_a_run_judged_on_evidence_from_another_directory_is_refused(agreeing, keywords):
    """The record agreeing with ITSELF is not enough; it must describe the directories
    this verifier is actually reading."""
    keywords = {"evidence_dir": Path("/host/evidence"), "scope_dir": Path("/host/candidate"), **keywords}
    verdict, reasons = with_directories(agreeing, **keywords)
    assert verdict == "REFUSE" and "SANDBOX_LAYOUT" in reasons


@pytest.mark.parametrize(
    "forbidden", [Path("/host/candidate"), Path("/host/candidate/inner"), Path("/host/evidence")]
)
def test_a_mount_that_is_or_contains_a_directory_the_box_must_not_see_is_refused(agreeing, forbidden):
    verdict, reasons = with_directories(
        agreeing, evidence_dir=Path("/host/evidence"), scope_dir=Path("/host/candidate"),
        forbidden_roots=[forbidden],
    )
    assert verdict == "REFUSE" and "SANDBOX_LAYOUT" in reasons


def test_a_mount_that_merely_sits_beside_a_forbidden_directory_is_fine(agreeing):
    verdict, _ = with_directories(
        agreeing, evidence_dir=Path("/host/evidence"), scope_dir=Path("/host/candidate"),
        forbidden_roots=[Path("/host/private")],
    )
    assert verdict == "ACCEPT"


def test_a_record_that_names_the_root_as_a_mount_is_refused_even_if_its_argv_agrees(agreeing):
    layout = sandbox_spec.Layout(Path("/"), Path("/host/child"), Path("/host/evidence"))
    argv = sandbox_spec.build_argv(
        policy_document(), docker=["docker"], name="n", uid=1001, gid=65534, layout=layout,
        candidate=SHA_A, tree=TREE, manifest="",
    )
    record = good_sandbox(layout=layout.as_record(), argv=argv)
    verdict, reasons = verify_module.verify(
        agreeing[0], agreeing[1], SHA_A, good_capture(), read_of(good_evidence_document()),
        "success", record, forbidden_roots=[Path("/host/private")],
    )
    assert verdict == "REFUSE" and "SANDBOX_LAYOUT" in reasons


def test_the_verifier_audits_the_client_it_is_told_to_expect(agreeing):
    verdict, reasons = with_directories(agreeing, docker=["podman"])
    assert verdict == "REFUSE" and "SANDBOX_DOCKER_PREFIX" in reasons


def test_a_capture_with_no_absent_list_is_not_a_capture_with_nothing_absent(agreeing):
    capture = good_capture()
    del capture["absent"]
    assert "INPUT_ABSENT" in decide(agreeing, capture=capture)[1]


def test_a_sandbox_whose_argv_was_told_another_commit_is_refused(agreeing):
    other = good_sandbox()
    other["argv"] = [SHA_B if token == SHA_A else token for token in other["argv"]]
    assert "SANDBOX_COMMAND" in decide(agreeing, sandbox=other)[1]


def test_values_in_the_verdict_that_could_not_be_validated_are_dropped_not_recorded(tmp_path):
    process = run_entry(
        "verify.py", f"--policy={make_policy(tmp_path)}", "--candidate=PRIVATE-not-a-sha",
        "--inputs-manifest=", f"--capture={tmp_path / 'none.json'}", "--capture-digest=" + "0" * 64,
        "--capture-result=PRIVATE-weird", f"--evidence-dir={tmp_path / 'none'}", f"--scope-dir={tmp_path / 's'}", f"--child-dir={tmp_path / 'c'}",
        f"--verdict={tmp_path / 'verdict.json'}", env=good_environment(),
    )
    record = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert process.returncode == 1
    assert record["candidate_sha"] is None and record["capture_result"] is None
    assert "PRIVATE" not in json.dumps(record)


def test_the_verdict_publishes_no_digest_a_guess_could_confirm(tmp_path):
    run = run_pipeline(tmp_path)
    verdict = run.verdict
    for banned in ("capture_digest", "observation_evidence_digest", "required_inputs", "scope", "absent"):
        assert banned not in verdict, banned
    assert set(verdict) == disclosure.VERDICT_KEYS


def test_the_evidence_view_does_not_depend_on_the_content_of_an_extra_input():
    """Same request, two different secrets: an outsider must not be able to tell them apart."""
    policy = policy_document()
    base = good_evidence_document(
        inputs_requested=["extra/secret.txt", *SCOPE],
        inputs_observed=[
            {"relative_path": "extra/secret.txt", "blob": "1" * 40, "sha256": "2" * 64, "size": 9},
            *make_inputs(),
        ],
    )
    other = json.loads(json.dumps(base))
    other["inputs_observed"][0].update(blob="3" * 40, sha256="4" * 64, size=99)
    assert disclosure.evidence_view_digest(base, policy) == disclosure.evidence_view_digest(other, policy)
    assert disclosure.evidence_view(base, policy) == disclosure.evidence_view(other, policy)


def test_the_public_projection_does_not_depend_on_the_content_of_an_extra_input():
    policy = policy_document()
    first = good_capture(
        scope=["extra/secret.txt", *SCOPE],
        inputs=[{"relative_path": "extra/secret.txt", "blob": "1" * 40, "sha256": "2" * 64, "size": 1}, *make_inputs()],
    )
    second = json.loads(json.dumps(first))
    second["inputs"][0].update(blob="5" * 40, sha256="6" * 64, size=42)
    assert disclosure.public_projection(first, policy) == disclosure.public_projection(second, policy)
    assert "extra/secret.txt" not in json.dumps(disclosure.public_projection(first, policy))


# ---- the package: consistent, not merely self-sealed


@pytest.mark.parametrize(
    "field, value",
    [
        ("verdict", "FLIPPED"),
        ("verdict_reasons", ["INPUT_ABSENT"]),
        ("candidate_sha", "f" * 40),
        ("candidate_tree", "f" * 40),
        ("required_floor", ["scripts/other.py"]),
        ("extra_inputs_requested", 99),
        ("governance", {"anything": "else"}),
        ("sandbox", None),
        ("runner", {"os": "Windows"}),
        ("verifier", {"version": "other", "code_digest": "0" * 64}),
        ("evidence_view_digest", "0" * 64),
        ("anchor", {"repository_id": "1", "repository": "x/y", "workflow_ref": "x", "workflow_sha": "a" * 40, "run_id": "1", "run_attempt": "1"}),
    ],
)
def test_a_package_edited_and_then_resealed_is_still_refused(sealed, field, value):
    """The seal is an unkeyed hash - anyone can recompute it. What must catch the edit is
    the package disagreeing with the documents it claims to summarise."""
    package = package_of(sealed)
    package[field] = value
    reseal(sealed, package)
    assert "PACKAGE_INCONSISTENT" in preserve_module.check(sealed.public), field


def test_a_package_with_an_empty_member_list_is_refused_even_when_resealed(sealed):
    package = package_of(sealed)
    package["files"] = []
    reseal(sealed, package)
    assert "PACKAGE_MEMBER_SET" in preserve_module.check(sealed.public)


@pytest.mark.parametrize(
    "names",
    [
        ["../etc/passwd", "public-capture.json", "policy.json", "anchor-tree.tar"],
        ["verdict.json", "verdict.json", "policy.json", "anchor-tree.tar"],
        ["verdict.json", "public-capture.json", "policy.json"],
        ["verdict.json", "public-capture.json", "policy.json", "anchor-tree.tar", "extra.txt"],
        ["/abs/verdict.json", "public-capture.json", "policy.json", "anchor-tree.tar"],
    ],
)
def test_a_package_whose_members_are_not_exactly_the_four_is_refused_even_when_resealed(sealed, names):
    package = package_of(sealed)
    package["files"] = [{"name": name, "sha256": "0" * 64, "size": 0} for name in names]
    reseal(sealed, package)
    assert "PACKAGE_MEMBER_SET" in preserve_module.check(sealed.public)


def test_a_member_record_with_extra_fields_is_refused(sealed):
    package = package_of(sealed)
    package["files"][0]["extra"] = "x"
    reseal(sealed, package)
    assert "PACKAGE_FILE_RECORD" in preserve_module.check(sealed.public)


def test_a_member_whose_size_was_edited_is_refused(sealed):
    package = package_of(sealed)
    package["files"][0]["size"] += 1
    reseal(sealed, package)
    assert "PACKAGE_MEMBER_EDITED" in preserve_module.check(sealed.public)


def test_the_preserver_refuses_an_unisolated_interpreter(tmp_path):
    import subprocess as subprocess_module

    completed = subprocess_module.run(
        [__import__("sys").executable, str(ANCHOR / "preserve.py"), "check", "--package", str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode != 0 and "isolated" in completed.stdout + completed.stderr

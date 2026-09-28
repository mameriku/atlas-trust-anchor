"""The workflows as a structure, the lint that guards them, and attestation acceptance.

The workflow is the one part of this repository a unit test cannot execute, so it is
parsed - as YAML, not grepped - and its structure is asserted: which job holds which
secret, in which step, in what order, with what permissions and what triggers. The
old private-anchor failure (a plaintext bundle uploaded as a public artifact) is
asserted absent by structure, and the lint makes the same mistake unwritable.

Acceptance is the consumer's half of provenance: a GitHub-signed certificate must
name THIS anchor, ref, workflow, run and visibility. The attestation predicate is
never read, because the workflow that made it could have written anything there.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from support import (
    ANCHOR,
    ANCHOR_ID,
    ANCHOR_REPO,
    ROOT,
    SHA_A,
    TEST_WORKFLOW,
    WORKFLOW,
    WORKFLOW_REF,
    make_policy,
    run_entry,
)

import accept as accept_module  # noqa: E402
import disclosure as disclosure_module  # noqa: E402
import pinlint  # noqa: E402
import policy as policy_module  # noqa: E402

yaml = pytest.importorskip("yaml")

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PIN = re.compile(r"\A[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}\Z")
SHIPPED = json.loads((ANCHOR / "policy.json").read_text(encoding="utf-8"))


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(document):
    return document.get("on", document.get(True))


def steps_of(job):
    return job["steps"]


def step_named(job, fragment):
    matches = [step for step in steps_of(job) if fragment in step.get("name", "")]
    assert len(matches) == 1, f"{fragment!r} matched {len(matches)} steps"
    return matches[0]


def index_of(job, fragment):
    return steps_of(job).index(step_named(job, fragment))


def code_lines(path):
    return [
        line for line in path.read_text(encoding="utf-8").splitlines() if not line.strip().startswith("#")
    ]


QUALIFY = load(WORKFLOW)
QUALIFY_JOB = QUALIFY["jobs"]["qualify"]
ATTEST_JOB = QUALIFY["jobs"]["attest"]


# ==========================================================================
# triggers and permissions: who can start it, and what it may do
# ==========================================================================


def test_the_qualification_workflow_can_only_be_dispatched():
    assert set(triggers(QUALIFY)) == {"workflow_dispatch"}


def test_the_dispatch_inputs_are_exactly_the_two_the_caller_may_choose():
    assert set(triggers(QUALIFY)["workflow_dispatch"]["inputs"]) == {"candidate_sha", "inputs_manifest"}


def test_no_workflow_runs_from_a_fork_or_a_comment_with_secrets_in_reach():
    for path in WORKFLOWS:
        text = "\n".join(code_lines(path))
        for trigger in ("pull_request_target", "workflow_run", "issue_comment", "issues:", "discussion"):
            assert trigger not in text, f"{path.name} uses {trigger}"


def test_the_workflow_default_permissions_are_read_only():
    assert QUALIFY["permissions"] == {"contents": "read"}


def test_the_private_job_can_neither_write_nor_mint_a_token():
    assert "permissions" not in QUALIFY_JOB, "it inherits contents: read and nothing more"


def test_only_the_attestation_job_may_sign_and_it_holds_no_credential():
    assert ATTEST_JOB["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}
    assert "environment" not in ATTEST_JOB
    text = json.dumps(ATTEST_JOB)
    for forbidden in ("secrets.", "ATLAS_DEPLOY_KEY", "ANCHOR_GOVERNANCE_TOKEN", "candidate", "capture.py"):
        assert forbidden not in text.replace("candidate_sha", "").replace("candidate-sha", ""), forbidden


def test_the_job_that_holds_the_credential_runs_on_a_github_hosted_runner():
    assert QUALIFY_JOB["runs-on"] == "ubuntu-latest" and ATTEST_JOB["runs-on"] == "ubuntu-latest"
    for job in (QUALIFY_JOB, ATTEST_JOB):
        assert "container" not in job and "services" not in job


def test_the_workflow_has_exactly_the_two_jobs():
    assert set(QUALIFY["jobs"]) == {"qualify", "attest"}


def test_the_credential_is_released_by_an_environment_that_the_policy_names_and_checks():
    assert QUALIFY_JOB["environment"] == SHIPPED["credential"]["environment"]
    assert SHIPPED["governance"]["environment"]["name"] == QUALIFY_JOB["environment"]
    assert SHIPPED["governance"]["environment"]["deployment_branches"] == ["main"]


def test_the_policy_names_this_workflow_file_and_the_default_branch():
    assert SHIPPED["anchor"]["workflow_ref"].endswith("/.github/workflows/qualify.yml@refs/heads/main")
    assert (ROOT / ".github" / "workflows" / "qualify.yml").is_file()
    assert SHIPPED["anchor"]["ref"] == "refs/heads/main"


def test_the_required_status_check_is_the_job_the_test_workflow_defines():
    test = load(TEST_WORKFLOW)
    assert set(test["jobs"]) == {"test"}
    assert SHIPPED["governance"]["required_status_checks"] == ["test"]


# ==========================================================================
# secrets: one credential, one step
# ==========================================================================


def env_of(step):
    return step.get("env", {}) or {}


def test_the_deploy_key_is_bound_in_exactly_one_step_and_no_wider():
    assert "secrets." not in json.dumps(QUALIFY.get("env", {}))
    assert "env" not in QUALIFY_JOB, "a job-level env would hand the key to every step"
    holders = [
        step["name"]
        for job in QUALIFY["jobs"].values()
        for step in steps_of(job)
        if any("ATLAS_DEPLOY_KEY" in str(value) for value in env_of(step).values())
    ]
    assert holders == ["Fetch and freeze the candidate"]
    assert "secrets." not in json.dumps({k: v for k, v in QUALIFY_JOB.items() if k != "steps"})
    assert "secrets." not in json.dumps({k: v for k, v in QUALIFY.items() if k != "jobs"})


def test_the_step_that_holds_the_deploy_key_runs_the_capture_and_nothing_else():
    step = step_named(QUALIFY_JOB, "Fetch and freeze")
    scripts = re.findall(r"anchor/anchor/(\w+)\.py", step["run"])
    assert scripts == ["capture"]


def test_the_governance_token_is_bound_in_the_gate_step_only():
    holders = [
        step["name"]
        for job in QUALIFY["jobs"].values()
        for step in steps_of(job)
        if any("ANCHOR_GOVERNANCE_TOKEN" in str(value) for value in env_of(step).values())
    ]
    assert holders == ["Identity and governance gate"]


@pytest.mark.parametrize("fragment", ["Look at the candidate", "Verify", "Seal", "Audit", "Scrub", "Archive"])
def test_no_step_after_the_capture_holds_any_secret(fragment):
    step = step_named(QUALIFY_JOB, fragment)
    assert "secrets." not in json.dumps(step)


def test_the_credential_is_spent_only_after_identity_and_governance_are_established():
    gate = index_of(QUALIFY_JOB, "Identity and governance gate")
    lint = index_of(QUALIFY_JOB, "Lint the workflows")
    capture = index_of(QUALIFY_JOB, "Fetch and freeze")
    assert 0 < gate < capture and lint < capture
    assert index_of(QUALIFY_JOB, "Check out the trust anchor") == 0


def test_the_steps_run_in_the_order_the_design_depends_on():
    order = [
        "Check out the trust anchor", "Identity and governance gate", "Lint the workflows",
        "Archive the anchor tree", "Fetch and freeze", "Look at the candidate", "Verify",
        "Seal the evidence", "Audit what is about to be public", "Upload the public package",
        "Scrub the private workspace",
    ]
    positions = [index_of(QUALIFY_JOB, fragment) for fragment in order]
    assert positions == sorted(positions)


def test_the_gate_step_writes_the_observation_the_capture_step_reads():
    gate = step_named(QUALIFY_JOB, "Identity and governance gate")["run"]
    capture = step_named(QUALIFY_JOB, "Fetch and freeze")["run"]
    assert "governance.json" in gate and "governance.json" in capture


def test_every_secret_is_bound_as_one_steps_environment_variable_never_inlined():
    for path in WORKFLOWS:
        for line in code_lines(path):
            if "secrets." in line and "GITHUB_TOKEN" not in line:
                assert re.match(r"\s+[A-Z_]+: \$\{\{ secrets\.[A-Z_]+ \}\}\s*$", line), (path.name, line)


def test_the_test_workflow_is_secretless_and_cannot_be_given_any():
    text = "\n".join(code_lines(TEST_WORKFLOW))
    assert "secrets." not in text and "environment:" not in text and "id-token" not in text
    document = load(TEST_WORKFLOW)
    assert document["permissions"] == {"contents": "read"}
    assert "pull_request" in triggers(document), "the check must run on pull requests, without secrets"


def test_the_only_workflow_that_mentions_a_secret_is_the_qualification_one():
    for path in WORKFLOWS:
        mentions = [line for line in code_lines(path) if re.search(r"secrets\.(?!GITHUB_TOKEN)", line)]
        assert bool(mentions) == (path.name == "qualify.yml"), path.name


# ==========================================================================
# N14 regression: no private byte can cross a public artifact
# ==========================================================================


def test_no_private_bundle_or_archive_of_the_candidate_is_ever_made_or_uploaded():
    text = "\n".join(code_lines(WORKFLOW))
    for forbidden in (
        "git bundle", "candidate-bundle", "candidate.bundle", "ATLAS_READ_TOKEN",
        "repository: mameriku/atlas", "git archive --format=tar -o ../candidate", "candidate.tar",
    ):
        assert forbidden not in text, forbidden
    # The word survives only where it names GitHub's own attestation bundle.
    assert "bundle" not in json.dumps(QUALIFY_JOB)


def test_the_only_thing_archived_is_the_anchors_own_public_tree():
    archives = [line for line in code_lines(WORKFLOW) if "git archive" in line]
    assert len(archives) == 1 and "public/anchor-tree.tar" in archives[0]
    step = step_named(QUALIFY_JOB, "Archive the anchor tree")
    assert step["working-directory"] == "anchor"


def test_exactly_two_things_are_uploaded_and_both_are_public_directories():
    uploads = [
        step for job in QUALIFY["jobs"].values() for step in steps_of(job)
        if "upload-artifact" in step.get("uses", "")
    ]
    assert sorted(step["with"]["path"] for step in uploads) == ["attestation/", "public/"]


def test_the_public_upload_happens_only_when_the_audit_succeeded():
    upload = step_named(QUALIFY_JOB, "Upload the public package")
    assert "steps.audit.outcome == 'success'" in upload["if"]
    assert index_of(QUALIFY_JOB, "Audit what is about to be public") < index_of(QUALIFY_JOB, "Upload the public package")


def test_the_audit_holds_the_private_directory_it_checks_against():
    run = step_named(QUALIFY_JOB, "Audit what is about to be public")["run"]
    assert "--private-dir" in run and "anchor-sandbox/candidate" in run


def test_the_candidate_never_reaches_a_second_job():
    text = json.dumps(ATTEST_JOB)
    assert "anchor-sandbox" not in text and "anchor-private" not in text
    downloads = [s for s in steps_of(ATTEST_JOB) if "download-artifact" in s.get("uses", "")]
    assert [d["with"]["name"] for d in downloads] == ["public-${{ github.run_id }}-${{ github.run_attempt }}"]


def test_there_is_no_candidate_checkout_or_target_repository_in_the_workflow():
    for job in QUALIFY["jobs"].values():
        for step in steps_of(job):
            if "actions/checkout" in step.get("uses", ""):
                assert "repository" not in step.get("with", {})
                assert "token" not in step.get("with", {})


# ==========================================================================
# the steps that must not be skippable, and the scripts that run isolated
# ==========================================================================


@pytest.mark.parametrize(
    "fragment",
    ["Verify", "Seal the evidence", "Audit what is about to be public", "Upload the public package", "Scrub"],
)
def test_the_steps_after_the_sandbox_run_even_if_an_earlier_step_failed(fragment):
    assert "always()" in step_named(QUALIFY_JOB, fragment)["if"]


@pytest.mark.parametrize("fragment", ["Identity and governance gate", "Lint the workflows", "Fetch and freeze", "Look at the candidate"])
def test_the_steps_that_gate_the_credential_do_not_run_after_a_failure(fragment):
    assert "if" not in step_named(QUALIFY_JOB, fragment)


def test_the_verifier_is_told_the_capture_outcome_by_the_platform_not_by_a_file():
    env = env_of(step_named(QUALIFY_JOB, "Verify"))
    assert env["CAPTURE_OUTCOME"] == "${{ steps.capture.outcome }}"
    assert env["CAPTURE_DIGEST"] == "${{ steps.capture.outputs.capture_digest }}"


def test_the_public_digest_is_a_job_output_the_attestation_job_consumes():
    assert QUALIFY_JOB["outputs"]["public_digest"] == "${{ steps.audit.outputs.public_digest }}"
    assert env_of(step_named(ATTEST_JOB, "Check the package"))["PUBLIC_DIGEST"] == "${{ needs.qualify.outputs.public_digest }}"
    assert ATTEST_JOB["needs"] == "qualify"


def test_the_attestation_job_checks_the_digest_before_it_signs_anything():
    assert index_of(ATTEST_JOB, "Check the package") < index_of(ATTEST_JOB, "Attest the verdict")
    assert index_of(ATTEST_JOB, "Identity gate") < index_of(ATTEST_JOB, "Download the public package")


def test_the_attestation_is_bound_to_the_verdict_alone():
    step = step_named(ATTEST_JOB, "Attest the verdict")
    assert step["with"] == {"subject-path": "public/verdict.json"}
    assert PIN.match(step["uses"].split(" ")[0])


def test_every_action_is_pinned_to_a_full_commit_with_a_version_comment():
    for path in WORKFLOWS:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = re.match(r"\s*-?\s*uses:\s*(\S+)\s*(#\s*v\S+)?", line)
            if match:
                assert PIN.match(match.group(1)), f"{path.name}:{number}"
                assert match.group(2), f"{path.name}:{number} has no version comment"


def test_no_checkout_persists_its_credential():
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        assert text.count("persist-credentials: false") == text.count("uses: actions/checkout@")


def test_the_workflow_starts_every_trusted_script_isolated():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "PY: python3 -I -S -B" in text
    for line in text.splitlines():
        stripped = line.strip()
        if re.search(r"anchor/anchor/\w+\.py", stripped) and not stripped.startswith(("#", "cp ")):
            assert stripped.startswith(("$PY", "--")) or "$PY" in stripped, f"not isolated: {stripped}"


def test_pythonpath_is_not_set_anywhere():
    """-I ignores PYTHONPATH, so a workflow that pins it is pinning nothing."""
    for path in WORKFLOWS:
        for line in path.read_text(encoding="utf-8").splitlines():
            assert not line.strip().startswith("PYTHONPATH:"), line


def test_the_scripts_the_workflow_runs_all_exist_and_use_the_flags_they_are_given():
    text = WORKFLOW.read_text(encoding="utf-8")
    for script in set(re.findall(r"anchor/anchor/(\w+)\.py", text)):
        assert (ANCHOR / f"{script}.py").is_file(), script


def test_the_child_is_run_by_the_sandbox_script_and_docker_is_never_named_in_a_workflow():
    assert "sandbox.py" in step_named(QUALIFY_JOB, "Look at the candidate")["run"]
    assert not [line for line in code_lines(WORKFLOW) if re.search(r"(?<![\w./-])docker(?![\w-])", line)]


# ==========================================================================
# the lint, exercised by making it fail
# ==========================================================================


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_the_real_workflows_pass_the_lint(path):
    assert pinlint.problems_in(path.read_text(encoding="utf-8"), path.name) == []


def test_the_lint_passes_the_repository_as_committed():
    assert pinlint.main([str(ROOT / ".github" / "workflows")]) == 0


def test_the_lint_refuses_to_report_success_when_it_found_nothing_to_check(tmp_path):
    assert pinlint.main([str(tmp_path)]) == 2


@pytest.mark.parametrize(
    "line, expected",
    [
        ("      - uses: actions/checkout@v4\n", "not pinned"),
        ("      - uses: actions/checkout@v5.0.0\n", "not pinned"),
        ("      - uses: actions/checkout@11bd719\n", "not pinned"),
        ("      - uses: actions/checkout@main\n", "not pinned"),
        ('      - uses: "actions/checkout@v4"\n', "not pinned"),
        ("        continue-on-error: true\n", "non-terminal"),
        ("    continue-on-error: false\n", "non-terminal"),
    ],
)
def test_the_lint_fires_on_an_unpinned_or_non_terminal_workflow(line, expected):
    assert any(expected in problem for problem in pinlint.problems_in(line, "probe.yml"))


def test_a_full_sha_pin_with_a_version_comment_passes():
    line = "      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0\n"
    assert pinlint.problems_in(line, "probe.yml") == []


def test_the_lint_fires_when_a_caller_string_is_spliced_into_a_shell():
    injected = "      - name: x\n        run: |\n          echo ${{ inputs.candidate_sha }}\n"
    assert any("spliced" in p for p in pinlint.problems_in(injected, "probe.yml"))


def test_the_lint_fires_on_a_single_line_run_with_an_expression():
    assert any("spliced" in p for p in pinlint.problems_in("      - run: echo ${{ inputs.x }}\n", "probe.yml"))


def test_the_lint_does_not_confuse_a_with_block_for_a_run_block():
    block = (
        "      - uses: actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4\n"
        "        with:\n          name: verdict-${{ github.run_id }}\n          path: public/\n"
    )
    assert pinlint.problems_in(block, "probe.yml") == []


UPLOAD = "      - uses: actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4\n        with:\n          name: x\n          path: {path}\n"


@pytest.mark.parametrize(
    "path",
    ["candidate.bundle", "candidate/", ".", "..", "/tmp/x", "capture/capture.json", "publicity/", "./public/",
     "${{ runner.temp }}/anchor-sandbox", "anchor/", "public-not/", "|"],
)
def test_the_lint_refuses_an_upload_from_anywhere_but_the_public_directories(path):
    problems = pinlint.problems_in(UPLOAD.format(path=path), "probe.yml")
    assert any("upload-artifact" in p for p in problems), path


@pytest.mark.parametrize("path", ["public", "public/", "public/verdict.json", "attestation/", "'public/'", '"attestation/x"'])
def test_the_lint_allows_an_upload_from_a_public_directory(path):
    assert not [p for p in pinlint.problems_in(UPLOAD.format(path=path), "probe.yml") if "upload-artifact" in p]


def test_the_lint_refuses_an_upload_that_names_no_path_or_two():
    none = "      - uses: actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4\n        with:\n          name: x\n"
    two = UPLOAD.format(path="public/") + "          path: candidate/\n"
    assert any("exactly one path" in p for p in pinlint.problems_in(none, "probe.yml"))
    assert any("exactly one path" in p for p in pinlint.problems_in(two, "probe.yml"))


@pytest.mark.parametrize(
    "line",
    ["          set -x\n", "          bash -xe script\n", "          set -euxo pipefail\n", "          printenv\n",
     "          env | sort\n", "          export -p\n", "        ACTIONS_STEP_DEBUG: true\n", "          ACTIONS_RUNNER_DEBUG=1 cmd\n"],
)
def test_the_lint_refuses_shell_tracing_and_environment_dumps(line):
    assert any("traces the shell" in p for p in pinlint.problems_in("      - run: |\n" + line, "probe.yml"))


def test_the_lint_does_not_object_to_a_comment_that_mentions_tracing():
    assert pinlint.problems_in("# never use set -x or printenv here\n", "probe.yml") == []


@pytest.mark.parametrize(
    "line, name",
    [
        ("          TOKEN: ${{ secrets.ANY }}\n", "other.yml"),
        ("          with: ${{ secrets.ANY }}\n", "qualify.yml"),
        ("      token: ${{ secrets.ANY }}\n", "qualify.yml"),
        ("    secrets: inherit\n", "qualify.yml"),
        ("      - run: echo ${{ secrets.ANY }}\n", "qualify.yml"),
    ],
)
def test_the_lint_refuses_a_secret_that_is_not_one_steps_env_binding_in_the_qualification_workflow(line, name):
    assert pinlint.problems_in(line, name)


def test_the_lint_allows_the_env_binding_form_only_in_the_qualification_workflow():
    binding = "        env:\n          ATLAS_DEPLOY_KEY: ${{ secrets.ATLAS_DEPLOY_KEY }}\n"
    assert pinlint.problems_in(binding, "qualify.yml") == []
    assert pinlint.problems_in(binding, "test.yml")


def test_the_lint_allows_the_job_token_anywhere():
    assert pinlint.problems_in("          T: ${{ secrets.GITHUB_TOKEN }}\n", "test.yml") == []


def test_the_lint_refuses_docker_in_a_run_block_but_not_in_a_comment():
    assert any("docker" in p for p in pinlint.problems_in("      - run: |\n          docker run x\n", "probe.yml"))
    assert not any("docker" in p for p in pinlint.problems_in("      - run: |\n          # docker is not used\n          echo hi\n", "probe.yml"))


@pytest.mark.parametrize("trigger", ["pull_request_target", "workflow_run", "issue_comment"])
def test_the_lint_refuses_a_trigger_that_runs_with_secrets_in_reach(trigger):
    assert any("trigger" in p for p in pinlint.problems_in(f"on:\n  {trigger}:\n", "probe.yml"))


# ==========================================================================
# attestation acceptance
# ==========================================================================


def policy(tmp_path):
    return policy_module.load(make_policy(tmp_path))


def verdict(**anchor):
    return {
        "verdict_version": disclosure_module.VERDICT_VERSION,
        "verdict": "ACCEPT",
        "reasons": [],
        "candidate_sha": SHA_A,
        "anchor": {"run_id": "4242", "run_attempt": "1", "workflow_sha": SHA_A, **anchor},
    }


def good_certificate(**overrides):
    certificate = {
        "sourceRepositoryURI": f"https://github.com/{ANCHOR_REPO}",
        "sourceRepositoryIdentifier": str(ANCHOR_ID),
        "sourceRepositoryRef": "refs/heads/main",
        "githubWorkflowRef": WORKFLOW_REF,
        "githubWorkflowTrigger": "workflow_dispatch",
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryVisibilityAtSigning": "public",
        "sourceRepositoryDigest": SHA_A,
        "runInvocationURI": f"https://github.com/{ANCHOR_REPO}/actions/runs/4242/attempts/1",
    }
    certificate.update(overrides)
    return certificate


def test_a_certificate_naming_this_anchors_run_is_accepted(tmp_path):
    assert accept_module.check_certificate(good_certificate(), policy(tmp_path), verdict()) == []


def test_certificate_field_names_are_matched_regardless_of_casing(tmp_path):
    shouty = {key.upper(): value for key, value in good_certificate().items()}
    assert accept_module.check_certificate(shouty, policy(tmp_path), verdict()) == []


@pytest.mark.parametrize(
    "override",
    [
        {"sourceRepositoryURI": "https://github.com/someone/else"},
        {"sourceRepositoryIdentifier": "1"},
        {"sourceRepositoryRef": "refs/heads/feature"},
        {"sourceRepositoryRef": "refs/tags/v1"},
        {"githubWorkflowRef": WORKFLOW_REF.replace("qualify", "other")},
        {"githubWorkflowRef": WORKFLOW_REF.replace("heads/main", "heads/dev")},
        {"githubWorkflowTrigger": "push"},
        {"githubWorkflowTrigger": "pull_request"},
        {"runnerEnvironment": "self-hosted"},
        {"sourceRepositoryVisibilityAtSigning": "private"},
        {"sourceRepositoryDigest": "f" * 40},
        {"runInvocationURI": f"https://github.com/{ANCHOR_REPO}/actions/runs/9999/attempts/1"},
        {"runInvocationURI": f"https://github.com/{ANCHOR_REPO}/actions/runs/4242/attempts/2"},
        {"runInvocationURI": "https://github.com/someone/else/actions/runs/4242/attempts/1"},
    ],
)
def test_a_certificate_that_names_anything_else_is_refused(tmp_path, override):
    assert accept_module.check_certificate(good_certificate(**override), policy(tmp_path), verdict()) == [
        "ATTESTATION_IDENTITY_MISMATCH"
    ]


@pytest.mark.parametrize("field", sorted(good_certificate()))
def test_a_certificate_missing_a_field_is_refused_rather_than_assumed_fine(tmp_path, field):
    certificate = good_certificate()
    del certificate[field]
    assert accept_module.check_certificate(certificate, policy(tmp_path), verdict()) == ["ATTESTATION_FIELD_MISSING"]


def test_a_verdict_that_names_no_run_cannot_match_a_certificate(tmp_path):
    assert accept_module.check_certificate(good_certificate(), policy(tmp_path), {"verdict": "ACCEPT"})


def test_the_verification_command_pins_the_signer_the_ref_and_the_runner_kind(tmp_path):
    command = accept_module.verify_command(["gh"], Path("v.json"), Path("b.jsonl"), policy(tmp_path))
    joined = " ".join(command)
    assert "--repo mameriku/atlas-trust-anchor" in joined
    assert "--signer-workflow mameriku/atlas-trust-anchor/.github/workflows/qualify.yml" in joined
    assert "--source-ref refs/heads/main" in joined
    assert "--deny-self-hosted-runners" in command and "--bundle" in command
    assert command[-2:] == ["--format", "json"]
    assert "@" not in accept_module.signer_workflow(policy(tmp_path))


def fake_gh(tmp_path, *, stdout="", code=0):
    script = tmp_path / "gh.py"
    script.write_text(
        f"import sys\nsys.stdout.write({stdout!r})\nsys.exit({code})\n", encoding="utf-8"
    )
    return [sys.executable, str(script)]


def attested(certificates, predicate=None):
    return json.dumps(
        [
            {
                "attestation": {},
                "verificationResult": {
                    "signature": {"certificate": certificate},
                    "statement": {"predicate": predicate or {}},
                },
            }
            for certificate in certificates
        ]
    )


def run_accept(tmp_path, gh, document=None, candidate=SHA_A, policy_sha256=None):
    path = tmp_path / "verdict.json"
    path.write_text(json.dumps(document if document is not None else verdict()), encoding="utf-8")
    return accept_module.accept(path, tmp_path / "bundle.jsonl", policy(tmp_path), gh, candidate, policy_sha256)


def test_a_verified_attestation_from_this_anchor_returns_the_verdict_the_file_states(tmp_path):
    gh = fake_gh(tmp_path, stdout=attested([good_certificate()]))
    assert run_accept(tmp_path, gh) == ("ACCEPT", [])


def test_an_authentic_refusal_is_reported_as_a_refusal_not_as_a_failure_to_verify(tmp_path):
    gh = fake_gh(tmp_path, stdout=attested([good_certificate()]))
    refused = {**verdict(), "verdict": "REFUSE", "reasons": ["INPUT_ABSENT"]}
    assert run_accept(tmp_path, gh, refused) == ("REFUSE", [])


def test_a_signature_gh_could_not_verify_is_refused(tmp_path):
    assert run_accept(tmp_path, fake_gh(tmp_path, code=1))[1] == ["ATTESTATION_NOT_VERIFIED"]


@pytest.mark.parametrize("output", ["", "not json", "{}", "[]", json.dumps([{"verificationResult": {}}]), json.dumps(["x"])])
def test_an_answer_with_no_certificate_in_it_is_refused(tmp_path, output):
    assert run_accept(tmp_path, fake_gh(tmp_path, stdout=output))[1] == ["ATTESTATION_NO_CERTIFICATE"]


def test_a_missing_gh_is_a_refusal_not_a_crash(tmp_path):
    assert run_accept(tmp_path, ["definitely-not-gh-xyz"])[1] == ["ATTESTATION_TOOL_FAILED"]


def test_an_unreadable_verdict_is_refused_before_gh_is_asked_anything(tmp_path):
    (tmp_path / "verdict.json").write_text("{nope", encoding="utf-8")
    result = accept_module.accept(tmp_path / "verdict.json", tmp_path / "b", policy(tmp_path), ["gh"], SHA_A)
    assert result == (None, ["VERDICT_UNREADABLE"])


def test_the_predicate_is_never_believed_even_when_it_says_everything_is_fine(tmp_path):
    """The workflow that made the attestation could have written any predicate. A
    certificate naming another repository is refused whatever the predicate claims."""
    lying = {"repository": ANCHOR_REPO, "ref": "refs/heads/main", "verdict": "ACCEPT", "trusted": True}
    bad = good_certificate(sourceRepositoryURI="https://github.com/someone/else")
    gh = fake_gh(tmp_path, stdout=attested([bad], predicate=lying))
    verdict_and_reasons = run_accept(tmp_path, gh)
    assert verdict_and_reasons == (None, ["ATTESTATION_IDENTITY_MISMATCH"])


def test_every_certificate_in_the_answer_must_name_this_anchor(tmp_path):
    gh = fake_gh(tmp_path, stdout=attested([good_certificate(), good_certificate(githubWorkflowTrigger="push")]))
    assert run_accept(tmp_path, gh)[1] == ["ATTESTATION_IDENTITY_MISMATCH"]


def test_the_acceptance_helper_reads_nothing_from_the_predicate():
    source = (ANCHOR / "accept.py").read_text(encoding="utf-8")
    assert '"predicate"' not in source and "'predicate'" not in source and ".predicate" not in source


def test_the_acceptance_entry_point_refuses_a_bad_policy_and_a_missing_tool(tmp_path):
    (tmp_path / "v.json").write_text(json.dumps(verdict()), encoding="utf-8")
    missing = run_entry(
        "accept.py", "--policy", str(make_policy(tmp_path)), "--verdict", str(tmp_path / "v.json"),
        "--bundle", str(tmp_path / "b"), "--candidate", SHA_A, "--gh", "definitely-not-gh-xyz",
    )
    assert missing.returncode == 1 and "ATTESTATION_TOOL_FAILED" in missing.stdout
    unbound = json.loads(json.dumps(SHIPPED))
    unbound["anchor"]["repository_id"] = None
    unbound_path = tmp_path / "unbound-policy.json"
    unbound_path.write_text(json.dumps(unbound), encoding="utf-8")
    bad = run_entry(
        "accept.py", "--policy", str(unbound_path), "--verdict", str(tmp_path / "v.json"),
        "--bundle", str(tmp_path / "b"), "--candidate", SHA_A,
    )
    assert bad.returncode == 2 and "POLICY_REFUSED" in bad.stdout


# ==========================================================================
# the governance file and the ruleset it applies
# ==========================================================================

RULESET = json.loads((ROOT / "governance" / "ruleset-main.json").read_text(encoding="utf-8"))


def ruleset_rule(kind):
    return next(rule for rule in RULESET["rules"] if rule["type"] == kind)


def test_the_ruleset_the_bootstrap_applies_is_exactly_what_policy_requires():
    required = SHIPPED["governance"]
    assert {rule["type"] for rule in RULESET["rules"]} == set(required["required_rules"])
    assert RULESET["enforcement"] == "active" and RULESET["target"] == "branch"
    assert RULESET["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert RULESET["bypass_actors"] == [], "the bypass list must be empty"


def test_the_ruleset_requires_review_from_someone_who_did_not_push():
    parameters = ruleset_rule("pull_request")["parameters"]
    assert parameters["required_approving_review_count"] >= SHIPPED["governance"]["required_approvals"]
    assert parameters["dismiss_stale_reviews_on_push"] is True
    assert parameters["require_last_push_approval"] is True
    assert parameters["required_review_thread_resolution"] is True


def test_the_ruleset_requires_exactly_the_status_check_policy_names():
    contexts = [c["context"] for c in ruleset_rule("required_status_checks")["parameters"]["required_status_checks"]]
    assert contexts == SHIPPED["governance"]["required_status_checks"]


def test_the_governance_document_asks_for_nothing_paid():
    text = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    lowered = text.lower()
    for phrase in ("upgrade the account", "github pro", "purchase", "paid plan", "403 upgrade"):
        assert phrase not in lowered, phrase
    assert "GitHub Free" in text


def test_the_governance_document_states_the_one_free_prerequisite_instead_of_lowering_the_review():
    text = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    assert "second GitHub account" in text and "not** lowered" in text


def test_the_bootstrap_commands_in_the_governance_document_exist_in_the_repository():
    text = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    assert "governance/ruleset-main.json" in text
    assert "--allow-write" in text and "Do not pass it" in text
    assert "atlas-qualification" in text


def test_the_stated_bounds_remain_stated():
    """The README names what is trusted. If that goes, the claim has drifted."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for phrase in (
        "access control",
        "cannot bootstrap itself",
        "never chooses **who** judges",
        "infrastructure trust assumption",
        "This repository is public. The thing it judges is private.",
        "the recursion",
    ):
        assert phrase in readme, f"the README no longer states: {phrase}"


# ==========================================================================
# what an independent review found: a genuine verdict is not evidence about
# another commit, an older policy, or a file that has been mis-built
# ==========================================================================


def signed(tmp_path):
    return fake_gh(tmp_path, stdout=attested([good_certificate()]))


def test_a_genuine_verdict_for_another_commit_is_refused(tmp_path):
    """Public artifacts can be replayed: an ACCEPT for commit A, shown as proof for B."""
    assert run_accept(tmp_path, signed(tmp_path), candidate="c" * 40) == (None, ["VERDICT_CANDIDATE_MISMATCH"])


@pytest.mark.parametrize("candidate", ["", "abc", "A" * 40, "z" * 40, SHA_A + "0"])
def test_a_candidate_that_is_not_a_full_lowercase_sha_is_refused_before_gh_is_asked(tmp_path, candidate):
    assert run_accept(tmp_path, ["definitely-not-gh-xyz"], candidate=candidate) == (None, ["CANDIDATE_INVALID"])


def test_a_verdict_of_another_schema_version_is_refused(tmp_path):
    document = {**verdict(), "verdict_version": "atlas-anchor-verdict/1"}
    assert run_accept(tmp_path, signed(tmp_path), document) == (None, ["VERDICT_VERSION"])


@pytest.mark.parametrize(
    "document, code",
    [
        ({"verdict": "ACCEPT", "reasons": ["INPUT_ABSENT"]}, "VERDICT_INCONSISTENT"),
        ({"verdict": "ACCEPT", "reasons": None}, "VERDICT_INCONSISTENT"),
        ({"verdict": "REFUSE", "reasons": []}, "VERDICT_INCONSISTENT"),
        ({"verdict": "MAYBE", "reasons": []}, "VERDICT_UNKNOWN"),
        ({"verdict": None, "reasons": []}, "VERDICT_UNKNOWN"),
        ({"verdict": True, "reasons": []}, "VERDICT_UNKNOWN"),
    ],
)
def test_a_verdict_the_verifier_could_not_have_produced_is_refused(tmp_path, document, code):
    assert run_accept(tmp_path, signed(tmp_path), {**verdict(), **document}) == (None, [code])


def test_a_verdict_made_under_another_policy_is_refused_unless_the_caller_says_otherwise(tmp_path):
    made_under = {**verdict(), "policy_digest": "a" * 64}
    assert run_accept(tmp_path, signed(tmp_path), made_under, policy_sha256="b" * 64) == (
        None, ["VERDICT_POLICY_MISMATCH"],
    )
    assert run_accept(tmp_path, signed(tmp_path), made_under, policy_sha256="a" * 64) == ("ACCEPT", [])
    assert run_accept(tmp_path, signed(tmp_path), made_under, policy_sha256=None) == ("ACCEPT", [])


def test_the_acceptance_entry_point_requires_the_commit_being_relied_on(tmp_path):
    process = run_entry(
        "accept.py", "--policy", str(make_policy(tmp_path)), "--verdict", str(tmp_path / "v.json"),
        "--bundle", str(tmp_path / "b"),
    )
    assert process.returncode == 2 and "USAGE_ERROR" in process.stdout


def test_the_acceptance_entry_point_names_the_policy_it_holds_by_default():
    source = (ANCHOR / "accept.py").read_text(encoding="utf-8")
    assert "--allow-older-policy" in source and "hashlib.sha256(arguments.policy.read_bytes())" in source


# ---- the lint, against the bypasses the review found


@pytest.mark.parametrize(
    "line",
    [
        "          K: ${{ secrets['ATLAS_DEPLOY_KEY'] }}\n",
        "          K: ${{ secrets [ 'ATLAS_DEPLOY_KEY' ] }}\n",
        "          J: ${{ toJSON(secrets) }}\n",
        "          J: ${{ tojson( secrets ) }}\n",
        "          T: ${{ SECRETS.ATLAS_DEPLOY_KEY }}\n",
    ],
)
def test_the_lint_refuses_a_secret_reference_however_it_is_spelled(line):
    assert pinlint.problems_in(line, "test.yml"), line
    assert pinlint.problems_in(line, "qualify.yml"), line


def test_the_lint_refuses_an_upload_action_however_its_name_is_cased():
    step = (
        "      - uses: Actions/Upload-Artifact@330a01c490aca151604b8cf639adc76d48f6c5d4\n"
        "        with:\n          name: x\n          path: candidate/\n"
    )
    assert any("upload-artifact" in problem for problem in pinlint.problems_in(step, "probe.yml"))


@pytest.mark.parametrize("line", ["    container: ubuntu:24.04\n", "  container:\n", "    services:\n", "  services:\n"])
def test_the_lint_refuses_a_container_or_service_it_cannot_audit(line):
    assert any("cannot audit" in problem for problem in pinlint.problems_in(line, "probe.yml"))


@pytest.mark.parametrize(
    "line",
    ["      - { run: echo hi }\n", "      - {name: x, run: y}\n", "        env: *shared\n", "        <<: *defaults\n", "      - &step\n"],
)
def test_the_lint_refuses_the_yaml_forms_that_hide_a_step_from_it(line):
    assert any("hide" in problem for problem in pinlint.problems_in(line, "probe.yml")), line


def test_the_lint_refuses_the_test_seam_in_any_workflow_but_not_in_a_comment():
    assert any("test seam" in p for p in pinlint.problems_in("      - run: |\n          $PY x --docker-command '[]'\n", "probe.yml"))
    assert not any("test seam" in p for p in pinlint.problems_in("# --docker-command is for tests\n", "probe.yml"))


def test_the_lint_refuses_docker_however_it_is_cased_in_a_run_block():
    assert any("docker" in p for p in pinlint.problems_in("      - run: |\n          DOCKER run x\n", "probe.yml"))


# ---- the workflow, against the same review


def test_dispatch_derived_values_are_passed_attached_so_they_never_parse_as_options():
    """An input shaped like an option must be a VALUE. `--candidate="$X"` cannot be
    read as anything else; `--candidate "$X"` can be, if $X begins with a dash."""
    for line in code_lines(WORKFLOW):
        if "$CANDIDATE_SHA" in line or "$INPUTS_MANIFEST" in line or "$CAPTURE_DIGEST" in line or "$CAPTURE_OUTCOME" in line:
            assert re.search(r'--[a-z-]+="\$', line), line


def test_the_verifier_is_told_which_directories_the_box_used():
    run = step_named(QUALIFY_JOB, "Verify")["run"]
    assert "--scope-dir" in run and "--evidence-dir" in run and "--sandbox-record" in run


def test_the_audit_is_given_the_freeze_it_must_keep_out_of_public_files():
    run = step_named(QUALIFY_JOB, "Audit what is about to be public")["run"]
    for argument in ("--private-dir", "--capture", "--policy"):
        assert argument in run


def test_no_workflow_contains_the_test_seam_that_chooses_the_container_client():
    for path in WORKFLOWS:
        assert "--docker-command" not in "\n".join(code_lines(path)), path.name


def test_the_ruleset_pins_the_required_check_to_the_github_actions_integration():
    checks = ruleset_rule("required_status_checks")["parameters"]["required_status_checks"]
    assert checks == [{"context": "test", "integration_id": SHIPPED["governance"]["required_status_check_integration_id"]}]
    assert SHIPPED["governance"]["required_status_check_integration_id"] == 15368


def test_the_governance_document_states_what_the_review_added():
    text = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    for phrase in (
        "can_admins_bypass",
        "repository secret",
        "integration",
        "Secrets",
        "environment_only_secrets",
        "extra input",
        "guess",
    ):
        assert phrase in text, phrase


def test_the_governance_document_keeps_change_control_apart_from_independent_review():
    text = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    for phrase in (
        "Change control is not independent review",
        "same person",
        "not independent review evidence",
        "N2 stays **BLOCKED**",
        "fresh model reviewer",
    ):
        assert phrase in text, phrase
    assert "not** lowered" in text or "is not lowered" in text

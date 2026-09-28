"""The freeze, and the child that looks at it.

The freeze is the only account of what the candidate IS, and it is made from git's
object store, at a commit, after the credential is gone. The child is the only
code that touches candidate bytes, and it does so in a box. So the tests that matter
are the ones where the candidate tries to be something other than a plain file, or
tries to bring its own judge.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

from support import (
    ALPHA,
    ANCHOR,
    BETA,
    FAKE_KEY,
    SHA_A,
    _git,
    good_environment,
    governed_observation,
    make_candidate,
    make_policy,
    run_entry,
    sha256_hex,
)

import capture as capture_module  # noqa: E402
import evidence as evidence_module  # noqa: E402
import policy as policy_module  # noqa: E402
import publog  # noqa: E402
import runner as runner_module  # noqa: E402
import target  # noqa: E402
from pipeline import run_pipeline  # noqa: E402


def freeze(tmp_path, files=None, scope=None, limit=1 << 20, root_name="candidate"):
    root = tmp_path / root_name
    sha = make_candidate(root, files)
    environment = target.git_environment(tmp_path / "home", {"PATH": os.environ["PATH"]})
    (tmp_path / "home").mkdir(exist_ok=True)
    record = capture_module.capture(
        environment, root, sha, scope or [ALPHA], limit, tmp_path / "scope"
    )
    return root, sha, record


# ==========================================================================
# the freeze reads the object store
# ==========================================================================


def test_capture_reads_the_object_store_and_records_what_is_absent(tmp_path):
    _, sha, record = freeze(tmp_path, scope=[ALPHA, "src/missing.py"])
    assert record["candidate_sha"] == sha
    assert record["absent"] == ["src/missing.py"]
    assert record["inputs"][0]["sha256"] == hashlib.sha256(b"A = 1\n").hexdigest()


def test_capture_reads_the_object_store_not_the_working_tree(tmp_path):
    """A dirty checkout is not a candidate."""
    root = tmp_path / "candidate"
    sha = make_candidate(root)
    (root / ALPHA).write_text("A = 999  # uncommitted\n", encoding="utf-8")
    (tmp_path / "home").mkdir()
    environment = target.git_environment(tmp_path / "home", {"PATH": os.environ["PATH"]})
    record = capture_module.capture(environment, root, sha, [ALPHA], 1 << 20, tmp_path / "scope")
    assert record["inputs"][0]["sha256"] == hashlib.sha256(b"A = 1\n").hexdigest()
    assert (tmp_path / "scope" / ALPHA).read_bytes() == b"A = 1\n"


def test_capture_refuses_a_commit_that_is_not_the_one_asked_for(tmp_path):
    root = tmp_path / "candidate"
    make_candidate(root)
    (tmp_path / "home").mkdir()
    environment = target.git_environment(tmp_path / "home", {"PATH": os.environ["PATH"]})
    with pytest.raises(publog.TargetError) as error:
        capture_module.capture(environment, root, SHA_A, [ALPHA], 1 << 20, tmp_path / "scope")
    assert error.value.code == "TARGET_IDENTITY_MISMATCH"


def test_capture_does_not_freeze_a_directory_as_if_it_were_a_file(tmp_path):
    _, _, record = freeze(tmp_path, scope=["src"])
    assert record["absent"] == ["src"]
    assert record["inputs"] == []


def test_capture_records_the_tree_as_well_as_the_commit(tmp_path):
    root, sha, record = freeze(tmp_path)
    assert record["candidate_tree"] == _git(root, "rev-parse", f"{sha}^{{tree}}")


def test_an_executable_file_is_a_usable_input(tmp_path):
    root = tmp_path / "candidate"
    make_candidate(root, {"run.sh": "echo hi\n"})
    _git(root, "update-index", "--chmod=+x", "run.sh")
    _git(root, "commit", "-qm", "exec")
    sha = _git(root, "rev-parse", "HEAD")
    (tmp_path / "home").mkdir()
    environment = target.git_environment(tmp_path / "home", {"PATH": os.environ["PATH"]})
    record = capture_module.capture(environment, root, sha, ["run.sh"], 1 << 20, tmp_path / "scope")
    assert record["absent"] == [] and len(record["inputs"]) == 1


def _add_special(root, path, mode, content=b"other/place\n"):
    blob = subprocess.run(
        ["git", "-C", str(root), "hash-object", "-w", "--stdin"],
        input=content, capture_output=True, check=True,
    ).stdout.decode().strip()
    _git(root, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}")
    _git(root, "commit", "-qm", "special")
    return _git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize("mode, description", [("120000", "symlink"), ("160000", "submodule")])
def test_a_symlink_or_submodule_is_not_frozen_as_if_it_were_a_file(tmp_path, mode, description):
    """A mode-120000 entry is a blob whose content is a PATH. Freezing it as a file
    would let the candidate choose what a required 'file' contains by pointing
    elsewhere; a 160000 entry names a commit that is not in this repository at all."""
    root = tmp_path / "candidate"
    make_candidate(root)
    content = b"other/place\n" if mode == "120000" else b"e" * 0
    if mode == "160000":
        sha = _git(root, "rev-parse", "HEAD")
        _git(root, "update-index", "--add", "--cacheinfo", f"160000,{sha},linked")
        _git(root, "commit", "-qm", "submodule")
    else:
        _add_special(root, "linked", mode, content)
    head = _git(root, "rev-parse", "HEAD")
    (tmp_path / "home").mkdir()
    environment = target.git_environment(tmp_path / "home", {"PATH": os.environ["PATH"]})
    record = capture_module.capture(environment, root, head, ["linked"], 1 << 20, tmp_path / "scope")
    assert record["absent"] == ["linked"], description
    assert not (tmp_path / "scope" / "linked").exists()


def test_a_file_over_the_size_limit_is_not_frozen(tmp_path):
    _, _, record = freeze(tmp_path, files={ALPHA: "x" * 100}, limit=50)
    assert record["absent"] == [ALPHA]


def test_a_file_exactly_at_the_size_limit_is_frozen(tmp_path):
    _, _, record = freeze(tmp_path, files={ALPHA: "x" * 50}, limit=50)
    assert record["absent"] == [] and record["inputs"][0]["size"] == 50


def test_the_export_is_the_frozen_bytes_and_is_read_only(tmp_path):
    _, _, record = freeze(tmp_path, files={ALPHA: "exact bytes\r\n\x00\x01"})
    exported = tmp_path / "scope" / ALPHA
    assert exported.read_bytes() == b"exact bytes\r\n\x00\x01"
    assert sha256_hex(exported.read_bytes()) == record["inputs"][0]["sha256"]
    assert not os.access(exported, os.W_OK) or os.name == "nt"


def test_the_export_holds_only_the_requested_scope(tmp_path):
    freeze(tmp_path, scope=[ALPHA])
    assert sorted(p.relative_to(tmp_path / "scope").as_posix() for p in (tmp_path / "scope").rglob("*") if p.is_file()) == [ALPHA]


def test_the_scope_directory_exists_even_when_nothing_was_frozen(tmp_path):
    """A bind mount of a missing directory fails, and that failure is not a verdict."""
    freeze(tmp_path, scope=["src/missing.py"])
    assert (tmp_path / "scope").is_dir()


@pytest.mark.parametrize("path", ["../out.py", "a/../../out.py", "/abs.py"])
def test_the_export_refuses_a_path_that_leaves_the_export_directory(tmp_path, path):
    with pytest.raises(publog.TargetError) as error:
        capture_module._export(tmp_path / "scope", path, b"x")
    assert error.value.code == "TARGET_EXPORT_ESCAPE"


# ==========================================================================
# the capture entry point
# ==========================================================================


def cli(tmp_path, *, environment=None, observation=None, source=True, manifest="", sha=None):
    repository = tmp_path / "private"
    head = make_candidate(repository)
    root = tmp_path / "runner"
    (root / "fetch").mkdir(parents=True)
    governance = root / "governance.json"
    governance.write_text(json.dumps(governed_observation() if observation is None else observation), encoding="utf-8")
    outputs = root / "outputs.txt"
    outputs.write_text("", encoding="utf-8")
    arguments = [
        "--policy", str(make_policy(tmp_path, floor=[ALPHA, BETA])),
        "--governance", str(governance),
        "--candidate", sha or head,
        "--inputs-manifest", manifest,
        "--workdir", str(root / "fetch"),
        "--scope-dir", str(root / "scope"),
        "--capture", str(root / "capture.json"),
    ]
    if source:
        arguments += ["--source", repository.as_uri()]
    env = good_environment(GITHUB_OUTPUT=str(outputs), ATLAS_DEPLOY_KEY=FAKE_KEY)
    env.update(environment or {})
    return run_entry("capture.py", *arguments, env=env), root, head, outputs


def test_capture_publishes_its_digest_as_a_step_output(tmp_path):
    process, root, _, outputs = cli(tmp_path)
    assert process.returncode == 0, process.stdout
    written = (root / "capture.json").read_bytes()
    assert f"capture_digest={hashlib.sha256(written).hexdigest()}" in outputs.read_text(encoding="utf-8")
    assert json.loads(written)["governance"]["rules_in_force"]


def test_capture_writes_only_the_private_freeze(tmp_path):
    _, root, _, _ = cli(tmp_path)
    assert sorted(p.name for p in root.iterdir() if p.is_file()) == ["capture.json", "governance.json", "outputs.txt"]


def test_capture_leaves_no_fetched_repository_behind(tmp_path):
    _, root, _, _ = cli(tmp_path)
    assert not (root / "fetch" / "repo").exists()
    assert not (root / "fetch" / "ssh").exists()


@pytest.mark.parametrize(
    "environment",
    [
        {"GITHUB_REF": "refs/heads/side"},
        {"GITHUB_ACTOR": "intruder"},
        {"GITHUB_EVENT_NAME": "pull_request"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
    ],
)
def test_capture_refuses_before_it_reads_anything_if_the_dispatch_is_wrong(tmp_path, environment):
    process, root, _, _ = cli(tmp_path, environment=environment)
    assert process.returncode == 2
    assert not (root / "capture.json").exists()
    assert not (root / "fetch" / "repo").exists()


def test_capture_refuses_when_governance_cannot_be_established(tmp_path):
    """No observation, no capture - the shape a removed protection takes from
    inside a run: everything else about the anchor is unchanged."""
    process, root, _, _ = cli(tmp_path, observation={})
    assert process.returncode == 2
    assert "CAPTURE_REFUSED" in process.stdout
    assert not (root / "capture.json").exists()


@pytest.mark.parametrize(
    "override",
    [
        {"observed_approvals": 0},
        {"repository_private": True},
        {"environment": {"name": "atlas-qualification", "deployment_branches": ["*"]}},
        {"status_check_contexts": []},
    ],
)
def test_capture_refuses_an_observation_that_does_not_establish_protection(tmp_path, override):
    process, root, _, _ = cli(tmp_path, observation=governed_observation(**override))
    assert process.returncode == 2 and not (root / "capture.json").exists()


def test_capture_refuses_a_tampered_observation(tmp_path):
    observation = governed_observation()
    observation["observed_approvals"] = 5
    process, root, _, _ = cli(tmp_path, observation=observation)
    assert process.returncode == 2 and not (root / "capture.json").exists()


def test_capture_without_a_deploy_key_refuses_the_real_target_without_trying_the_network(tmp_path):
    process, root, _, _ = cli(tmp_path, source=False, environment={"ATLAS_DEPLOY_KEY": ""})
    assert process.returncode == 2
    assert "CREDENTIAL_MISSING" in process.stdout
    assert not (root / "capture.json").exists()


def test_capture_refuses_a_candidate_that_is_not_in_the_repository(tmp_path):
    process, root, _, _ = cli(tmp_path, sha="d" * 40)
    assert process.returncode == 2
    assert "TARGET_FETCH_FAILED" in process.stdout


# ==========================================================================
# C1 regression: a candidate shipping its own judge ships inert files
# ==========================================================================


def test_c1_a_candidate_shipping_its_own_judge_is_inert(tmp_path):
    """The earlier design resolved its anchor inside a repository the caller
    supplied, so a candidate carrying the real launcher beside a three-line
    always-accept verifier was ACCEPTED with every control green. Here the judge is
    never looked up in the candidate: it is checked out from this repository."""
    files = {
        ALPHA: "A = 1\n",
        "anchor/verify.py": 'print("[VERIFY] ACCEPT")\nraise SystemExit(0)\n',
        "anchor/policy.json": '{"required_inputs_floor": []}',
        ".github/workflows/qualify.yml": "name: fake\n",
    }
    run = run_pipeline(tmp_path, files=files, floor=[ALPHA])
    assert run.verdict["verdict"] == "ACCEPT"
    exported = {p.relative_to(run.sandbox / "candidate").as_posix() for p in (run.sandbox / "candidate").rglob("*") if p.is_file()}
    assert exported == {ALPHA}, "the candidate's own judge was handed to the box"
    assert "def verify(" in (ANCHOR / "verify.py").read_text(encoding="utf-8")


def test_c1b_a_candidate_that_ships_a_judge_and_deletes_a_required_input_is_refused(tmp_path):
    run = run_pipeline(
        tmp_path, files={ALPHA: "A = 1\n", "anchor/verify.py": "raise SystemExit(0)\n"}, floor=[ALPHA, BETA]
    )
    assert run.verdict["verdict"] == "REFUSE"
    assert "INPUT_ABSENT" in run.verdict["reasons"]


# ==========================================================================
# the child: observes, and decides nothing
# ==========================================================================


def child_scope(tmp_path, files):
    root = tmp_path / "tree"
    for relative_path, body in files.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    return root


def test_the_child_never_says_either_verdict_word():
    source = (ANCHOR / "runner.py").read_text(encoding="utf-8")
    assert "ACCEPT" not in source
    assert "REFUSE" not in source


def test_the_child_holds_no_second_definition_of_scope():
    """One derivation of the required set, in the anchor's policy module."""
    source = (ANCHOR / "runner.py").read_text(encoding="utf-8")
    assert "def parse_manifest" not in source
    assert "anchor_policy.effective_scope" in source


def test_the_child_cannot_run_a_subprocess_or_open_a_socket():
    import ast

    names = set()
    for node in ast.walk(ast.parse((ANCHOR / "runner.py").read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    assert not names & {"subprocess", "socket", "urllib", "http", "ssl", "git", "requests", "shutil"}


def test_the_childs_blob_id_is_the_id_git_gives_the_same_bytes(tmp_path):
    for body in (b"", b"a", b"line\n", b"\x00\xff\r\n" * 100):
        root = tmp_path / str(len(body))
        root.mkdir()
        (root / "f").write_bytes(body)
        expected = subprocess.run(
            ["git", "hash-object", "--stdin"], input=body, capture_output=True, check=True
        ).stdout.decode().strip()
        assert runner_module.blob_id(body) == expected


def test_the_child_and_the_freeze_agree_about_every_input(tmp_path):
    root, sha, record = freeze(tmp_path, files={ALPHA: "A = 1\n", BETA: "B = 2\r\n"}, scope=[ALPHA, BETA])
    observed = runner_module.observe(tmp_path / "scope", sha, record["candidate_tree"], [ALPHA, BETA], 1 << 20)
    assert observed["inputs_observed"] == record["inputs"]
    assert observed["inputs_unreadable"] == []


def test_the_childs_evidence_is_a_document_the_verifier_accepts_the_shape_of(tmp_path):
    scope = child_scope(tmp_path, {ALPHA: b"A = 1\n"})
    document = runner_module.observe(scope, "a" * 40, "b" * 40, [ALPHA, BETA], 1 << 20)
    assert evidence_module.validate(document) == []
    assert runner_module.EVIDENCE_VERSION == evidence_module.EVIDENCE_VERSION


@pytest.mark.parametrize(
    "files, reason",
    [
        ({}, "ABSENT"),
        ({"src": b"a directory, not a file"}, "NOT_REGULAR"),
    ],
)
def test_the_child_reports_an_unreadable_input_with_a_fixed_word(tmp_path, files, reason):
    scope = child_scope(tmp_path, files)
    if "src" in files:
        (scope / "src").unlink()
        (scope / "src").mkdir()
    document = runner_module.observe(scope, "a" * 40, "b" * 40, [ALPHA], 1 << 20)
    assert document["inputs_unreadable"] == [{"relative_path": ALPHA, "reason": reason}] or (
        document["inputs_unreadable"][0]["reason"] in {"ABSENT", "NOT_REGULAR"}
    )


def test_the_child_refuses_a_file_over_the_size_limit(tmp_path):
    scope = child_scope(tmp_path, {ALPHA: b"x" * 100})
    document = runner_module.observe(scope, "a" * 40, "b" * 40, [ALPHA], 50)
    assert document["inputs_unreadable"] == [{"relative_path": ALPHA, "reason": "TOO_LARGE"}]
    assert document["inputs_observed"] == []


def test_the_child_refuses_a_symlink_even_to_a_regular_file(tmp_path):
    scope = child_scope(tmp_path, {"real.py": b"x = 1\n"})
    try:
        os.symlink(scope / "real.py", scope / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this host")
    document = runner_module.observe(scope, "a" * 40, "b" * 40, ["link.py"], 1 << 20)
    assert document["inputs_unreadable"] == [{"relative_path": "link.py", "reason": "NOT_REGULAR"}]


def test_the_child_refuses_a_path_through_a_symlinked_directory(tmp_path):
    scope = child_scope(tmp_path, {"real/inner.py": b"x = 1\n"})
    try:
        os.symlink(scope / "real", scope / "alias", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this host")
    document = runner_module.observe(scope, "a" * 40, "b" * 40, ["alias/inner.py"], 1 << 20)
    assert document["inputs_unreadable"][0]["reason"] == "NOT_REGULAR"


def child_args(tmp_path, scope, **extra):
    return [
        "--policy", str(make_policy(tmp_path, floor=[ALPHA])),
        "--root", str(scope),
        "--candidate", "a" * 40,
        "--tree", "b" * 40,
        "--evidence", str(tmp_path / "evidence" / "evidence.json"),
        "--inputs-manifest", extra.get("manifest", ""),
    ]


def test_the_child_writes_only_where_it_was_told(tmp_path):
    scope = child_scope(tmp_path, {ALPHA: b"A = 1\n"})
    (tmp_path / "evidence").mkdir()
    process = run_entry("runner.py", *child_args(tmp_path, scope), env=good_environment())
    assert process.returncode == 0, process.stdout + process.stderr
    assert sorted(p.name for p in (tmp_path / "evidence").iterdir()) == ["evidence.json"]


def test_the_child_will_not_overwrite_an_existing_evidence_file(tmp_path):
    scope = child_scope(tmp_path, {ALPHA: b"A = 1\n"})
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "evidence.json").write_text("planted", encoding="utf-8")
    process = run_entry("runner.py", *child_args(tmp_path, scope), env=good_environment())
    assert process.returncode != 0
    assert (tmp_path / "evidence" / "evidence.json").read_text(encoding="utf-8") == "planted"


def test_the_child_exits_non_zero_when_it_cannot_read_a_required_input(tmp_path):
    scope = child_scope(tmp_path, {})
    (tmp_path / "evidence").mkdir()
    process = run_entry("runner.py", *child_args(tmp_path, scope), env=good_environment())
    assert process.returncode == 4


def test_a_manifest_that_begins_with_a_dash_is_not_parsed_as_an_option(tmp_path):
    """The host passes `--inputs-manifest=<value>`, so a value shaped like a flag is a value."""
    scope = child_scope(tmp_path, {ALPHA: b"A = 1\n", "-rf": b"x\n"})
    (tmp_path / "evidence").mkdir()
    process = run_entry(
        "runner.py", *child_args(tmp_path, scope)[:-2], "--inputs-manifest=-rf", env=good_environment()
    )
    assert process.returncode == 0, process.stdout + process.stderr


def test_a_module_planted_beside_the_candidate_cannot_shadow_a_trusted_one(tmp_path):
    """C2 regression, executed. Isolated mode drops the working directory and the
    script directory from sys.path; the trusted directory is then named from the
    script's own resolved location, so a same-named file is never reached."""
    scope = child_scope(tmp_path, {ALPHA: b"A = 1\n"})
    (tmp_path / "evidence").mkdir()
    (tmp_path / "policy.py").write_text(
        "def assert_isolated():\n    pass\ndef load(path):\n    return {}\n"
        "def effective_scope(policy, manifest):\n    return []\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(ANCHOR / "runner.py"), *child_args(tmp_path, scope)],
        capture_output=True, text=True, cwd=str(tmp_path),
        env={**os.environ, **good_environment(), "PYTHONPATH": str(tmp_path)}, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    written = json.loads((tmp_path / "evidence" / "evidence.json").read_text(encoding="utf-8"))
    assert written["inputs_requested"] == [ALPHA], "the hostile policy module was used"


def test_the_child_refuses_an_unisolated_interpreter(tmp_path):
    scope = child_scope(tmp_path, {ALPHA: b"A = 1\n"})
    (tmp_path / "evidence").mkdir()
    completed = subprocess.run(
        [sys.executable, str(ANCHOR / "runner.py"), *child_args(tmp_path, scope)],
        capture_output=True, text=True, env={**os.environ, **good_environment()}, check=False,
    )
    assert completed.returncode != 0
    assert not (tmp_path / "evidence" / "evidence.json").exists()

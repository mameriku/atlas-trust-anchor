"""Does the candidate ever see a credential - and can it touch the judge?

The deploy key is read-only and scoped to the target, but "read-only access to your
private repository" is still not something a piece of code being examined should
have. The candidate must observe NONE of it, through any of the channels a process
has: its environment, files it can read, git configuration, credential helpers,
HOME, the runner's temp directory, SSH configuration, or the arguments it was
started with.

These tests use synthetic credentials and the recording stand-in for docker, so the
assertion is about what was ACTUALLY handed over, not about what the code intended
to hand over. `leak_everywhere` sets every secret in every step's environment, as a
workflow mistake would, to show the anchor's own boundaries hold even then.

The second half is the inverse question: can what the candidate does reach the
evaluator, the policy, the workflow, or the capture record? The stand-in models
mount semantics from the audited argument vector, so this fails if the anchor stops
asking for a read-only mount, drops one, or adds one.
"""

from __future__ import annotations

import json
import os
import shlex
import stat

import pytest

from support import (
    ANCHOR,
    FAKE_GITHUB_TOKEN,
    FAKE_GOVERNANCE_TOKEN,
    FAKE_KEY,
    HOST_KEY,
    ROOT,
    make_candidate,
    make_policy,
    sha256_hex,
    tree_bytes,
)

import policy as policy_module  # noqa: E402
import publog  # noqa: E402
import sandbox  # noqa: E402
import sandbox_spec  # noqa: E402
import target  # noqa: E402
from pipeline import run_pipeline  # noqa: E402

KEY_BODY = "SYNTHETIC-DEPLOY-KEY-c2ec4f8a91d34b7ea06f5d28"
SECRETS = [KEY_BODY, FAKE_GOVERNANCE_TOKEN, FAKE_GITHUB_TOKEN]
SECRET_NAMES = {
    "ATLAS_DEPLOY_KEY",
    "ANCHOR_GOVERNANCE_TOKEN",
    "GITHUB_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
}

DUMP_EVERYTHING = """
import os, json, sys
RESULTS["environment"] = dict(os.environ)
RESULTS["argv"] = sys.argv
RESULTS["home_exists"] = os.path.exists(os.path.expanduser("~/.ssh"))
tree = {}
for target in ("/candidate", "/child", "/evidence"):
    mount, host = host_path(target)
    for root, _, files in os.walk(host):
        for name in files:
            full = os.path.join(root, name)
            tree[target + full[len(host):].replace(os.sep, "/")] = open(full, "rb").read().decode("latin-1")
RESULTS["visible"] = tree
attempt_write("/evidence/evidence.json", b"{}")
finish()
"""


def _run_entry_report(run):
    """The detailed record of the container start (the fake logs each call twice)."""
    return next(entry for entry in run.report() if entry["kind"] == "run" and "mounts" in entry)


def _visible(run) -> dict:
    output = next(e for e in run.report() if e["kind"] == "child-output")["stdout"]
    return json.loads(output.split("FAKE_RESULTS ", 1)[1])


# --------------------------------------------------------------------------
# the candidate observes no credential
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def leaky_run(tmp_path_factory):
    """Every secret exported to every step, and a child that dumps all it can see."""
    return run_pipeline(
        tmp_path_factory.mktemp("leaky"),
        docker_config={"mode": "script", "script": DUMP_EVERYTHING},
        leak_everywhere=True,
    )


def test_the_docker_client_is_not_given_any_secret_variable(leaky_run):
    client = _run_entry_report(leaky_run)["client_environment"]
    assert not SECRET_NAMES & set(client), sorted(SECRET_NAMES & set(client))
    for secret in SECRETS:
        assert all(secret not in str(value) for value in client.values())


def test_nothing_the_container_was_started_with_contains_a_secret(leaky_run):
    """Process arguments, options, mounts, command: the whole `docker run` line."""
    entry = dict(_run_entry_report(leaky_run))
    entry.pop("client_environment")
    started = json.dumps(entry)
    for secret in SECRETS:
        assert secret not in started


def test_the_container_command_forwards_no_environment_at_all(leaky_run):
    entry = _run_entry_report(leaky_run)
    for forbidden in ("-e", "--env", "--env-file", "-v", "--volume", "--privileged", "--cap-add"):
        assert forbidden not in entry["argv"], forbidden
        assert forbidden not in entry["options"], forbidden


def test_the_child_environment_holds_a_path_and_nothing_else(leaky_run):
    seen = _visible(leaky_run)["environment"]
    # CPython itself adds LC_CTYPE at start-up on Linux when the locale is "C" (PEP 538).
    # The anchor never sets it, and the check on secret values below covers it too.
    assert set(seen) <= {"PATH", "SYSTEMROOT", "WINDIR", "FAKE_MOUNTS", "LC_CTYPE"}, sorted(seen)
    assert seen.get("LC_CTYPE", "C.UTF-8") in {"C.UTF-8", "C.utf8", "UTF-8"}, seen.get("LC_CTYPE")
    for secret in SECRETS:
        assert all(secret not in value for value in seen.values())


def test_no_file_the_child_can_read_contains_a_secret(leaky_run):
    visible = _visible(leaky_run)["visible"]
    assert visible, "the child could see nothing at all, so this proves nothing"
    for path, content in visible.items():
        for secret in SECRETS:
            assert secret not in content, f"{path} contains a secret"


def test_the_child_sees_no_git_configuration_no_ssh_and_no_credential_helper(leaky_run):
    visible = _visible(leaky_run)
    paths = list(visible["visible"])
    assert not [path for path in paths if "/.git" in path or path.endswith("/config")]
    assert not [path for path in paths if "ssh" in path.lower() or "known_hosts" in path]
    assert visible["home_exists"] is False
    joined = " ".join(visible["visible"].values()).lower()
    for word in ("credential.helper", "extraheader", "sshcommand", "begin openssh"):
        assert word not in joined


def test_the_container_is_given_three_mounts_all_under_the_sandbox_directory(leaky_run):
    mounts = _run_entry_report(leaky_run)["mounts"]
    assert sorted(mounts) == ["/candidate", "/child", "/evidence"]
    for container_path, mount in mounts.items():
        source = os.path.realpath(mount["source"])
        assert source.startswith(os.path.realpath(leaky_run.sandbox)), container_path
        for forbidden in (leaky_run.private, ROOT, ANCHOR, leaky_run.root):
            assert source != os.path.realpath(forbidden)
    assert mounts["/candidate"]["readonly"] and mounts["/child"]["readonly"]
    assert not mounts["/evidence"]["readonly"]


def test_the_candidate_directory_is_a_plain_tree_with_no_git_history(leaky_run):
    names = {path.name for path in (leaky_run.sandbox / "candidate").rglob("*")}
    assert ".git" not in names
    assert not any(name.endswith(".bundle") for name in names)


def test_the_run_still_worked_so_the_isolation_is_not_just_a_broken_run(leaky_run):
    assert leaky_run.steps["capture"].returncode == 0
    assert leaky_run.steps["sandbox"].returncode == 0


# --------------------------------------------------------------------------
# the key's life: written for one fetch, gone after
# --------------------------------------------------------------------------


def _policy(tmp_path):
    return policy_module.load(make_policy(tmp_path))


def _fetch(tmp_path, candidate=None, environ=None, source=None):
    repository = tmp_path / "source"
    sha = make_candidate(repository)
    workdir = tmp_path / "work"
    workdir.mkdir()
    environment = {"PATH": os.environ["PATH"], "ATLAS_DEPLOY_KEY": FAKE_KEY}
    environment.update(environ or {})
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return workdir, sha, lambda: target.fetch_candidate(
        _policy(tmp_path), environment, candidate or sha, workdir, source or repository.as_uri()
    )


def test_the_key_and_everything_it_touched_is_gone_after_a_successful_fetch(tmp_path):
    workdir, _, fetch = _fetch(tmp_path)
    fetch()
    assert not (workdir / "ssh").exists()
    for path, content in tree_bytes(workdir).items():
        assert KEY_BODY.encode() not in content, path


def test_the_key_and_everything_it_touched_is_gone_after_a_failed_fetch(tmp_path):
    workdir, _, fetch = _fetch(tmp_path, candidate="e" * 40)
    with pytest.raises(publog.TargetError):
        fetch()
    assert not (workdir / "ssh").exists()
    for path, content in tree_bytes(workdir).items():
        assert KEY_BODY.encode() not in content, path


def test_git_is_started_with_a_rebuilt_environment_holding_no_secret(tmp_path, monkeypatch):
    seen = []
    real = target.run_git

    def spy(environment, repository, *arguments, **keywords):
        seen.append((dict(environment), arguments))
        return real(environment, repository, *arguments, **keywords)

    monkeypatch.setattr(target, "run_git", spy)
    _, _, fetch = _fetch(
        tmp_path,
        environ={
            "GITHUB_TOKEN": FAKE_GITHUB_TOKEN,
            "ANCHOR_GOVERNANCE_TOKEN": FAKE_GOVERNANCE_TOKEN,
        },
    )
    fetch()
    assert seen
    for environment, _ in seen:
        assert not SECRET_NAMES & set(environment)
        for secret in SECRETS:
            assert all(secret not in value for value in environment.values())


def test_the_key_reaches_git_as_a_file_named_in_the_ssh_command_and_never_as_content(
    tmp_path, monkeypatch
):
    observed = {}
    real = target.run_git

    def spy(environment, repository, *arguments, **keywords):
        if "fetch" in arguments:
            command = environment.get("GIT_SSH_COMMAND", "")
            parts = shlex.split(command)
            path = parts[parts.index("-i") + 1] if "-i" in parts else None
            observed["command"] = command
            observed["file"] = bool(path) and os.path.exists(path)
            observed["content_in_command"] = KEY_BODY in command
            if path and os.path.exists(path) and hasattr(os, "getuid"):
                observed["mode"] = stat.S_IMODE(os.stat(path).st_mode)
        return real(environment, repository, *arguments, **keywords)

    monkeypatch.setattr(target, "run_git", spy)
    _, _, fetch = _fetch(tmp_path)
    fetch()
    assert observed["file"] is True
    assert observed["content_in_command"] is False
    assert observed.get("mode", 0o600) == 0o600


def test_the_server_is_authenticated_against_the_pinned_host_key(tmp_path, monkeypatch):
    observed = {}
    real = target.run_git

    def spy(environment, repository, *arguments, **keywords):
        if "fetch" in arguments:
            command = environment["GIT_SSH_COMMAND"]
            observed["command"] = command
            known = next(
                part.split("=", 1)[1]
                for part in shlex.split(command)
                if part.startswith("UserKnownHostsFile=")
            )
            observed["known_hosts"] = open(known, encoding="utf-8").read()
        return real(environment, repository, *arguments, **keywords)

    monkeypatch.setattr(target, "run_git", spy)
    _, _, fetch = _fetch(tmp_path)
    fetch()
    assert observed["known_hosts"] == f"github.com {HOST_KEY}\n"
    for option in (
        "StrictHostKeyChecking=yes",
        "HostKeyAlgorithms=ssh-ed25519",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "BatchMode=yes",
        "ForwardAgent=no",
        "PasswordAuthentication=no",
    ):
        assert option in observed["command"], option


def test_the_fetched_repository_keeps_no_remote_and_no_credential(tmp_path):
    workdir, _, fetch = _fetch(tmp_path)
    repository = fetch()
    config = (repository / ".git" / "config").read_text(encoding="utf-8")
    for word in ("url", "sshcommand", "credential", "extraheader", "OPENSSH"):
        assert word.lower() not in config.lower()


@pytest.mark.parametrize(
    "line",
    [
        "[remote \"origin\"]\n\turl = git@github.com:x/y.git\n",
        "[core]\n\tsshCommand = ssh -i /tmp/key\n",
        "[credential]\n\thelper = store\n",
        "[http]\n\textraheader = AUTHORIZATION: bearer x\n",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    ],
)
def test_a_repository_config_that_could_authenticate_later_is_refused(tmp_path, line):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(line, encoding="utf-8")
    with pytest.raises(publog.TargetError) as error:
        target.audit_repository_config(tmp_path)
    assert error.value.code == "CREDENTIAL_PERSISTED"


@pytest.mark.parametrize(
    "key, code",
    [
        (None, "CREDENTIAL_MISSING"),
        ("", "CREDENTIAL_MISSING"),
        ("   \n", "CREDENTIAL_MISSING"),
        ("not a key at all", "CREDENTIAL_MALFORMED"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "CREDENTIAL_MALFORMED"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 9000 + "\n-----END OPENSSH PRIVATE KEY-----", "CREDENTIAL_MALFORMED"),
    ],
)
def test_a_missing_or_malformed_key_is_refused_without_echoing_it(tmp_path, key, code):
    workdir = tmp_path / "work"
    workdir.mkdir()
    environment = {"PATH": os.environ["PATH"]}
    if key is not None:
        environment["ATLAS_DEPLOY_KEY"] = key
    with pytest.raises(publog.TargetError) as error:
        target.fetch_candidate(
            _policy(tmp_path), environment, "a" * 40, workdir, "git@github.com:mameriku/atlas.git"
        )
    assert error.value.code == code
    if key and key.strip():
        assert key.strip() not in str(error.value)
        assert "SYNTHETIC" not in str(error.value)


@pytest.mark.parametrize(
    "source",
    ["https://github.com/mameriku/atlas.git", "git@github.com:someone/else.git", "ssh://evil/x", "/local/path"],
)
def test_a_source_that_is_not_the_target_is_refused(tmp_path, source):
    with pytest.raises(publog.TargetError) as error:
        target.assert_source(_policy(tmp_path), source)
    assert error.value.code == "TARGET_SOURCE_REFUSED"


def test_the_docker_client_environment_is_an_allow_list():
    parent = {name: "x" for name in SECRET_NAMES} | {"PATH": "/bin", "HOME": "/home/r", "EDITOR": "vi"}
    client = sandbox.client_environment(parent)
    assert set(client) == {"PATH", "HOME"}


def test_the_git_environment_names_no_variable_it_was_not_given_a_reason_for():
    environment = target.git_environment(
        __import__("pathlib").Path("/h"), {"PATH": "/bin", **{name: "x" for name in SECRET_NAMES}}
    )
    assert not SECRET_NAMES & set(environment)
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"


# --------------------------------------------------------------------------
# the candidate cannot reach the judge
# --------------------------------------------------------------------------

def _tamper_script(root) -> str:
    private = root / "anchor-private"
    public = root / "public"
    targets = [
        "/candidate/scripts/one.py",
        "/candidate/new-file.py",
        "/child/runner.py",
        "/child/policy.json",
        "/child/policy.py",
        "/evidence/allowed.json",
        str(ANCHOR / "verify.py"),
        str(ANCHOR / "policy.json"),
        str(ROOT / ".github" / "workflows" / "qualify.yml"),
        str(private / "capture.json"),
        str(private / "sandbox.json"),
        str(private / "governance.json"),
        str(public / "verdict.json"),
        "/anchor/anchor/verify.py",
        "/capture/capture.json",
    ]
    return "import json\nfor path in " + repr(targets) + ":\n    attempt_write(path, b'tampered')\nfinish()\n"


@pytest.fixture(scope="module")
def tamper_run(tmp_path_factory):
    base = tmp_path_factory.mktemp("tamper")
    # run_pipeline lays the runner out under <tmp>/runner, so the script can name
    # the real host paths of the capture record and the verdict before they exist.
    script = _tamper_script(base / "runner")
    return run_pipeline(base, docker_config={"mode": "script", "script": script})


def _tamper_outcomes(run) -> dict:
    output = next(e for e in run.report() if e["kind"] == "child-output")["stdout"]
    return json.loads(output.split("FAKE_RESULTS ", 1)[1])


def test_only_the_evidence_directory_is_writable_from_inside_the_box(tamper_run):
    outcomes = _tamper_outcomes(tamper_run)
    written = [path for path, result in outcomes.items() if result == "written"]
    assert written == ["/evidence/allowed.json"], outcomes


def test_the_read_only_mounts_and_unmounted_paths_are_refused_for_different_reasons(tamper_run):
    outcomes = _tamper_outcomes(tamper_run)
    assert outcomes["/candidate/scripts/one.py"] == "denied:read-only"
    assert outcomes["/child/runner.py"] == "denied:read-only"
    assert outcomes["/child/policy.json"] == "denied:read-only"
    assert outcomes["/anchor/anchor/verify.py"] == "denied:not-mounted"
    assert outcomes["/capture/capture.json"] == "denied:not-mounted"


def test_the_evaluator_the_policy_and_the_workflow_are_byte_for_byte_unchanged(tamper_run):
    for path in (ANCHOR / "verify.py", ANCHOR / "policy.json", ANCHOR / "policy.py", ANCHOR / "sandbox.py"):
        assert b"tampered" not in path.read_bytes(), path
    assert b"tampered" not in (ROOT / ".github" / "workflows" / "qualify.yml").read_bytes()


def test_the_capture_record_and_verdict_inputs_are_unchanged_and_still_bind(tamper_run):
    for name in ("capture.json", "sandbox.json", "governance.json"):
        assert b"tampered" not in (tamper_run.private / name).read_bytes(), name
    capture = (tamper_run.private / "capture.json").read_bytes()
    assert sha256_hex(capture) == tamper_run.output("capture_digest")


def test_a_run_that_tried_to_tamper_is_refused_for_leaving_no_evidence(tamper_run):
    verdict = tamper_run.verdict
    assert verdict["verdict"] == "REFUSE"
    assert any(reason.startswith("EVIDENCE_") for reason in verdict["reasons"])


def test_dropping_the_read_only_flag_from_a_mount_is_caught_by_the_audit(tmp_path):
    """The stand-in models mounts from the vector; the audit reads the same vector."""
    document = json.loads(make_policy(tmp_path).read_text(encoding="utf-8"))
    layout = sandbox_spec.Layout(tmp_path / "c", tmp_path / "k", tmp_path / "e")
    argv = sandbox_spec.build_argv(
        document, docker=["docker"], name="n", uid=1001, gid=65534, layout=layout,
        candidate="a" * 40, tree="b" * 40, manifest="",
    )
    weakened = [token.replace(",readonly", "") for token in argv]
    problems = sandbox_spec.audit_argv(weakened, document, layout.as_record())
    assert "SANDBOX_MOUNT_WRITABLE" in problems

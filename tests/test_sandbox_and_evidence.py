"""The box, and what comes back out of it.

Two halves of one boundary. The box is audited from its command line, by code that
shares nothing with the code that builds it: every required property is checked, and
any option the audit does not recognise is a refusal, so `--privileged` is refused by
not being on a list rather than by being on a blacklist. What comes back is hostile
bytes in a hostile directory, reduced to fixed codes before anyone can quote them.

Nothing here claims proof about Docker or the kernel. Escape from the runtime is an
infrastructure trust assumption. What is proven is that the anchor asks for every
property, notices when one goes missing, and never believes the child about anything.
"""

from __future__ import annotations

import json
import os
import random
import sys

import pytest

from support import (
    FAKE_DOCKER,
    IMAGE,
    IMAGE_ID,
    SHA_A,
    good_environment,
    make_policy,
    policy_document,
    run_entry,
)

import evidence as evidence_module  # noqa: E402
import policy as policy_module  # noqa: E402
import publog  # noqa: E402
import sandbox  # noqa: E402
import sandbox_spec  # noqa: E402
from policy import PolicyError  # noqa: E402

POLICY = policy_document()
BOX = POLICY["sandbox"]


def layout(tmp_path):
    for name in ("candidate", "child", "evidence"):
        (tmp_path / name).mkdir(exist_ok=True)
    return sandbox_spec.Layout(tmp_path / "candidate", tmp_path / "child", tmp_path / "evidence")


def good_argv(tmp_path, **overrides):
    parameters = dict(
        docker=["docker"], name="atlas-anchor-1-1", uid=1001, gid=65534, layout=layout(tmp_path),
        candidate=SHA_A, tree="b" * 40, manifest="",
    )
    parameters.update(overrides)
    return sandbox_spec.build_argv(POLICY, **parameters)


def audit(argv, tmp_path):
    return sandbox_spec.audit_argv(argv, POLICY, layout(tmp_path).as_record())


def replace(argv, old, new):
    return [new if token == old else token for token in argv]


def remove_pair(argv, option):
    index = argv.index(option)
    return argv[:index] + argv[index + 2 :]


def remove_flag(argv, flag):
    return [token for token in argv if token != flag]


def set_value(argv, option, value, occurrence=0):
    seen = -1
    for index, token in enumerate(argv):
        if token == option:
            seen += 1
            if seen == occurrence:
                return argv[: index + 1] + [value] + argv[index + 2 :]
    raise AssertionError(option)


# ==========================================================================
# the argument vector
# ==========================================================================


def test_the_box_the_builder_writes_passes_its_own_audit(tmp_path):
    assert audit(good_argv(tmp_path), tmp_path) == []


def test_the_command_starts_with_the_flags_that_make_it_a_box(tmp_path):
    argv = good_argv(tmp_path)
    for flag in ("--rm", "--read-only"):
        assert flag in argv
    for pair in (
        ("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
        ("--pull", "never"), ("--ipc", "none"), ("--log-driver", "none"),
    ):
        assert argv[argv.index(pair[0]) + 1] == pair[1]


def test_the_limits_come_from_policy_not_from_the_builder(tmp_path):
    argv = good_argv(tmp_path)
    assert argv[argv.index("--pids-limit") + 1] == str(BOX["pids_limit"])
    assert argv[argv.index("--memory") + 1] == f"{BOX['memory_mb']}m"
    assert argv[argv.index("--memory-swap") + 1] == f"{BOX['memory_mb']}m"
    assert f"fsize={BOX['max_file_bytes']}" in argv


def test_the_image_is_the_pinned_digest_and_nothing_else(tmp_path):
    argv = good_argv(tmp_path)
    assert argv[argv.index(IMAGE)] == IMAGE
    assert "@sha256:" in IMAGE


def test_the_manifest_is_one_argument_even_if_it_looks_like_a_flag(tmp_path):
    argv = good_argv(tmp_path, manifest="-rf\n--privileged")
    assert argv[-1] == "--inputs-manifest=-rf\n--privileged"
    assert audit(argv, tmp_path) == []


def test_a_directory_path_with_a_comma_cannot_smuggle_a_mount_option(tmp_path):
    bad = sandbox_spec.Layout(tmp_path / "a,b", tmp_path / "c", tmp_path / "d")
    with pytest.raises(PolicyError, match="ends a mount field"):
        sandbox_spec.build_argv(
            POLICY, docker=["docker"], name="n", uid=1, gid=1, layout=bad,
            candidate=SHA_A, tree="b" * 40, manifest="",
        )


MUTATIONS = {
    "network on the default bridge": (lambda a: remove_pair(a, "--network"), "SANDBOX_NETWORK"),
    "network host": (lambda a: set_value(a, "--network", "host"), "SANDBOX_NETWORK"),
    "network bridge": (lambda a: set_value(a, "--network", "bridge"), "SANDBOX_NETWORK"),
    "ipc host": (lambda a: set_value(a, "--ipc", "host"), "SANDBOX_IPC"),
    "ipc missing": (lambda a: remove_pair(a, "--ipc"), "SANDBOX_IPC"),
    "pull always": (lambda a: set_value(a, "--pull", "always"), "SANDBOX_PULL"),
    "pull missing": (lambda a: remove_pair(a, "--pull"), "SANDBOX_PULL"),
    "root user": (lambda a: set_value(a, "--user", "0:0"), "SANDBOX_USER"),
    "root uid": (lambda a: set_value(a, "--user", "0:1001"), "SANDBOX_USER"),
    "root gid": (lambda a: set_value(a, "--user", "1001:0"), "SANDBOX_USER"),
    "named user": (lambda a: set_value(a, "--user", "root"), "SANDBOX_USER"),
    "no user": (lambda a: remove_pair(a, "--user"), "SANDBOX_USER"),
    "writable root filesystem": (lambda a: remove_flag(a, "--read-only"), "SANDBOX_WRITABLE_ROOT"),
    "container survives": (lambda a: remove_flag(a, "--rm"), "SANDBOX_NOT_EPHEMERAL"),
    "capabilities kept": (lambda a: remove_pair(a, "--cap-drop"), "SANDBOX_CAPABILITIES"),
    "one capability dropped": (lambda a: set_value(a, "--cap-drop", "NET_RAW"), "SANDBOX_CAPABILITIES"),
    "privilege escalation allowed": (lambda a: remove_pair(a, "--security-opt"), "SANDBOX_SECURITY_OPT"),
    "seccomp unconfined": (
        lambda a: a[:2] + ["--security-opt", "seccomp=unconfined"] + a[2:], "SANDBOX_SECURITY_OPT",
    ),
    "no pid limit": (lambda a: remove_pair(a, "--pids-limit"), "SANDBOX_PIDS"),
    "larger pid limit": (lambda a: set_value(a, "--pids-limit", "100000"), "SANDBOX_PIDS"),
    "no memory limit": (lambda a: remove_pair(a, "--memory"), "SANDBOX_MEMORY"),
    "swap allowed": (lambda a: set_value(a, "--memory-swap", "9999m"), "SANDBOX_MEMORY"),
    "more memory": (lambda a: set_value(a, "--memory", "9999m"), "SANDBOX_MEMORY"),
    "no cpu limit": (lambda a: remove_pair(a, "--cpus"), "SANDBOX_CPUS"),
    "more cpu": (lambda a: set_value(a, "--cpus", "64"), "SANDBOX_CPUS"),
    "file size limit raised": (lambda a: set_value(a, "--ulimit", "fsize=999999999", 0), "SANDBOX_FILE_SIZE"),
    "container logs kept": (lambda a: set_value(a, "--log-driver", "json-file"), "SANDBOX_LOG_DRIVER"),
    "tmp may execute": (
        lambda a: [t.replace("noexec", "exec") for t in a], "SANDBOX_TMPFS",
    ),
    "no tmpfs": (lambda a: remove_pair(a, "--tmpfs"), "SANDBOX_TMPFS"),
    "different entrypoint": (lambda a: set_value(a, "--entrypoint", "sh"), "SANDBOX_ENTRYPOINT"),
    "no entrypoint": (lambda a: remove_pair(a, "--entrypoint"), "SANDBOX_ENTRYPOINT"),
    "a tag instead of the digest": (lambda a: replace(a, IMAGE, "python:3.12-slim"), "SANDBOX_IMAGE"),
    "another digest": (lambda a: replace(a, IMAGE, IMAGE[:-4] + "ffff"), "SANDBOX_IMAGE"),
    "interpreter flags removed": (lambda a: remove_flag(a, "-I"), "SANDBOX_COMMAND"),
    "another script": (
        lambda a: replace(a, "/child/runner.py", "/candidate/scripts/one.py"), "SANDBOX_COMMAND",
    ),
    "docker socket among the client's options": (
        lambda a: a[: a.index(IMAGE)] + ["--label", "/var/run/docker.sock"] + a[a.index(IMAGE) :],
        "SANDBOX_DOCKER_SOCKET",
    ),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_every_required_property_is_audited_and_its_removal_is_named(tmp_path, name):
    mutate, code = MUTATIONS[name]
    assert code in audit(mutate(good_argv(tmp_path)), tmp_path), name


UNKNOWN = [
    "--privileged", "--cap-add", "--device", "--pid", "--uts", "--userns", "--env", "-e", "-v",
    "--volume", "--env-file", "--group-add", "--add-host", "--net=host", "--network=host",
    "--security-opt=seccomp=unconfined", "--sysctl", "--gpus", "--runtime", "--cgroup-parent",
    "--oom-kill-disable", "--init", "--detach", "-d", "-t", "-i", "--tty", "--mount-propagation",
    "--publish", "-p", "--link", "--dns", "--shm-size", "--stop-timeout", "--label", "--restart",
]


@pytest.mark.parametrize("option", UNKNOWN)
def test_an_option_the_audit_does_not_know_is_refused_rather_than_ignored(tmp_path, option):
    argv = good_argv(tmp_path)
    injected = argv[:2] + [option] + argv[2:]
    assert "SANDBOX_UNKNOWN_OPTION" in audit(injected, tmp_path)


@pytest.mark.parametrize(
    "mount, code",
    [
        ("type=bind,source=/,target=/host", "SANDBOX_MOUNT_TARGETS"),
        ("type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock", "SANDBOX_MOUNT_TARGETS"),
        ("type=volume,source=x,target=/data", "SANDBOX_MOUNT_TARGETS"),
    ],
)
def test_a_fourth_mount_is_refused(tmp_path, mount, code):
    argv = good_argv(tmp_path)
    assert code in audit(argv[:2] + ["--mount", mount] + argv[2:], tmp_path)


def test_a_mount_pointing_at_the_wrong_host_directory_is_refused(tmp_path):
    argv = good_argv(tmp_path)
    tampered = [t.replace(f"source={tmp_path / 'child'}", f"source={tmp_path}") for t in argv]
    assert "SANDBOX_MOUNT_SOURCE" in audit(tampered, tmp_path)


@pytest.mark.parametrize("role", ["candidate", "child"])
def test_a_writable_candidate_or_child_mount_is_refused(tmp_path, role):
    argv = good_argv(tmp_path)
    tampered = [t.replace(f"target=/{role},readonly", f"target=/{role}") for t in argv]
    assert "SANDBOX_MOUNT_WRITABLE" in audit(tampered, tmp_path)


def test_a_read_only_evidence_mount_is_refused_because_the_box_could_then_report_nothing(tmp_path):
    argv = good_argv(tmp_path)
    tampered = [t + ",readonly" if t.endswith("target=/evidence") else t for t in argv]
    assert "SANDBOX_MOUNT_MALFORMED" in audit(tampered, tmp_path)


def test_a_mount_carrying_an_extra_option_is_refused(tmp_path):
    argv = good_argv(tmp_path)
    tampered = [t + ",bind-propagation=rshared" if t.endswith("target=/candidate,readonly") else t for t in argv]
    assert "SANDBOX_MOUNT_MALFORMED" in audit(tampered, tmp_path)


def test_a_command_that_is_not_a_docker_run_is_refused(tmp_path):
    assert "SANDBOX_NOT_A_RUN" in sandbox_spec.audit_argv(["docker", "ps"], POLICY, {})


def test_a_command_with_no_image_is_refused(tmp_path):
    assert "SANDBOX_NO_IMAGE" in sandbox_spec.audit_argv(["docker", "run", "--rm"], POLICY, {})


# ==========================================================================
# the record of a run
# ==========================================================================


def good_record(tmp_path, **overrides):
    the_layout = layout(tmp_path)
    record = {
        "sandbox_version": sandbox_spec.SANDBOX_VERSION,
        "image": IMAGE,
        "image_id": IMAGE_ID,
        "params": {"name": "n", "uid": 1001, "gid": 65534, "candidate": SHA_A, "tree": "b" * 40},
        "layout": the_layout.as_record(),
        "argv": good_argv(tmp_path),
        "pull_ok": True,
        "started": True,
        "exit_code": 0,
        "timed_out": False,
        "output_exceeded": False,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    record.update(overrides)
    return record


def test_a_clean_hardened_run_is_acceptable(tmp_path):
    assert sandbox_spec.acceptable(good_record(tmp_path), POLICY) == []


@pytest.mark.parametrize(
    "override, code",
    [
        ({"pull_ok": False}, "SANDBOX_IMAGE_UNAVAILABLE"),
        ({"image_id": None}, "SANDBOX_IMAGE_UNAVAILABLE"),
        ({"image_id": "sha256:short"}, "SANDBOX_IMAGE_UNAVAILABLE"),
        ({"image": "python:latest"}, "SANDBOX_IMAGE"),
        ({"started": False}, "SANDBOX_NOT_STARTED"),
        ({"timed_out": True}, "SANDBOX_TIMEOUT"),
        ({"output_exceeded": True}, "SANDBOX_OUTPUT_LIMIT"),
        ({"exit_code": 1}, "SANDBOX_EXIT_NONZERO"),
        ({"exit_code": None}, "SANDBOX_EXIT_NONZERO"),
        ({"exit_code": "0"}, "SANDBOX_EXIT_NONZERO"),
        ({"exit_code": False}, "SANDBOX_EXIT_NONZERO"),
        ({"timed_out": None}, "SANDBOX_TIMEOUT"),
        ({"sandbox_version": "other"}, "SANDBOX_RECORD_INVALID"),
        ({"argv": "docker run"}, "SANDBOX_RECORD_INVALID"),
        ({"argv": [1, 2]}, "SANDBOX_RECORD_INVALID"),
        ({"layout": None}, "SANDBOX_RECORD_INVALID"),
    ],
)
def test_a_run_that_is_not_a_clean_hardened_one_is_refused_with_a_fixed_code(tmp_path, override, code):
    assert code in sandbox_spec.acceptable(good_record(tmp_path, **override), POLICY)


@pytest.mark.parametrize("record", [None, [], "text", 7, {}])
def test_no_usable_record_is_a_refusal(record):
    assert sandbox_spec.acceptable(record, POLICY) == ["SANDBOX_RECORD_INVALID"]


def test_a_record_whose_argv_was_weakened_after_the_run_is_refused(tmp_path):
    weakened = remove_pair(good_argv(tmp_path), "--network")
    assert "SANDBOX_NETWORK" in sandbox_spec.acceptable(good_record(tmp_path, argv=weakened), POLICY)


# ==========================================================================
# running it: bounds, not trust
# ==========================================================================


def scrubbed():
    """A minimal environment a Python child can still start under on any host."""
    return {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "WINDIR") if name in os.environ}


def run_python(code, timeout=10, cap=1000):
    return sandbox.execute([sys.executable, "-c", code], scrubbed(), timeout=timeout, cap=cap)


def test_output_is_counted_and_discarded_not_kept():
    result = run_python("import sys; sys.stdout.write('x' * 500); sys.stderr.write('y' * 300)")
    assert (result.stdout_bytes, result.stderr_bytes) == (500, 300)
    assert result.stdout == b"" and not result.output_exceeded


def test_a_command_that_talks_too_much_is_stopped():
    result = run_python("import sys\nwhile True:\n    sys.stdout.write('x' * 4096); sys.stdout.flush()", cap=8192)
    assert result.output_exceeded


def test_a_command_that_never_finishes_is_killed():
    result = run_python("import time; time.sleep(60)", timeout=1)
    assert result.timed_out


def test_a_command_that_cannot_be_started_is_a_result_not_a_crash():
    result = sandbox.execute(["definitely-not-a-real-binary-xyz"], {}, timeout=5, cap=100)
    assert result.returncode is None


def test_kept_output_is_still_bounded():
    result = sandbox.execute(
        [sys.executable, "-c", "print('z' * 100000)"], scrubbed(),
        timeout=10, cap=100, keep_stdout=True,
    )
    assert len(result.stdout) <= 100


def run_with_fake(tmp_path, config=None, uid=1001, gid=65534):
    the_layout = layout(tmp_path)
    report = tmp_path / "report.jsonl"
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({**(config or {}), "report": str(report)}), encoding="utf-8")
    record = sandbox.run_sandbox(
        POLICY, the_layout, parent_environment=scrubbed(),
        candidate=SHA_A, tree="b" * 40, manifest="", uid=uid, gid=gid, name="atlas-anchor-9-1",
        docker=[sys.executable, str(FAKE_DOCKER), "--config", str(config_path)],
    )
    entries = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()] if report.exists() else []
    return record, entries


def test_a_run_that_pulls_and_starts_records_the_image_identity(tmp_path):
    record, _ = run_with_fake(tmp_path, {"mode": "script", "script": "finish()\n"})
    assert record["pull_ok"] and record["image_id"] == IMAGE_ID and record["started"]


def test_a_failed_pull_never_starts_the_container(tmp_path):
    record, entries = run_with_fake(tmp_path, {"pull_fails": True})
    assert record["pull_ok"] is False and record["started"] is False
    assert not [e for e in entries if e["kind"] == "run"]


def test_root_is_refused_before_anything_is_pulled_or_started(tmp_path):
    record, entries = run_with_fake(tmp_path, uid=0)
    assert record["started"] is False and entries == []


@pytest.mark.parametrize("config", [{"mode": "script", "script": "import sys; sys.exit(3)\n"}, {"mode": "hang"}])
def test_the_container_is_removed_however_the_run_ended(tmp_path, config):
    if config.get("mode") == "hang":
        policy = json.loads(json.dumps(POLICY))
        policy["sandbox"]["timeout_seconds"] = 1
    else:
        policy = POLICY
    the_layout = layout(tmp_path)
    report = tmp_path / "report.jsonl"
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({**config, "report": str(report)}), encoding="utf-8")
    sandbox.run_sandbox(
        policy, the_layout, parent_environment=scrubbed(), candidate=SHA_A,
        tree="b" * 40, manifest="", uid=1001, gid=65534, name="atlas-anchor-9-1",
        docker=[sys.executable, str(FAKE_DOCKER), "--config", str(config_path)],
    )
    kinds = [json.loads(line)["argv"][:3] for line in report.read_text(encoding="utf-8").splitlines() if '"kind": "rm"' in line]
    assert kinds and kinds[-1] == ["rm", "--force", "atlas-anchor-9-1"]


def test_the_run_uses_exactly_the_audited_command(tmp_path):
    record, entries = run_with_fake(tmp_path, {"mode": "script", "script": "finish()\n"})
    started = next(e for e in entries if e["kind"] == "run" and "mounts" in e)
    assert started["argv"] == record["argv"][record["argv"].index("run") + 1 :]
    prefix = record["argv"][: record["argv"].index("run")]
    assert sandbox_spec.acceptable(record, POLICY, prefix, SHA_A, "b" * 40) == []
    # ... and it is not the run the verifier expects unless it is told the client is
    # the fake: a real verifier expects exactly `docker` before `run`.
    assert "SANDBOX_DOCKER_PREFIX" in sandbox_spec.acceptable(record, POLICY)


def sandbox_arguments(tmp_path, **overrides):
    (tmp_path / "scope").mkdir(exist_ok=True)
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps({"candidate_tree": "b" * 40}), encoding="utf-8")
    arguments = {
        "--policy": str(make_policy(tmp_path)), "--anchor-code": str(tmp_path / "code"),
        "--capture": str(capture), "--candidate": SHA_A, "--inputs-manifest": "",
        "--scope-dir": str(tmp_path / "scope"), "--child-dir": str(tmp_path / "child"),
        "--evidence-dir": str(tmp_path / "evidence"), "--record": str(tmp_path / "record.json"),
        "--name": "atlas-anchor-1-1", "--docker-command": json.dumps([sys.executable, str(FAKE_DOCKER)]),
        "--uid": "1001", "--gid": "1001",
    }
    arguments.update(overrides)
    (tmp_path / "code").mkdir(exist_ok=True)
    for name in ("policy.py", "runner.py"):
        (tmp_path / "code" / name).write_text("", encoding="utf-8")
    return [item for pair in arguments.items() for item in pair]


@pytest.mark.parametrize(
    "override",
    [
        {"--docker-command": "not json"},
        {"--docker-command": "[]"},
        {"--docker-command": '["docker", 7]'},
        {"--docker-command": '"docker"'},
        {"--name": "bad name; rm -rf"},
        {"--name": ""},
        {"--name": "a" * 65},
        {"--candidate": "abc"},
    ],
)
def test_the_sandbox_entry_point_refuses_malformed_input_without_starting_anything(tmp_path, override):
    process = run_entry("sandbox.py", *sandbox_arguments(tmp_path, **override), env=good_environment())
    assert process.returncode == 2
    assert not (tmp_path / "record.json").exists()


def test_the_child_is_staged_with_this_runs_policy_and_only_three_files(tmp_path):
    (tmp_path / "code").mkdir()
    for name in ("policy.py", "runner.py", "verify.py", "capture.py"):
        (tmp_path / "code" / name).write_text(name, encoding="utf-8")
    policy_path = make_policy(tmp_path)
    sandbox.stage_child(tmp_path / "code", tmp_path / "child", policy_path)
    assert sorted(p.name for p in (tmp_path / "child").iterdir()) == ["policy.json", "policy.py", "runner.py"]
    assert (tmp_path / "child" / "policy.json").read_bytes() == policy_path.read_bytes()


# ==========================================================================
# the evidence directory: every byte is a claim
# ==========================================================================


def good_evidence(**overrides):
    document = {
        "evidence_version": evidence_module.EVIDENCE_VERSION,
        "candidate_sha": SHA_A,
        "candidate_tree": "b" * 40,
        "inputs_requested": ["a.py"],
        "inputs_observed": [{"relative_path": "a.py", "blob": "c" * 40, "sha256": "d" * 64, "size": 3}],
        "inputs_unreadable": [],
    }
    document.update(overrides)
    return document


def place(tmp_path, payload, name="evidence.json"):
    directory = tmp_path / "ev"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
    return directory


def read(directory, limit=65536):
    return evidence_module.read_directory(directory, limit)


def test_a_well_formed_document_is_read_with_its_digest(tmp_path):
    result = read(place(tmp_path, good_evidence()))
    assert result.evidence == good_evidence() and result.problems == () and len(result.digest) == 64


def test_a_missing_directory_is_a_refusal(tmp_path):
    assert read(tmp_path / "absent").problems == ("EVIDENCE_MISSING",)


def test_a_directory_that_is_a_file_is_a_refusal(tmp_path):
    (tmp_path / "ev").write_text("x", encoding="utf-8")
    assert read(tmp_path / "ev").problems == ("EVIDENCE_NOT_DIRECTORY",)


def test_an_empty_directory_is_a_refusal_not_an_absence_of_problems(tmp_path):
    (tmp_path / "ev").mkdir()
    assert read(tmp_path / "ev").problems == ("EVIDENCE_MISSING",)


def test_an_extra_file_makes_the_whole_directory_a_refusal(tmp_path):
    directory = place(tmp_path, good_evidence())
    (directory / "notes.txt").write_text("hi", encoding="utf-8")
    result = read(directory)
    assert result.evidence is None and "EVIDENCE_UNEXPECTED_FILE" in result.problems


def test_a_differently_named_evidence_file_is_not_evidence(tmp_path):
    result = read(place(tmp_path, good_evidence(), name="evidence.JSON.bak"))
    assert result.evidence is None and "EVIDENCE_UNEXPECTED_FILE" in result.problems


@pytest.mark.parametrize("name", ["../evidence.json", "a/evidence.json", "..", "evidence.json "])
def test_a_traversal_shaped_name_is_never_read_as_evidence(tmp_path, name):
    directory = tmp_path / "ev"
    directory.mkdir()
    try:
        (directory / name).write_bytes(json.dumps(good_evidence()).encode())
    except (OSError, ValueError):
        pytest.skip("the host cannot create this name")
    result = read(directory)
    if result.evidence is not None:
        assert (directory / "evidence.json").exists(), "read a file that is not evidence.json"


def test_a_subdirectory_named_like_the_evidence_file_is_refused(tmp_path):
    directory = tmp_path / "ev"
    (directory / "evidence.json").mkdir(parents=True)
    assert "EVIDENCE_NOT_REGULAR" in read(directory).problems


def test_a_flood_of_files_is_refused_without_listing_them_all(tmp_path):
    directory = place(tmp_path, good_evidence())
    for index in range(100):
        (directory / f"f{index}").write_text("x", encoding="utf-8")
    assert "EVIDENCE_TOO_MANY_FILES" in read(directory).problems


def test_a_symlinked_evidence_file_is_refused(tmp_path):
    directory = tmp_path / "ev"
    directory.mkdir()
    (tmp_path / "real.json").write_text(json.dumps(good_evidence()), encoding="utf-8")
    try:
        os.symlink(tmp_path / "real.json", directory / "evidence.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this host")
    result = read(directory)
    assert result.evidence is None and "EVIDENCE_SYMLINK" in result.problems


def test_a_symlinked_evidence_directory_is_refused(tmp_path):
    place(tmp_path, good_evidence())
    try:
        os.symlink(tmp_path / "ev", tmp_path / "alias", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this host")
    assert read(tmp_path / "alias").problems == ("EVIDENCE_SYMLINK",)


def test_an_oversized_document_is_refused_without_being_parsed(tmp_path):
    assert read(place(tmp_path, {"padding": "x" * 5000}), limit=1024).problems == ("EVIDENCE_OVERSIZED",)


def test_a_document_exactly_at_the_limit_is_read(tmp_path):
    payload = json.dumps(good_evidence()).encode()
    assert read(place(tmp_path, payload), limit=len(payload)).evidence is not None


@pytest.mark.parametrize(
    "payload, code",
    [
        (b"\xff\xfe\x00\x00", "EVIDENCE_ENCODING"),
        (b'{"a": "\xc3\x28"}', "EVIDENCE_ENCODING"),
        (b"\xef\xbb\xbf{}", "EVIDENCE_MALFORMED"),
        (b"{not json", "EVIDENCE_MALFORMED"),
        (b"", "EVIDENCE_MALFORMED"),
        (b'{"a": NaN}', "EVIDENCE_MALFORMED"),
        (b'{"a": Infinity}', "EVIDENCE_MALFORMED"),
        (b'{"a": -Infinity}', "EVIDENCE_MALFORMED"),
        (b"[1, 2, 3]", "EVIDENCE_NOT_OBJECT"),
        (b'"a string"', "EVIDENCE_NOT_OBJECT"),
        (b"null", "EVIDENCE_NOT_OBJECT"),
        (b'{"a": 1, "a": 2}', "EVIDENCE_DUPLICATE_KEY"),
        (b'{"outer": {"k": 1, "k": 2}}', "EVIDENCE_DUPLICATE_KEY"),
        pytest.param(b"[" * 30000, "EVIDENCE_MALFORMED", id="deeply-nested"),
    ],
)
def test_malformed_bytes_are_refused_with_a_fixed_code(tmp_path, payload, code):
    result = read(place(tmp_path, payload))
    assert result.evidence is None and result.problems == (code,), result.problems


def test_an_enormous_integer_is_refused_whichever_way_the_interpreter_treats_it(tmp_path):
    """Python 3.10.7+ refuses to parse it (malformed); older ones parse it and the
    schema refuses the unknown field. Either way: a refusal, in fixed codes."""
    result = read(place(tmp_path, b'{"a": ' + b"9" * 20000 + b"}"))
    assert result.evidence is None and result.problems
    assert all(publog.CODE.match(problem) for problem in result.problems)


@pytest.mark.parametrize("key", sorted(evidence_module.AUTHORITY_KEYS))
def test_a_field_only_the_anchor_may_say_is_reported_as_an_authority_claim(tmp_path, key):
    result = read(place(tmp_path, {**good_evidence(), key: "ACCEPT"}))
    assert result.evidence is None and "EVIDENCE_AUTHORITY_FIELD" in result.problems


def test_an_unknown_field_is_refused_and_not_reported_as_authority(tmp_path):
    result = read(place(tmp_path, {**good_evidence(), "PRIVATE_SENTINEL_X": 1}))
    assert result.problems == ("EVIDENCE_UNKNOWN_FIELD",)


@pytest.mark.parametrize("field", sorted(evidence_module.TOP_KEYS))
def test_a_missing_field_is_refused(tmp_path, field):
    document = good_evidence()
    del document[field]
    assert read(place(tmp_path, document)).problems == ("EVIDENCE_FIELD_MISSING",)


@pytest.mark.parametrize(
    "override, code",
    [
        ({"evidence_version": "atlas-anchor-evidence/1"}, "EVIDENCE_VERSION"),
        ({"evidence_version": 2}, "EVIDENCE_VERSION"),
        ({"candidate_sha": "abc"}, "EVIDENCE_IDENTITY_TYPES"),
        ({"candidate_sha": SHA_A.upper()}, "EVIDENCE_IDENTITY_TYPES"),
        ({"candidate_tree": 5}, "EVIDENCE_IDENTITY_TYPES"),
        ({"inputs_requested": "a.py"}, "EVIDENCE_SCOPE_TYPES"),
        ({"inputs_requested": [1]}, "EVIDENCE_SCOPE_TYPES"),
        ({"inputs_requested": ["a\x00b"]}, "EVIDENCE_SCOPE_TYPES"),
        ({"inputs_requested": ["x" * 600]}, "EVIDENCE_SCOPE_TYPES"),
        ({"inputs_requested": [""]}, "EVIDENCE_SCOPE_TYPES"),
        ({"inputs_observed": {"a.py": 1}}, "EVIDENCE_LIST_TYPES"),
        ({"inputs_unreadable": "none"}, "EVIDENCE_LIST_TYPES"),
        ({"inputs_observed": ["a", 7]}, "EVIDENCE_OBSERVATION_SHAPE"),
        ({"inputs_observed": [{"relative_path": "a.py"}]}, "EVIDENCE_OBSERVATION_SHAPE"),
        (
            {"inputs_observed": [{"relative_path": "a.py", "blob": "c" * 40, "sha256": "d" * 64, "size": 3, "x": 1}]},
            "EVIDENCE_OBSERVATION_SHAPE",
        ),
        (
            {"inputs_observed": [{"relative_path": "a.py", "blob": "c" * 40, "sha256": "d" * 64, "size": True}]},
            "EVIDENCE_OBSERVATION_TYPES",
        ),
        (
            {"inputs_observed": [{"relative_path": "a.py", "blob": "c" * 40, "sha256": "d" * 64, "size": -1}]},
            "EVIDENCE_OBSERVATION_TYPES",
        ),
        (
            {"inputs_observed": [{"relative_path": "a.py", "blob": "c" * 39, "sha256": "d" * 64, "size": 1}]},
            "EVIDENCE_OBSERVATION_TYPES",
        ),
        (
            {"inputs_observed": [{"relative_path": "a.py", "blob": "c" * 40, "sha256": "D" * 64, "size": 1}]},
            "EVIDENCE_OBSERVATION_TYPES",
        ),
        (
            {"inputs_observed": [{"relative_path": "a.py", "blob": "c" * 40, "sha256": "d" * 64, "size": "3"}]},
            "EVIDENCE_OBSERVATION_TYPES",
        ),
        ({"inputs_unreadable": [{"relative_path": "a.py", "reason": "because"}]}, "EVIDENCE_UNREADABLE_SHAPE"),
        ({"inputs_unreadable": [{"relative_path": "a.py"}]}, "EVIDENCE_UNREADABLE_SHAPE"),
        ({"inputs_unreadable": ["a.py: permission denied"]}, "EVIDENCE_UNREADABLE_SHAPE"),
    ],
)
def test_a_field_of_the_wrong_shape_is_refused_with_a_fixed_code(tmp_path, override, code):
    result = read(place(tmp_path, good_evidence(**override)))
    assert result.evidence is None and code in result.problems, result.problems


@pytest.mark.parametrize("reason", sorted(evidence_module.UNREADABLE_REASONS))
def test_every_fixed_unreadable_reason_is_accepted_in_shape(tmp_path, reason):
    document = good_evidence(inputs_unreadable=[{"relative_path": "b.py", "reason": reason}])
    assert read(place(tmp_path, document)).problems == ()


def test_no_problem_ever_contains_text_taken_from_the_evidence(tmp_path):
    sentinel = "PRIVATE_SENTINEL_EVIDENCE_TEXT"
    documents = [
        {**good_evidence(), sentinel: sentinel},
        good_evidence(candidate_sha=sentinel),
        good_evidence(inputs_requested=[sentinel, 1]),
        good_evidence(inputs_observed=[{"relative_path": sentinel}]),
        good_evidence(inputs_unreadable=[{"relative_path": sentinel, "reason": sentinel}]),
    ]
    for index, document in enumerate(documents):
        result = read(place(tmp_path / str(index), document))
        assert result.problems
        for problem in result.problems:
            assert publog.CODE.match(problem) and sentinel not in problem


def test_seeded_random_corruption_never_raises_and_never_returns_text(tmp_path):
    """Two hundred structured corruptions of a good document. Whatever the bytes,
    the answer is either a document of the right shape or fixed codes."""
    rng = random.Random(20260928)
    base = json.dumps(good_evidence()).encode()
    for round_number in range(200):
        data = bytearray(base)
        for _ in range(rng.randint(1, 6)):
            position = rng.randrange(len(data))
            operation = rng.choice(["flip", "drop", "dup", "insert"])
            if operation == "flip":
                data[position] = rng.randrange(256)
            elif operation == "drop":
                del data[position]
            elif operation == "dup":
                data[position:position] = data[position : position + rng.randint(1, 8)]
            else:
                data[position:position] = bytes([rng.randrange(256)]) * rng.randint(1, 4)
        result = read(place(tmp_path / str(round_number), bytes(data)))
        assert (result.evidence is None) == bool(result.problems)
        for problem in result.problems:
            assert publog.CODE.match(problem)


# ==========================================================================
# what an independent audit found the first audit did not check
# ==========================================================================


def before_image(argv):
    return argv.index(IMAGE)


HARDER_MUTATIONS = {
    "a later ulimit overrides the correct one": (
        lambda a: a[: before_image(a)] + ["--ulimit", "fsize=-1"] + a[before_image(a) :],
        "SANDBOX_FILE_SIZE",
    ),
    "nofile raised": (lambda a: set_value(a, "--ulimit", "nofile=1048576", 1), "SANDBOX_FILE_SIZE"),
    "core dumps allowed": (lambda a: set_value(a, "--ulimit", "core=-1", 2), "SANDBOX_FILE_SIZE"),
    "a remote daemon chosen before run": (
        lambda a: ["docker", "-H", "tcp://203.0.113.9:2375"] + a[1:], "SANDBOX_DOCKER_PREFIX",
    ),
    "a context chosen before run": (
        lambda a: ["docker", "--context", "remote"] + a[1:], "SANDBOX_DOCKER_PREFIX",
    ),
    "another container client": (lambda a: ["podman"] + a[1:], "SANDBOX_DOCKER_PREFIX"),
    "a wrapper before the client": (lambda a: ["sh", "-c", "docker"] + a, "SANDBOX_DOCKER_PREFIX"),
    "workdir on the evidence mount": (lambda a: set_value(a, "--workdir", "/evidence"), "SANDBOX_WORKDIR"),
    "another hostname": (lambda a: set_value(a, "--hostname", "runner"), "SANDBOX_HOSTNAME"),
    "a name that is not a token": (lambda a: set_value(a, "--name", "a b"), "SANDBOX_NAME"),
    "no name": (lambda a: remove_pair(a, "--name"), "SANDBOX_NAME"),
    "extra arguments for the child": (lambda a: a + ["--policy", "/candidate/p.json"], "SANDBOX_COMMAND"),
    "the child told to write elsewhere": (
        lambda a: replace(a, "/evidence/evidence.json", "/tmp/evidence.json"), "SANDBOX_COMMAND",
    ),
    "the child told to read a candidate-supplied policy": (
        lambda a: replace(a, "/child/policy.json", "/candidate/policy.json"), "SANDBOX_COMMAND",
    ),
    "the child told to look somewhere else": (
        lambda a: replace(a, "/candidate", "/child"), "SANDBOX_COMMAND",
    ),
    "a commit that is not a sha": (lambda a: replace(a, SHA_A, "not-a-sha"), "SANDBOX_COMMAND"),
    "a manifest that is not attached": (
        lambda a: replace(a, "--inputs-manifest=", "--inputs-manifest"), "SANDBOX_COMMAND",
    ),
}


@pytest.mark.parametrize("name", sorted(HARDER_MUTATIONS))
def test_a_box_that_the_first_audit_would_have_passed_is_now_refused(tmp_path, name):
    mutate, code = HARDER_MUTATIONS[name]
    assert code in audit(mutate(good_argv(tmp_path)), tmp_path), name


def test_a_hardened_command_whose_manifest_mentions_the_socket_is_not_refused(tmp_path):
    """The manifest is caller text, after the image. Naming a socket there mounts nothing."""
    assert audit(good_argv(tmp_path, manifest="notes/docker.sock.md"), tmp_path) == []


@pytest.mark.parametrize("bad", ["a,b", "a\nb", "a\rb", 'a"b'])
def test_a_directory_path_that_could_end_a_mount_field_is_refused_by_the_builder(tmp_path, bad):
    layout_ = sandbox_spec.Layout(tmp_path / bad, tmp_path / "c", tmp_path / "d")
    with pytest.raises(PolicyError, match="ends a mount field"):
        sandbox_spec.build_argv(
            POLICY, docker=["docker"], name="n", uid=1, gid=1, layout=layout_,
            candidate=SHA_A, tree="b" * 40, manifest="",
        )


@pytest.mark.parametrize("breaker", ["\n", "\r", '"'])
def test_a_mount_option_carrying_a_line_break_or_quote_is_refused_by_the_audit(tmp_path, breaker):
    """Docker parses --mount as CSV. A line break or quote can make it read only part of
    the value, silently dropping the trailing `readonly` the audit thinks it saw."""
    argv = good_argv(tmp_path)
    tampered = [t + breaker + ",extra" if t.endswith("target=/child,readonly") else t for t in argv]
    assert "SANDBOX_MOUNT_MALFORMED" in audit(tampered, tmp_path)


def test_the_audit_knows_which_commit_and_tree_the_child_was_told(tmp_path):
    argv = good_argv(tmp_path)
    record = layout(tmp_path).as_record()
    assert sandbox_spec.audit_argv(argv, POLICY, record, ("docker",), SHA_A, "b" * 40) == []
    assert "SANDBOX_COMMAND" in sandbox_spec.audit_argv(argv, POLICY, record, ("docker",), "c" * 40, "b" * 40)
    assert "SANDBOX_COMMAND" in sandbox_spec.audit_argv(argv, POLICY, record, ("docker",), SHA_A, "c" * 40)


def test_a_different_client_is_accepted_only_when_the_audit_is_told_to_expect_it(tmp_path):
    argv = good_argv(tmp_path, docker=["python3", "fake_docker.py"])
    record = layout(tmp_path).as_record()
    assert "SANDBOX_DOCKER_PREFIX" in sandbox_spec.audit_argv(argv, POLICY, record)
    assert sandbox_spec.audit_argv(argv, POLICY, record, ("python3", "fake_docker.py")) == []


def test_the_docker_client_cannot_be_pointed_at_another_daemon_by_the_environment():
    parent = {
        "PATH": "/bin", "USERPROFILE": "C:\\u", "DOCKER_HOST": "tcp://evil:2375",
        "DOCKER_CONTEXT": "remote", "DOCKER_CONFIG": "/tmp/attacker",
    }
    assert set(sandbox.client_environment(parent)) == {"PATH", "USERPROFILE"}


def test_the_container_gid_is_a_fixed_unprivileged_group_not_the_runners_own():
    """On a hosted runner the runner user's primary group may be `docker`."""
    class FakeOs:
        @staticmethod
        def getuid():
            return 1000

        @staticmethod
        def getgid():
            return 1000

    original = sandbox.os
    sandbox.os = FakeOs
    try:
        assert sandbox._default_ids() == (1000, 65534)
    finally:
        sandbox.os = original

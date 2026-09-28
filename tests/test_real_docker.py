"""What a REAL container runtime does with the box the anchor asks for.

Everything else in this suite checks configuration: that the anchor asks for a
read-only mount, drops capabilities, sets a pid limit. This file checks the other
half against an actual Docker daemon and the actual pinned image: that a hostile
process inside the box is in fact refused. It runs the anchor's own `build_argv`
command line, with the child's command replaced by a script that tries everything a
hostile candidate would.

It is skipped when no Linux container daemon is reachable, so it runs on the
`ubuntu-latest` runner that qualification itself uses and on a developer machine
with Docker, and is honest about being skipped anywhere else.

What this is NOT: proof about the kernel, the runtime or the hypervisor. It reports
what THIS host's runtime did on THIS run. A container escape is an accepted
infrastructure trust assumption and is not attacked here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from support import ANCHOR, SHA_A

import policy as policy_module  # noqa: E402
import sandbox  # noqa: E402
import sandbox_spec  # noqa: E402
import verify as verify_module  # noqa: E402
import evidence as evidence_module  # noqa: E402


def _daemon_is_linux() -> bool:
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            capture_output=True, timeout=25, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0 and b"linux" in completed.stdout.lower()


pytestmark = pytest.mark.skipif(
    not _daemon_is_linux(), reason="no reachable Linux container daemon on this host"
)

UID = os.getuid() if hasattr(os, "getuid") and os.getuid() != 0 else 1000
GID = os.getgid() if hasattr(os, "getgid") and os.getgid() != 0 else 1000
ALLOWED_IMAGE_ENV = {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "HOSTNAME", "HOME"}

HOSTILE = r'''
import json, os, socket, subprocess, sys
out = {"uid": os.getuid(), "gid": os.getgid(), "env": dict(os.environ)}

def attempt(path):
    try:
        with open(path, "w") as handle:
            handle.write("x")
        return "written"
    except OSError as error:
        return "denied:%s" % error.errno

for name, path in (
    ("candidate", "/candidate/new.txt"), ("child", "/child/new.txt"),
    ("etc", "/etc/pwned"), ("usr", "/usr/pwned"), ("root", "/pwned"),
    ("evidence", "/evidence/ok.txt"), ("tmp", "/tmp/ok.txt"),
):
    out["write_" + name] = attempt(path)

try:
    with open("/tmp/x.sh", "w") as handle:
        handle.write("#!/bin/sh\necho hi\n")
    os.chmod("/tmp/x.sh", 0o755)
    out["tmp_exec"] = "ran" if subprocess.run(["/tmp/x.sh"], capture_output=True).returncode == 0 else "refused"
except OSError as error:
    out["tmp_exec"] = "refused:%s" % error.errno

try:
    socket.create_connection(("1.1.1.1", 53), timeout=3).close()
    out["network"] = "connected"
except OSError:
    out["network"] = "refused"
try:
    socket.getaddrinfo("example.com", 80)
    out["dns"] = "resolved"
except OSError:
    out["dns"] = "refused"

for line in open("/proc/self/status"):
    key, _, value = line.partition(":")
    if key in ("CapEff", "CapPrm", "CapBnd", "CapInh", "NoNewPrivs", "Seccomp"):
        out[key] = value.strip()

out["mount_points"] = sorted({line.split()[4] for line in open("/proc/self/mountinfo") if len(line.split()) > 4})
out["docker_socket"] = os.path.exists("/var/run/docker.sock")
out["ssh_dir"] = os.path.exists(os.path.expanduser("~/.ssh"))
out["passwd_readable_root_files"] = sorted(os.listdir("/"))

spawned = []
try:
    for _ in range(300):
        spawned.append(subprocess.Popen(["sleep", "4"]))
except OSError as error:
    out["spawn_stopped"] = "errno:%s" % error.errno
out["spawned"] = len(spawned)
for process in spawned:
    process.kill()
print("HOSTILE_REPORT " + json.dumps(out))
'''

MEMORY_HOG = "b = bytearray(2 << 30)\nfor i in range(0, len(b), 4096):\n    b[i] = 1\nprint('SURVIVED')\n"
FILE_HOG = "with open('/evidence/big.bin', 'wb') as h:\n    h.write(b'x' * (16 << 20))\nprint('SURVIVED')\n"
TIMED_LOOP = "import time\ntime.sleep(60)\n"


def real_policy(tmp_path):
    document = json.loads((ANCHOR / "policy.json").read_text(encoding="utf-8"))
    document["anchor"]["repository_id"] = 1
    document["required_inputs_floor"] = ["scripts/one.py"]
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return policy_module.load(path), path


def layout(tmp_path):
    for name in ("candidate", "child", "evidence"):
        (tmp_path / name).mkdir(exist_ok=True)
    (tmp_path / "candidate" / "scripts").mkdir(exist_ok=True)
    (tmp_path / "candidate" / "scripts" / "one.py").write_bytes(b"ONE = 1\n")
    return sandbox_spec.Layout(tmp_path / "candidate", tmp_path / "child", tmp_path / "evidence")


def hostile_argv(policy, the_layout, script):
    """The anchor's own command, with only the child's program replaced."""
    argv = sandbox_spec.build_argv(
        policy, docker=["docker"], name="atlas-anchor-realtest", uid=UID, gid=GID,
        layout=the_layout, candidate=SHA_A, tree="b" * 40, manifest="",
    )
    image = argv.index(policy["sandbox"]["image"])
    return argv[: image + 1] + ["-I", "-S", "-B", "-c", script]


def run(argv, timeout=180):
    environment = dict(os.environ)
    environment["ANCHOR_TEST_SECRET"] = "SYNTHETIC-CLIENT-ENV-SECRET-4f1c9a"
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=environment, check=False)


@pytest.fixture(scope="module")
def pulled(tmp_path_factory):
    policy, _ = real_policy(tmp_path_factory.mktemp("policy"))
    completed = subprocess.run(
        ["docker", "pull", "--quiet", policy["sandbox"]["image"]], capture_output=True, timeout=600, check=False
    )
    if completed.returncode != 0:
        pytest.skip("the pinned image could not be pulled on this host")
    return policy


@pytest.fixture(scope="module")
def report(tmp_path_factory, pulled):
    base = tmp_path_factory.mktemp("hostile")
    the_layout = layout(base)
    process = run(hostile_argv(pulled, the_layout, HOSTILE))
    assert process.returncode == 0, process.stderr[-500:]
    line = next(text for text in process.stdout.splitlines() if text.startswith("HOSTILE_REPORT "))
    data = json.loads(line.split(" ", 1)[1])
    data["_evidence_dir"] = sorted(path.name for path in (base / "evidence").iterdir())
    data["_candidate_dir"] = sorted(path.name for path in (base / "candidate").rglob("*") if path.is_file())
    return data


def test_the_child_runs_as_the_unprivileged_user_it_was_given(report):
    assert (report["uid"], report["gid"]) == (UID, GID) and report["uid"] != 0


def test_no_variable_of_the_docker_client_environment_reaches_the_child(report):
    assert "ANCHOR_TEST_SECRET" not in report["env"]
    assert not any("SYNTHETIC" in str(value) for value in report["env"].values())
    assert set(report["env"]) <= ALLOWED_IMAGE_ENV, sorted(set(report["env"]) - ALLOWED_IMAGE_ENV)


@pytest.mark.parametrize("target", ["candidate", "child", "etc", "usr", "root"])
def test_the_real_runtime_refuses_writes_outside_the_evidence_directory(report, target):
    assert report["write_" + target].startswith("denied"), target


def test_the_evidence_directory_and_tmp_are_the_only_places_the_child_can_write(report):
    assert report["write_evidence"] == "written" and report["write_tmp"] == "written"
    assert report["_evidence_dir"] == ["ok.txt"]
    assert report["_candidate_dir"] == ["scripts/one.py"]


def test_the_real_runtime_refuses_to_execute_from_tmp(report):
    assert report["tmp_exec"].startswith("refused")


def test_the_real_runtime_gives_the_child_no_network(report):
    assert report["network"] == "refused" and report["dns"] == "refused"


def test_the_child_holds_no_capabilities_and_cannot_gain_privilege(report):
    for field in ("CapEff", "CapPrm", "CapBnd", "CapInh"):
        assert int(report[field], 16) == 0, field
    assert report["NoNewPrivs"] == "1"
    assert report["Seccomp"] in {"2", "1"}


def test_the_child_sees_no_docker_socket_and_no_ssh_directory(report):
    assert report["docker_socket"] is False and report["ssh_dir"] is False


def test_the_child_sees_only_the_expected_mounts_of_ours(report):
    ours = {point for point in report["mount_points"] if point.startswith(("/candidate", "/child", "/evidence", "/tmp"))}
    assert ours == {"/candidate", "/child", "/evidence", "/tmp"}
    assert not [p for p in report["mount_points"] if p in {"/host", "/var/run/docker.sock", "/run/docker.sock"}]


def test_the_real_pid_limit_stops_a_fork_flood(report, pulled):
    assert report["spawned"] < 300 and report["spawned"] <= pulled["sandbox"]["pids_limit"]


def test_the_real_memory_limit_kills_a_memory_hog(tmp_path, pulled):
    process = run(hostile_argv(pulled, layout(tmp_path), MEMORY_HOG))
    assert "SURVIVED" not in process.stdout and process.returncode != 0


def test_the_real_file_size_limit_stops_a_disk_filler(tmp_path, pulled):
    the_layout = layout(tmp_path)
    process = run(hostile_argv(pulled, the_layout, FILE_HOG))
    assert "SURVIVED" not in process.stdout and process.returncode != 0
    big = tmp_path / "evidence" / "big.bin"
    assert not big.exists() or big.stat().st_size <= pulled["sandbox"]["max_file_bytes"]


def test_the_real_argument_vector_passes_the_anchors_own_audit(tmp_path, pulled):
    the_layout = layout(tmp_path)
    argv = sandbox_spec.build_argv(
        pulled, docker=["docker"], name="n", uid=UID, gid=GID, layout=the_layout,
        candidate=SHA_A, tree="b" * 40, manifest="",
    )
    assert sandbox_spec.audit_argv(argv, pulled, the_layout.as_record()) == []


def test_the_whole_sandbox_step_runs_the_real_child_in_the_real_box(tmp_path, pulled):
    """The anchor's own run_sandbox: pull, identify, start, remove - and the evidence
    the real child wrote is a document the verifier accepts the shape of."""
    the_layout = layout(tmp_path)
    _, policy_path = real_policy(tmp_path)
    sandbox.stage_child(ANCHOR, the_layout.child, policy_path)
    record = sandbox.run_sandbox(
        pulled, the_layout, parent_environment=dict(os.environ), candidate=SHA_A,
        tree="b" * 40, manifest="", docker=["docker"], uid=UID, gid=GID, name="atlas-anchor-realtest-2",
    )
    assert sandbox_spec.acceptable(record, pulled) == [], record
    assert record["image_id"].startswith("sha256:")
    result = evidence_module.read_directory(the_layout.evidence, 1 << 20)
    assert result.problems == () and result.evidence["inputs_unreadable"] == []
    assert [entry["relative_path"] for entry in result.evidence["inputs_observed"]] == ["scripts/one.py"]


def test_the_wall_clock_kills_a_container_that_never_finishes(tmp_path, pulled):
    quick = json.loads(json.dumps(pulled))
    quick["sandbox"]["timeout_seconds"] = 3
    the_layout = layout(tmp_path)
    started = sandbox.execute(
        hostile_argv(quick, the_layout, TIMED_LOOP), {"PATH": os.environ["PATH"], **(
            {"SYSTEMROOT": os.environ["SYSTEMROOT"]} if "SYSTEMROOT" in os.environ else {}
        )}, timeout=quick["sandbox"]["timeout_seconds"], cap=1000,
    )
    subprocess.run(["docker", "rm", "--force", "atlas-anchor-realtest"], capture_output=True, check=False)
    assert started.timed_out


def test_the_named_container_does_not_outlive_its_run(tmp_path, pulled):
    listing = subprocess.run(
        ["docker", "ps", "--all", "--filter", "name=atlas-anchor-realtest", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=False,
    )
    assert listing.stdout.strip() == ""

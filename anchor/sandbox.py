"""The box the candidate is looked at in, and the record of how the box was built.

The previous design bought isolation with a second GitHub job, and paid for it by
shipping the candidate between jobs as an artifact. On a public repository an
artifact is world-readable, so that payment was a disclosure. Here the candidate
never leaves the runner: the boundary is a container on the same ephemeral VM.

What the container is given, and nothing else:

  /candidate   the frozen scope, read-only. Regular files only; no .git, no history.
  /child       three anchor files (policy.py, policy.json, runner.py), read-only.
  /evidence    the ONE writable bind mount. What comes back through it is hostile.
  /tmp         a small tmpfs, noexec.

What it is not given: a network, a credential, a host directory, the docker
socket, the anchor checkout, the capture record, the runner's temp directory, or
any environment variable. `docker run` forwards none of the client's environment
unless told to, and it is never told to.

Two things are deliberately NOT kept:

  * The child's stdout and stderr. They are counted and discarded. A public log
    is a disclosure surface and hostile output is the last thing that should be
    written near one; nothing downstream needs the bytes, only whether there were
    too many.
  * Any decision. This module builds a box, runs it and records what happened.
    Whether that is acceptable is decided elsewhere, from the record, by code the
    box never saw.

The record carries the exact argument vector so that the verifier can audit it
against the required hardening independently of the builder. A builder that
quietly stopped passing `--cap-drop` would be caught by a check that does not
share its code.

Escape from the container itself - the runtime, the kernel, the hypervisor - is
outside what this can prove. It is an infrastructure trust assumption (see the
README), not something a second verifier of Docker could close.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import policy as anchor_policy
import publog
from policy import PolicyError
from sandbox_spec import (
    IMAGE_ID,
    SANDBOX_VERSION,
    Layout,
    acceptable,
    build_argv,
    digest_of,
)

CHILD_CODE = ("policy.py", "runner.py")

_PULL_TIMEOUT_SECONDS = 300
_INSPECT_TIMEOUT_SECONDS = 30
_POLL_SECONDS = 0.05

# The docker client is started with these variables and no others. The deploy key,
# the governance token, and the OIDC request variables are not on the list, so
# they cannot ride along even if a workflow step were to export them.
#
# DOCKER_HOST, DOCKER_CONTEXT and DOCKER_CONFIG are deliberately NOT on it: each
# selects WHICH daemon runs the box, and a box on a remote daemon is not a box on
# this runner. The client uses its default socket, and the audit refuses any
# option before `run` that would say otherwise.
_CLIENT_ENVIRONMENT = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "LANG",
)


@dataclass(frozen=True)
class Execution:
    returncode: int | None
    stdout_bytes: int
    stderr_bytes: int
    stdout: bytes
    timed_out: bool
    output_exceeded: bool


# --------------------------------------------------------------------------
# running it
# --------------------------------------------------------------------------


def client_environment(parent: Mapping[str, str]) -> dict[str, str]:
    """The environment the docker CLIENT gets: a short allow-list, nothing inherited."""
    return {name: parent[name] for name in _CLIENT_ENVIRONMENT if name in parent}


def _drain(stream: Any, limit: int, keep: bool, state: dict[str, Any], key: str) -> None:
    while True:
        chunk = stream.read(4096)
        if not chunk:
            return
        state[key] += len(chunk)
        if keep and state[key] <= limit:
            state[key + "_data"].append(chunk)
        if state[key] > limit:
            state["exceeded"].set()


def execute(
    argv: Sequence[str],
    environment: Mapping[str, str],
    *,
    timeout: float,
    cap: int,
    keep_stdout: bool = False,
) -> Execution:
    """Run a command, COUNT its output against a cap and discard it.

    `keep_stdout` exists for one trusted use - reading an image id back from the
    docker client - and is still bounded by `cap`. A command that talks too much,
    or too long, is killed: the limit is on the run, not on what is printed.
    """
    state: dict[str, Any] = {
        "out": 0,
        "err": 0,
        "out_data": [],
        "err_data": [],
        "exceeded": threading.Event(),
    }
    try:
        process = subprocess.Popen(  # noqa: S603 - argv is built here, never a shell string
            list(argv),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, ValueError):
        return Execution(None, 0, 0, b"", False, False)

    readers = [
        threading.Thread(target=_drain, args=(process.stdout, cap, keep_stdout, state, "out")),
        threading.Thread(target=_drain, args=(process.stderr, cap, False, state, "err")),
    ]
    for reader in readers:
        reader.daemon = True
        reader.start()

    timed_out = False
    deadline = time.monotonic() + timeout
    while process.poll() is None:
        if state["exceeded"].is_set():
            break
        if time.monotonic() > deadline:
            timed_out = True
            break
        time.sleep(_POLL_SECONDS)
    if process.poll() is None:
        process.kill()
    process.wait()
    for reader in readers:
        reader.join(timeout=5)

    return Execution(
        process.returncode,
        state["out"],
        state["err"],
        b"".join(state["out_data"]),
        timed_out,
        state["exceeded"].is_set(),
    )


def stage_child(source: Path, destination: Path, policy_path: Path) -> None:
    """Copy exactly the files the child needs. It is given no more of the anchor.

    The policy is the one THIS run loaded, not whatever sits beside the code: the
    child and the verifier must be judging under the same floor, limits and
    identity, and two policy files that could differ would be two definitions.
    """
    destination.mkdir(parents=True, exist_ok=True)
    for name in CHILD_CODE:
        shutil.copyfile(source / name, destination / name)
    shutil.copyfile(policy_path, destination / "policy.json")


def _pull_and_identify(
    policy: Mapping[str, Any], docker: Sequence[str], environment: Mapping[str, str]
) -> tuple[bool, str | None]:
    image = policy["sandbox"]["image"]
    pulled = execute(
        [*docker, "pull", "--quiet", image],
        environment,
        timeout=_PULL_TIMEOUT_SECONDS,
        cap=1 << 20,
    )
    if pulled.returncode != 0 or pulled.timed_out:
        return False, None
    inspected = execute(
        [*docker, "image", "inspect", "--format", "{{.Id}}", image],
        environment,
        timeout=_INSPECT_TIMEOUT_SECONDS,
        cap=512,
        keep_stdout=True,
    )
    image_id = inspected.stdout.decode("utf-8", errors="replace").strip()
    if inspected.returncode != 0 or not IMAGE_ID.match(image_id):
        return False, None
    return True, image_id


def run_sandbox(
    policy: Mapping[str, Any],
    layout: Layout,
    *,
    parent_environment: Mapping[str, str],
    candidate: str,
    tree: str,
    manifest: str,
    docker: Sequence[str],
    uid: int,
    gid: int,
    name: str,
) -> dict[str, Any]:
    """Build the box, run the child in it, and return the record. Decides nothing."""
    box = policy["sandbox"]
    environment = client_environment(parent_environment)
    argv = build_argv(
        policy,
        docker=docker,
        name=name,
        uid=uid,
        gid=gid,
        layout=layout,
        candidate=candidate,
        tree=tree,
        manifest=manifest,
    )
    record: dict[str, Any] = {
        "sandbox_version": SANDBOX_VERSION,
        "image": box["image"],
        "image_id": None,
        "params": {"name": name, "uid": uid, "gid": gid, "candidate": candidate, "tree": tree},
        "layout": layout.as_record(),
        "argv": argv,
        "pull_ok": False,
        "started": False,
        "exit_code": None,
        "timed_out": False,
        "output_exceeded": False,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }

    if uid == 0 or gid == 0:
        return record
    pulled, image_id = _pull_and_identify(policy, docker, environment)
    record["pull_ok"] = pulled
    record["image_id"] = image_id
    if not pulled:
        return record

    try:
        result = execute(
            argv,
            environment,
            timeout=box["timeout_seconds"],
            cap=box["max_output_bytes"],
        )
    finally:
        # However the run ended, the container does not outlive it.
        execute(
            [*docker, "rm", "--force", name],
            environment,
            timeout=_INSPECT_TIMEOUT_SECONDS,
            cap=4096,
        )
    record["started"] = result.returncode is not None
    record["exit_code"] = result.returncode
    record["timed_out"] = result.timed_out
    record["output_exceeded"] = result.output_exceeded
    record["stdout_bytes"] = result.stdout_bytes
    record["stderr_bytes"] = result.stderr_bytes
    return record


_UNPRIVILEGED_GID = 65534


def _default_ids() -> tuple[int, int]:
    """The runner's uid, so it can write the evidence directory, and a fixed gid.

    Not the runner's own gid: on a hosted runner that user's primary group may be the
    `docker` group, and a child in it would have the socket's group access if any
    future mount ever exposed one.
    """
    if not hasattr(os, "getuid"):
        raise PolicyError("no uid is available on this platform; pass --uid and --gid")
    return os.getuid(), _UNPRIVILEGED_GID


def _parse_docker(raw: str) -> list[str]:
    try:
        command = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PolicyError("--docker-command is not JSON") from error
    if not isinstance(command, list) or not command or not all(
        isinstance(part, str) and part for part in command
    ):
        raise PolicyError("--docker-command is not a non-empty list of strings")
    return command


def main(argv: list[str]) -> int:
    anchor_policy.assert_isolated()
    parser = publog.Parser("SANDBOX", "Run the frozen scope in the sandbox.")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--anchor-code", required=True, type=Path)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--inputs-manifest", required=True)
    parser.add_argument("--scope-dir", required=True, type=Path)
    parser.add_argument("--child-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--docker-command", default='["docker"]')
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    arguments = parser.parse_args(argv)

    try:
        policy = anchor_policy.load(arguments.policy)
        anchor_policy.assert_full_sha(arguments.candidate, "candidate")
        docker = _parse_docker(arguments.docker_command)
        uid, gid = (
            (arguments.uid, arguments.gid)
            if arguments.uid is not None and arguments.gid is not None
            else _default_ids()
        )
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", arguments.name):
            raise PolicyError("the container name is not a plain token")
        capture = json.loads(arguments.capture.read_text(encoding="utf-8"))
        tree = capture["candidate_tree"]
    except (PolicyError, OSError, ValueError, KeyError) as error:
        detail = str(error) if isinstance(error, PolicyError) else "unreadable input"
        publog.emit_policy_refusal("SANDBOX", "SANDBOX_REFUSED", detail)
        return 2

    stage_child(arguments.anchor_code, arguments.child_dir, arguments.policy)
    arguments.evidence_dir.mkdir(parents=True, exist_ok=True)
    layout = Layout(
        arguments.scope_dir.resolve(),
        arguments.child_dir.resolve(),
        arguments.evidence_dir.resolve(),
    )
    record = run_sandbox(
        policy,
        layout,
        parent_environment=os.environ,
        candidate=arguments.candidate,
        tree=tree,
        manifest=arguments.inputs_manifest,
        docker=docker,
        uid=uid,
        gid=gid,
        name=arguments.name,
    )
    arguments.record.parent.mkdir(parents=True, exist_ok=True)
    arguments.record.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")

    problems = acceptable(record, policy)
    exit_code = record["exit_code"]
    publog.emit(
        "SANDBOX",
        "PASS" if not problems else "REFUSE",
        None if not problems else problems[0],
        exit_code=exit_code if isinstance(exit_code, int) and exit_code >= 0 else 999,
        stdout_bytes=record["stdout_bytes"],
        stderr_bytes=record["stderr_bytes"],
        problems=len(problems),
    )
    return 0 if record["started"] else 2


if __name__ == "__main__":
    raise SystemExit(publog.guarded("SANDBOX", main, sys.argv[1:]))

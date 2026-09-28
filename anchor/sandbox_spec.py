"""What the sandbox must be, as pure data and pure checks - and nothing that runs.

The verifier has to know what a correctly built box looks like, and has to audit
the record of one, without being able to start a process or touch a network. That
is why this is a module of its own: `sandbox.py` builds and runs boxes and may
spawn docker; this module only describes them, and is what the verifier imports.

`build_argv` says what the box is. `audit_argv` re-derives, from the command
alone and without sharing a line of its logic, whether that command has every
property required - so a builder that quietly stopped passing `--cap-drop` is
caught by a check that does not share its bug. `acceptable` turns a run record
into fixed reason codes.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy import PolicyError

SANDBOX_VERSION = "atlas-anchor-sandbox/1"
TARGETS = {"candidate": "/candidate", "child": "/child", "evidence": "/evidence"}
UNPRIVILEGED_GID = 65534
MOUNT_BREAKERS = (",", "\n", "\r", '"')
EVIDENCE_FILE = "/evidence/evidence.json"
IMAGE_ID = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

_VALUE_OPTIONS = frozenset(
    {
        "--name",
        "--pull",
        "--network",
        "--user",
        "--cap-drop",
        "--security-opt",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--ulimit",
        "--tmpfs",
        "--mount",
        "--workdir",
        "--hostname",
        "--entrypoint",
        "--log-driver",
        "--ipc",
    }
)
_FLAG_OPTIONS = frozenset({"--rm", "--read-only"})


@dataclass(frozen=True)
class Layout:
    """The three host directories the container may see, and nothing else."""

    candidate: Path
    child: Path
    evidence: Path

    def as_record(self) -> dict[str, str]:
        return {
            "candidate": str(self.candidate),
            "child": str(self.child),
            "evidence": str(self.evidence),
        }


# --------------------------------------------------------------------------
# building and auditing the argument vector
# --------------------------------------------------------------------------


def build_argv(
    policy: Mapping[str, Any],
    *,
    docker: Sequence[str],
    name: str,
    uid: int,
    gid: int,
    layout: Layout,
    candidate: str,
    tree: str,
    manifest: str,
) -> list[str]:
    """The whole `docker run` command. Every property the box has is spelled here."""
    box = policy["sandbox"]
    memory = f"{box['memory_mb']}m"
    if any(
        character in str(path)
        for path in (layout.candidate, layout.child, layout.evidence)
        for character in MOUNT_BREAKERS
    ):
        # `--mount` is a CSV field: a comma ends the source and begins an option of the
        # caller's choosing, and a quote or a line break makes the parser read only part
        # of the value - which could silently drop the trailing `readonly`.
        raise PolicyError("a sandbox directory path contains a character that ends a mount field")
    return [
        *docker,
        "run",
        "--rm",
        "--name",
        name,
        "--pull",
        "never",
        "--network",
        "none",
        "--ipc",
        "none",
        "--user",
        f"{uid}:{gid}",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(box["pids_limit"]),
        "--memory",
        memory,
        "--memory-swap",
        memory,
        "--cpus",
        str(box["cpus"]),
        "--ulimit",
        f"fsize={box['max_file_bytes']}",
        "--ulimit",
        "nofile=256",
        "--ulimit",
        "core=0",
        "--log-driver",
        "none",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={box['tmpfs_mb']}m",
        "--mount",
        f"type=bind,source={layout.candidate},target={TARGETS['candidate']},readonly",
        "--mount",
        f"type=bind,source={layout.child},target={TARGETS['child']},readonly",
        "--mount",
        f"type=bind,source={layout.evidence},target={TARGETS['evidence']}",
        "--workdir",
        "/tmp",
        "--hostname",
        "anchor-child",
        "--entrypoint",
        "python3",
        box["image"],
        "-I",
        "-S",
        "-B",
        f"{TARGETS['child']}/runner.py",
        "--policy",
        f"{TARGETS['child']}/policy.json",
        "--root",
        TARGETS["candidate"],
        "--evidence",
        EVIDENCE_FILE,
        "--candidate",
        candidate,
        "--tree",
        tree,
        f"--inputs-manifest={manifest}",
    ]


def _split_run(
    argv: Sequence[str],
) -> tuple[list[str], dict[str, list[str]], set[str], str | None, list[str], list[str]]:
    """The client prefix, options (with values), bare flags, the image, the command, problems."""
    problems: list[str] = []
    try:
        start = list(argv).index("run") + 1
    except ValueError:
        return [], {}, set(), None, [], ["SANDBOX_NOT_A_RUN"]
    prefix = list(argv)[: start - 1]
    options: dict[str, list[str]] = {}
    flags: set[str] = set()
    index = start
    while index < len(argv):
        token = argv[index]
        if token in _VALUE_OPTIONS:
            if index + 1 >= len(argv):
                problems.append("SANDBOX_MALFORMED_OPTION")
                break
            options.setdefault(token, []).append(argv[index + 1])
            index += 2
        elif token in _FLAG_OPTIONS:
            flags.add(token)
            index += 1
        elif token.startswith("-"):
            problems.append("SANDBOX_UNKNOWN_OPTION")
            index += 1
        else:
            return prefix, options, flags, token, list(argv[index + 1 :]), problems
    return prefix, options, flags, None, [], problems + ["SANDBOX_NO_IMAGE"]


def _single(options: Mapping[str, list[str]], name: str) -> str | None:
    values = options.get(name, [])
    return values[0] if len(values) == 1 else None


def _parse_mount(mount: str) -> tuple[dict[str, str], bool]:
    fields: dict[str, str] = {}
    readonly = False
    malformed = False
    for part in mount.split(","):
        key, separator, value = part.partition("=")
        if separator:
            fields[key] = value
        elif key in {"readonly", "ro"}:
            readonly = True
        else:
            malformed = True
    return fields, readonly and not malformed


_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")


def _reaches_docker_socket(source: str) -> bool:
    """A mount of the socket, or of any directory that contains it (`/`, `/var`, `/run`)."""
    trimmed = source.rstrip("/") or "/"
    return any(socket == trimmed or socket.startswith(trimmed.rstrip("/") + "/") for socket in _SOCKETS)


def _audit_mounts(options: Mapping[str, list[str]], layout: Mapping[str, str]) -> list[str]:
    problems: list[str] = []
    mounts = options.get("--mount", [])
    seen: dict[str, tuple[dict[str, str], bool]] = {}
    for mount in mounts:
        if any(character in mount for character in MOUNT_BREAKERS[1:]):
            return ["SANDBOX_MOUNT_MALFORMED"]
        fields, readonly = _parse_mount(mount)
        seen[fields.get("target", "")] = (fields, readonly)
    if sorted(seen) != sorted(TARGETS.values()) or len(mounts) != len(TARGETS):
        return ["SANDBOX_MOUNT_TARGETS"]
    for role, target in TARGETS.items():
        fields, readonly = seen[target]
        if _reaches_docker_socket(fields.get("source", "")):
            problems.append("SANDBOX_DOCKER_SOCKET")
        if fields.get("type") != "bind" or set(fields) - {"type", "source", "target"}:
            problems.append("SANDBOX_MOUNT_MALFORMED")
        if fields.get("source") != layout.get(role):
            problems.append("SANDBOX_MOUNT_SOURCE")
        if role != "evidence" and not readonly:
            problems.append("SANDBOX_MOUNT_WRITABLE")
        if role == "evidence" and readonly:
            problems.append("SANDBOX_MOUNT_MALFORMED")
    return problems


FULL_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
_NAME = re.compile(r"\A[A-Za-z0-9_.-]{1,64}\Z")
_COMMAND_HEAD = [
    "-I",
    "-S",
    "-B",
    f"{TARGETS['child']}/runner.py",
    "--policy",
    f"{TARGETS['child']}/policy.json",
    "--root",
    TARGETS["candidate"],
    "--evidence",
    EVIDENCE_FILE,
]


def _audit_command(
    command: Sequence[str], candidate: str | None, tree: str | None
) -> list[str]:
    """The child's command line, in full. Nothing after the image is left unread.

    Every element is fixed except three: which commit, which tree, and the
    caller's manifest - and each of those is checked for its SHAPE, and for its
    VALUE where the verifier knows what it should be.
    """
    if len(command) != len(_COMMAND_HEAD) + 5 or list(command[: len(_COMMAND_HEAD)]) != _COMMAND_HEAD:
        return ["SANDBOX_COMMAND"]
    tail = list(command[len(_COMMAND_HEAD) :])
    problems = []
    if tail[0] != "--candidate" or tail[2] != "--tree" or not tail[4].startswith("--inputs-manifest="):
        return ["SANDBOX_COMMAND"]
    if not FULL_SHA.match(tail[1]) or not FULL_SHA.match(tail[3]):
        problems.append("SANDBOX_COMMAND")
    if candidate is not None and tail[1] != candidate:
        problems.append("SANDBOX_COMMAND")
    if tree is not None and tail[3] != tree:
        problems.append("SANDBOX_COMMAND")
    return problems


def audit_argv(
    argv: Sequence[str],
    policy: Mapping[str, Any],
    layout: Mapping[str, str],
    docker: Sequence[str] = ("docker",),
    candidate: str | None = None,
    tree: str | None = None,
) -> list[str]:
    """Fixed codes for every required property this command does not have.

    Independent of `build_argv`: it reads the command as a docker client would and
    checks properties, rather than comparing with what the builder meant to write.
    Any option it does not recognise is a problem, so `--privileged`, `--cap-add`,
    `--device`, `-v`, `--env`, `--pid` and their relatives are refused by not
    being on the list rather than by being on a blacklist.

    Two places a hostile edit could hide are closed explicitly. Everything BEFORE
    `run` is the docker client's own options - `-H tcp://...`, `--context` - which
    choose which daemon runs the box, so the prefix must be exactly the expected
    client and nothing else. And every option that takes a value must have EXACTLY
    the value required: a later `--ulimit fsize=-1` must not be able to override an
    earlier correct one just because the earlier one is still present.
    """
    box = policy["sandbox"]
    prefix, options, flags, image, command, problems = _split_run(argv)

    if prefix != list(docker):
        problems.append("SANDBOX_DOCKER_PREFIX")
    # Only where it could be an argument to the CLIENT: the candidate's own manifest,
    # after the image, may legitimately be any text, and naming a socket there mounts
    # nothing.
    client_side = list(argv)[: len(argv) - len(command)]
    if any("docker.sock" in token for token in client_side):
        problems.append("SANDBOX_DOCKER_SOCKET")
    if _single(options, "--network") != "none":
        problems.append("SANDBOX_NETWORK")
    if _single(options, "--ipc") != "none":
        problems.append("SANDBOX_IPC")
    if _single(options, "--pull") != "never":
        problems.append("SANDBOX_PULL")

    match = re.fullmatch(r"([0-9]+):([0-9]+)", _single(options, "--user") or "")
    if not match or int(match.group(1)) == 0 or int(match.group(2)) != UNPRIVILEGED_GID:
        # The group is pinned, not merely non-zero: on a hosted runner the runner user's
        # own primary group can be `docker`, and a member of it can use the socket.
        problems.append("SANDBOX_USER")
    if "--read-only" not in flags:
        problems.append("SANDBOX_WRITABLE_ROOT")
    if "--rm" not in flags:
        problems.append("SANDBOX_NOT_EPHEMERAL")
    if options.get("--cap-drop") != ["ALL"]:
        problems.append("SANDBOX_CAPABILITIES")
    if options.get("--security-opt") != ["no-new-privileges"]:
        problems.append("SANDBOX_SECURITY_OPT")

    memory = f"{box['memory_mb']}m"
    if _single(options, "--pids-limit") != str(box["pids_limit"]):
        problems.append("SANDBOX_PIDS")
    if _single(options, "--memory") != memory or _single(options, "--memory-swap") != memory:
        problems.append("SANDBOX_MEMORY")
    if _single(options, "--cpus") != str(box["cpus"]):
        problems.append("SANDBOX_CPUS")
    if options.get("--ulimit") != [f"fsize={box['max_file_bytes']}", "nofile=256", "core=0"]:
        problems.append("SANDBOX_FILE_SIZE")
    if _single(options, "--log-driver") != "none":
        problems.append("SANDBOX_LOG_DRIVER")
    if _single(options, "--workdir") != "/tmp":
        problems.append("SANDBOX_WORKDIR")
    if _single(options, "--hostname") != "anchor-child":
        problems.append("SANDBOX_HOSTNAME")
    if not _NAME.match(_single(options, "--name") or ""):
        problems.append("SANDBOX_NAME")

    tmpfs = options.get("--tmpfs", [])
    if len(tmpfs) != 1 or not re.fullmatch(
        rf"/tmp:rw,noexec,nosuid,nodev,size={box['tmpfs_mb']}m", tmpfs[0]
    ):
        problems.append("SANDBOX_TMPFS")
    if _single(options, "--entrypoint") != "python3":
        problems.append("SANDBOX_ENTRYPOINT")
    if image != box["image"]:
        problems.append("SANDBOX_IMAGE")
    problems.extend(_audit_command(command, candidate, tree))
    problems.extend(_audit_mounts(options, layout))
    return list(dict.fromkeys(problems))


def acceptable(
    record: Any,
    policy: Mapping[str, Any],
    docker: Sequence[str] = ("docker",),
    candidate: str | None = None,
    tree: str | None = None,
) -> list[str]:
    """Fixed codes for why this record does not describe a clean, hardened run."""
    if not isinstance(record, dict) or record.get("sandbox_version") != SANDBOX_VERSION:
        return ["SANDBOX_RECORD_INVALID"]
    layout = record.get("layout")
    argv = record.get("argv")
    if (
        not isinstance(layout, dict)
        or not isinstance(argv, list)
        or not all(isinstance(token, str) for token in argv)
    ):
        return ["SANDBOX_RECORD_INVALID"]
    reasons = audit_argv(argv, policy, layout, docker, candidate, tree)

    if record.get("pull_ok") is not True or not IMAGE_ID.match(str(record.get("image_id"))):
        reasons.append("SANDBOX_IMAGE_UNAVAILABLE")
    if record.get("image") != policy["sandbox"]["image"]:
        reasons.append("SANDBOX_IMAGE")
    if record.get("started") is not True:
        reasons.append("SANDBOX_NOT_STARTED")
    if record.get("timed_out") is not False:
        reasons.append("SANDBOX_TIMEOUT")
    if record.get("output_exceeded") is not False:
        reasons.append("SANDBOX_OUTPUT_LIMIT")
    exit_code = record.get("exit_code")
    # False == 0 and 0.0 == 0 in Python, so equality alone would read a boolean or a
    # float as a clean exit. Only an actual integer zero is one.
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code != 0:
        reasons.append("SANDBOX_EXIT_NONZERO")
    return list(dict.fromkeys(reasons))


def public_digest_of(record: Mapping[str, Any]) -> str:
    """A digest of the record that says nothing about the caller's manifest.

    The record's argv carries `--inputs-manifest=<the caller's paths>`. A hash of a
    structure that contains text a guesser can enumerate is an oracle for it, so the
    published digest is taken over a copy in which that one token is replaced.
    """
    redacted = dict(record)
    argv = record.get("argv")
    if isinstance(argv, list):
        redacted["argv"] = [
            "--inputs-manifest=<redacted>" if isinstance(t, str) and t.startswith("--inputs-manifest=") else t
            for t in argv
        ]
    return digest_of(redacted)


def digest_of(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

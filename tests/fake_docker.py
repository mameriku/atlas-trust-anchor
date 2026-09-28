"""A stand-in for `docker`, for tests that must not need a container runtime.

It speaks just enough of the CLI for sandbox.py: `pull`, `image inspect`, `rm`,
and `run`. For `run` it does two things a real runtime would not let a test do:

  * it RECORDS everything it was handed - the client's environment, the full
    argument vector, the mount table - to a report file the test reads back, so
    "the candidate saw no credential" is checked against what was actually passed
    rather than against what the code intended to pass
  * it runs the child as an ordinary process under a scrubbed environment, with
    container paths (/candidate, /child, /evidence) mapped to the host directories
    named in the argument vector

It models mount semantics from the argument vector itself: a hostile child that
writes through `attempt_write` is refused unless the target mount is present and
not read-only. That does not prove a kernel enforces anything - nothing here is
evidence about Docker or Linux - but it does make the test fail if the anchor
stops asking for a read-only mount, drops a mount, or adds one.

Configuration is passed as `--config <path>` before the docker subcommand, because
the anchor starts docker with an allow-listed environment and no test flag could
reach it that way.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

IMAGE_ID = "sha256:" + "a" * 64
_VALUE_OPTIONS = {
    "--name", "--pull", "--network", "--user", "--cap-drop", "--security-opt",
    "--pids-limit", "--memory", "--memory-swap", "--cpus", "--ulimit", "--tmpfs",
    "--mount", "--workdir", "--hostname", "--entrypoint", "--log-driver", "--ipc",
    "-e", "--env", "-v", "--volume", "--device", "--cap-add", "--pid", "--net",
}

# Defined inside a hostile child: how it "writes" under the modelled mounts.
PRELUDE = '''
import json, os, sys
MOUNTS = json.loads(os.environ["FAKE_MOUNTS"])
RESULTS = {}

def host_path(container_path):
    for target, mount in MOUNTS.items():
        if container_path == target or container_path.startswith(target + "/"):
            return mount, mount["source"] + container_path[len(target):]
    return None, None

def attempt_write(container_path, data=b"x"):
    mount, host = host_path(container_path)
    if mount is None:
        RESULTS[container_path] = "denied:not-mounted"
        return False
    if mount["readonly"]:
        RESULTS[container_path] = "denied:read-only"
        return False
    os.makedirs(os.path.dirname(host), exist_ok=True)
    with open(host, "wb") as handle:
        handle.write(data)
    RESULTS[container_path] = "written"
    return True

def read_container(container_path):
    mount, host = host_path(container_path)
    if mount is None:
        return None
    with open(host, "rb") as handle:
        return handle.read()

def finish():
    print("FAKE_RESULTS " + json.dumps(RESULTS))
'''


def _parse_run(arguments: list[str]):
    options: dict[str, list[str]] = {}
    flags: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in _VALUE_OPTIONS:
            options.setdefault(token, []).append(arguments[index + 1])
            index += 2
        elif token.startswith("-"):
            flags.append(token)
            index += 1
        else:
            return options, flags, token, arguments[index + 1 :]
    return options, flags, None, []


def _mounts(options: dict[str, list[str]]) -> dict[str, dict]:
    table = {}
    for mount in options.get("--mount", []):
        fields = {}
        readonly = False
        for part in mount.split(","):
            key, separator, value = part.partition("=")
            if separator:
                fields[key] = value
            elif key in {"readonly", "ro"}:
                readonly = True
        table[fields["target"]] = {"source": fields["source"], "readonly": readonly}
    return table


def _substitute(token: str, mounts: dict[str, dict]) -> str:
    for target, mount in mounts.items():
        if token == target or token.startswith(target + "/"):
            return mount["source"] + token[len(target):]
    return token


def _child_environment() -> dict[str, str]:
    """What a container would give the child: a path and nothing that was exported."""
    environment = {"PATH": os.environ.get("PATH", os.defpath)}
    for name in ("SYSTEMROOT", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _record(config: dict, entry: dict) -> None:
    report = config.get("report")
    if report:
        with open(report, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")


def _run(config: dict, arguments: list[str]) -> int:
    options, flags, image, command = _parse_run(arguments)
    mounts = _mounts(options)
    environment = _child_environment()
    _record(
        config,
        {
            "kind": "run",
            "client_environment": dict(os.environ),
            "argv": arguments,
            "flags": flags,
            "options": options,
            "image": image,
            "mounts": mounts,
            "child_environment": environment,
            "command": command,
        },
    )

    mode = config.get("mode", "honest")
    if mode == "honest":
        child = [sys.executable, *[_substitute(token, mounts) for token in command]]
        completed = subprocess.run(child, capture_output=True, env=environment, check=False)
    elif mode == "script":
        environment["FAKE_MOUNTS"] = json.dumps(mounts)
        completed = subprocess.run(
            [sys.executable, "-B", "-c", PRELUDE + config["script"]],
            capture_output=True,
            env=environment,
            check=False,
        )
    elif mode == "flood":
        sys.stdout.buffer.write(b"x" * int(config.get("bytes", 1 << 20)))
        sys.stdout.flush()
        return 0
    elif mode == "hang":
        import time

        time.sleep(600)
        return 0
    else:
        return 125
    _record(config, {"kind": "child-output", "stdout": completed.stdout.decode("utf-8", "replace"),
                     "stderr": completed.stderr.decode("utf-8", "replace"), "returncode": completed.returncode})
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    return completed.returncode


def main(argv: list[str]) -> int:
    config: dict = {}
    if argv[:1] == ["--config"]:
        config = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        argv = argv[2:]
    command = argv[0] if argv else ""
    _record(config, {"kind": command, "client_environment": dict(os.environ), "argv": argv})
    if command == "pull":
        return 1 if config.get("pull_fails") else 0
    if command == "image":
        print(config.get("image_id", IMAGE_ID))
        return 0
    if command == "rm":
        return 0
    if command == "run":
        return _run(config, argv[1:])
    return 125


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

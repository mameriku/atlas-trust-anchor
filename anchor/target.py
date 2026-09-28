"""Get exactly one commit of the private target, and give the credential back.

The credential is a read-only deploy key for the target repository alone. It has
no authority over this anchor, no write authority anywhere, and no use except the
single `git fetch` below. The properties this module exists to hold:

  * it is read from ONE environment variable, set on ONE workflow step - never a
    job-wide or workflow-wide variable
  * it lives on disk for the duration of one fetch, mode 0600, outside the
    workspace, and is overwritten and removed in a `finally`
  * git is started with a rebuilt environment that does not contain it, or the
    governance token, or the GitHub token: the key reaches git only as a file
    named in GIT_SSH_COMMAND
  * the server is authenticated against a host key pinned in policy, not trusted
    on first use; a host that does not match is a refusal
  * afterwards the fetched repository's config is audited for anything that would
    let a later process authenticate as the anchor, and refused if it finds any

Nothing here executes target-controlled code: no checkout, so no hooks and no
filters; no submodules; objects are fsck'd on the way in. The result is an object
store, read later only through plumbing commands.

Every failure is a `publog.TargetError` with a fixed code. Git's own stderr can
quote a path or a ref from the private repository, and is never surfaced.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

from publog import TargetError  # noqa: E402

_GIT_TIMEOUT_SECONDS = 300
_MAX_KEY_BYTES = 8192
_KEY_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
_KEY_FOOTER = "-----END OPENSSH PRIVATE KEY-----"
_FULL_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
_PERSISTED = re.compile(
    r"(sshcommand|credential|extraheader|insteadof|pushurl|\burl\b|BEGIN OPENSSH|"
    r"\binclude|askpass|cookiefile|proxy|sslcainfo)",
    re.IGNORECASE
)


def ssh_url(policy: Mapping[str, Any]) -> str:
    return f"git@github.com:{policy['target']['repository']}.git"


def assert_source(policy: Mapping[str, Any], source: str | None) -> str:
    """The URL to fetch from: the target's ssh address, or a local file for tests.

    A `file://` source is what the test suite fetches from. It cannot carry the
    deploy key anywhere, because ssh is not involved, and it is refused in any
    other form so that this argument cannot redirect a real fetch.
    """
    if source is None:
        return ssh_url(policy)
    if source == ssh_url(policy) or source.startswith("file://"):
        return source
    raise TargetError("TARGET_SOURCE_REFUSED", "a source that is neither the target nor a file")


def _key_problem(key: str | None) -> str | None:
    if not key or not key.strip():
        return "CREDENTIAL_MISSING"
    stripped = key.strip()
    if (
        len(stripped) > _MAX_KEY_BYTES
        or not stripped.startswith(_KEY_HEADER)
        or not stripped.endswith(_KEY_FOOTER)
    ):
        return "CREDENTIAL_MALFORMED"
    return None


def git_environment(
    home: Path, parent: Mapping[str, str], ssh_command: str | None = None
) -> dict[str, str]:
    """A rebuilt environment for git. Nothing is inherited that is not named here."""
    environment = {
        "PATH": parent.get("PATH", os.defpath),
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ASKPASS": "",
        "LC_ALL": "C",
    }
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"):
        if name in parent:
            environment[name] = parent[name]
    if ssh_command is not None:
        environment["GIT_SSH_COMMAND"] = ssh_command
    return environment


def run_git(
    environment: Mapping[str, str],
    repository: Path | None,
    *arguments: str,
    code: str = "TARGET_GIT_FAILED",
) -> bytes:
    """One git command. Its stderr is captured and dropped; failure is a fixed code."""
    command = ["git"]
    if repository is not None:
        command += ["-C", str(repository)]
    try:
        completed = subprocess.run(  # noqa: S603 - argv, never a shell string
            command + list(arguments),
            capture_output=True,
            check=False,
            env=dict(environment),
            timeout=_GIT_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TargetError(code, type(error).__name__) from None
    if completed.returncode != 0:
        raise TargetError(code, "git exited non-zero")
    return completed.stdout


def _ssh_command(key: Path, known_hosts: Path) -> str:
    options = [
        "ssh",
        "-F",
        os.devnull,
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        f"GlobalKnownHostsFile={os.devnull}",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
    ]
    return " ".join(shlex.quote(part) for part in options)


def _destroy(path: Path) -> None:
    """Overwrite, then remove. Best effort by design: the runner is ephemeral too."""
    try:
        size = path.stat().st_size
        with path.open("r+b") as handle:
            handle.write(b"\0" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


def _write_private(path: Path, payload: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)


def audit_repository_config(repository: Path) -> None:
    """Refuse a fetched repository whose config could authenticate anyone later."""
    try:
        text = (repository / ".git" / "config").read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise TargetError("CREDENTIAL_PERSISTED", "config unreadable") from None
    if _PERSISTED.search(text):
        raise TargetError(
            "CREDENTIAL_PERSISTED", "the fetched repository's config names a remote or a credential"
        )


def fetch_candidate(
    policy: Mapping[str, Any],
    environ: Mapping[str, str],
    candidate: str,
    workdir: Path,
    source: str | None = None,
) -> Path:
    """The target's object store at exactly `candidate`, with no credential left behind."""
    if not _FULL_SHA.match(candidate):
        raise TargetError("TARGET_SHA_INVALID", "not a full sha")
    url = assert_source(policy, source)
    secret_name = policy["credential"]["secret"]
    key_problem = _key_problem(environ.get(secret_name))
    if key_problem and not url.startswith("file://"):
        raise TargetError(key_problem, "no usable deploy key")

    ssh_dir = workdir / "ssh"
    home = workdir / "home"
    repository = workdir / "repo"
    for directory in (ssh_dir, home):
        directory.mkdir(parents=True, exist_ok=False)
        os.chmod(directory, 0o700)

    key_path = ssh_dir / "id_ed25519"
    known_hosts = ssh_dir / "known_hosts"
    _write_private(known_hosts, f"github.com {policy['credential']['host_key']}\n")

    ssh_command = None
    try:
        if key_problem is None:
            _write_private(key_path, environ[secret_name].strip() + "\n")
            ssh_command = _ssh_command(key_path, known_hosts)

        environment = git_environment(home, environ, ssh_command)
        run_git(environment, None, "init", "--quiet", str(repository), code="TARGET_INIT_FAILED")
        run_git(environment, repository, "remote", "add", "origin", url, code="TARGET_INIT_FAILED")
        run_git(
            environment,
            repository,
            "-c",
            "transfer.fsckObjects=true",
            "-c",
            "protocol.version=2",
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--depth",
            "1",
            "origin",
            candidate,
            code="TARGET_FETCH_FAILED",
        )
    finally:
        # The credential is gone before anything else is done with the repository.
        _destroy(key_path)
        shutil.rmtree(ssh_dir, ignore_errors=True)

    clean = git_environment(home, environ)
    resolved = (
        run_git(
            clean,
            repository,
            "rev-parse",
            "--verify",
            f"{candidate}^{{commit}}",
            code="TARGET_IDENTITY_MISMATCH",
        )
        .decode("ascii", errors="replace")
        .strip()
    )
    if resolved != candidate:
        raise TargetError("TARGET_IDENTITY_MISMATCH", "fetched a different commit")

    run_git(clean, repository, "remote", "remove", "origin", code="TARGET_INIT_FAILED")
    audit_repository_config(repository)
    return repository

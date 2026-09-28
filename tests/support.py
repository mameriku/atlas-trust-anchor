"""Shared helpers for the anchor suite.

Everything here is synthetic. There is no network, no real credential, no real
private repository, and no real container runtime: the box is exercised through a
stand-in `docker` (tests/fake_docker.py) that runs the child as a plain process
under a scrubbed environment and records exactly what it was handed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANCHOR = ROOT / "anchor"
TESTS = ROOT / "tests"
WORKFLOW = ROOT / ".github" / "workflows" / "qualify.yml"
TEST_WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
FAKE_DOCKER = TESTS / "fake_docker.py"

if str(ANCHOR) not in sys.path:
    sys.path.insert(0, str(ANCHOR))

import governance as governance_module  # noqa: E402
import policy as policy_module  # noqa: E402

ANCHOR_ID = 987654321
TARGET_ID = 1311516591
ANCHOR_REPO = "mameriku/atlas-trust-anchor"
WORKFLOW_REF = f"{ANCHOR_REPO}/.github/workflows/qualify.yml@refs/heads/main"
SHA_A = "a" * 40
SHA_B = "b" * 40
ALPHA, BETA, GAMMA = "src/alpha.py", "src/beta.py", "src/gamma.py"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
IMAGE = "python:3.12-slim-bookworm@sha256:" + "1" * 64
IMAGE_ID = "sha256:" + "a" * 64
FAKE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "SYNTHETIC-DEPLOY-KEY-c2ec4f8a91d34b7ea06f5d28\n"
    "-----END OPENSSH PRIVATE KEY-----"
)
FAKE_GOVERNANCE_TOKEN = "SYNTHETIC-GOVERNANCE-TOKEN-91b7d3c0e5a84f26"
FAKE_GITHUB_TOKEN = "SYNTHETIC-GITHUB-TOKEN-5e1f0a7c2d9b4863"


def governed_observation(**overrides: object) -> dict:
    """What a properly protected anchor looks like when it is asked."""
    observation: dict = {
        "governance_version": governance_module.GOVERNANCE_VERSION,
        "repository": ANCHOR_REPO,
        "repository_id": ANCHOR_ID,
        "repository_private": False,
        "default_branch": "main",
        "ref": "refs/heads/main",
        "rules_in_force": [
            "deletion",
            "non_fast_forward",
            "pull_request",
            "required_status_checks",
        ],
        "rulesets": [
            {
                "id": 1,
                "name": "anchor",
                "enforcement": "active",
                "bypass_actor_count": 0,
                "target": "branch",
            }
        ],
        "observed_approvals": 1,
        "dismiss_stale_reviews": True,
        "last_push_approval": True,
        "strict_status_checks": True,
        "status_check_contexts": ["test"],
        "credential_only_in_environment": True,
        "environment": {
            "name": "atlas-qualification",
            "deployment_branches": ["main"],
            "admins_can_bypass": False,
        },
    }
    observation.update(overrides)
    observation["observation_digest"] = governance_module._digest(observation)
    return observation


def policy_document(floor: list[str] | None = None, **overrides: object) -> dict:
    document: dict[str, object] = {
        "policy_version": "atlas-anchor-policy/2",
        "anchor": {
            "repository": ANCHOR_REPO,
            "repository_id": ANCHOR_ID,
            "workflow_ref": WORKFLOW_REF,
            "ref": "refs/heads/main",
            "visibility": "public",
        },
        "target": {
            "repository": "mameriku/atlas",
            "repository_id": TARGET_ID,
            "visibility": "private",
        },
        "trigger": {"event": "workflow_dispatch", "actors": ["mameriku"]},
        "credential": {
            "kind": "deploy-key",
            "environment": "atlas-qualification",
            "secret": "ATLAS_DEPLOY_KEY",
            "host_key": HOST_KEY,
        },
        "sandbox": {
            "image": IMAGE,
            "timeout_seconds": 20,
            "memory_mb": 256,
            "cpus": 1,
            "pids_limit": 64,
            "max_output_bytes": 4096,
            "max_file_bytes": 1048576,
            "tmpfs_mb": 8,
        },
        "required_inputs_floor": floor or ["scripts/one.py", "scripts/two.py"],
        "limits": {"max_evidence_bytes": 65536, "max_observations": 512, "max_input_bytes": 1048576},
        "disclosure": {"private_transport": "none", "publish_floor_digests": True},
        "governance": {
            "required_ref": "refs/heads/main",
            "required_rules": ["deletion", "non_fast_forward", "pull_request", "required_status_checks"],
            "required_approvals": 1,
            "require_last_push_approval": True,
            "require_dismiss_stale_reviews": True,
            "require_empty_bypass": True,
            "required_status_checks": ["test"],
            "required_status_check_integration_id": 15368,
            "environment": {
                "name": "atlas-qualification",
                "deployment_branches": ["main"],
                "environment_only_secrets": ["ATLAS_DEPLOY_KEY", "ANCHOR_GOVERNANCE_TOKEN"],
            },
        },
    }
    document.update(overrides)
    return document


def make_policy(tmp_path: Path, floor: list[str] | None = None, **overrides: object) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy_document(floor, **overrides)), encoding="utf-8")
    return path


def good_environment(**overrides: str) -> dict[str, str]:
    environment = {
        "GITHUB_REPOSITORY_ID": str(ANCHOR_ID),
        "GITHUB_REPOSITORY": ANCHOR_REPO,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_SHA": SHA_A,
        "GITHUB_SHA": SHA_A,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_ACTOR": "mameriku",
        "GITHUB_TRIGGERING_ACTOR": "mameriku",
        "GITHUB_RUN_ID": "4242",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    environment.update(overrides)
    return environment


def run_entry(script: str, *arguments: str, env: dict[str, str] | None = None, cwd=None):
    """A trusted entry point, started the way the workflow starts it."""
    environment = dict(os.environ)
    environment.update(env or {})
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(ANCHOR / script), *arguments],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
        cwd=cwd,
    )


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, text=True, check=True
    ).stdout.strip()


def make_candidate(
    root: Path, files: dict[str, str] | None = None, message: str = "candidate"
) -> str:
    """A throwaway Atlas-like repository. It contains no anchor authority at all."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    _git(root, "config", "user.email", "candidate@test")
    _git(root, "config", "user.name", "candidate")
    _git(root, "config", "core.autocrlf", "false")
    contents = files or {ALPHA: "A = 1\n", BETA: "B = 2\n", GAMMA: "G = 3\n"}
    for relative_path, body in contents.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body.encode("utf-8"))
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_bytes(directory: Path) -> dict[str, bytes]:
    """Every file under a directory, by relative path - what a process could read."""
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }

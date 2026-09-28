"""The `qualify` job, replayed step by step with the real entry points.

The workflow is YAML and cannot be executed in a test, but everything it does is a
command line over a handful of directories. This replays those command lines in
the same order, under the same `-I -S -B`, over a synthetic private candidate,
with a stand-in `docker`. It exists so that "no private byte reaches a public
surface" can be tested against what the entry points actually produced - the
console, the verdict, every file in the public directory - and not against a
reading of the source.

Secrets are synthetic. By default each is set only where the workflow sets it (the
deploy key on the capture step alone). `leak_everywhere=True` sets all of them on
every step, modelling a workflow mistake, to show the anchor's own boundaries hold
even then.
"""

from __future__ import annotations

import json
import shutil
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from support import (
    ANCHOR,
    FAKE_DOCKER,
    FAKE_GITHUB_TOKEN,
    FAKE_GOVERNANCE_TOKEN,
    FAKE_KEY,
    good_environment,
    governed_observation,
    make_candidate,
    make_policy,
    run_entry,
)


@dataclass
class Run:
    root: Path
    private: Path
    sandbox: Path
    public: Path
    policy: Path
    candidate: str
    manifest: str
    docker_report: Path
    outputs: Path
    steps: dict = field(default_factory=dict)

    @property
    def console(self) -> str:
        """Everything every step wrote to stdout or stderr - the whole public log."""
        return "\n".join(
            f"{name}\n{process.stdout}\n{process.stderr}" for name, process in self.steps.items()
        )

    @property
    def verdict(self) -> dict | None:
        path = self.public / "verdict.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    def report(self) -> list[dict]:
        if not self.docker_report.is_file():
            return []
        return [
            json.loads(line)
            for line in self.docker_report.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def output(self, name: str) -> str | None:
        for line in self.outputs.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key == name:
                return value
        return None


def _seal_archive(destination: Path) -> None:
    with tarfile.open(destination, "w") as archive:
        payload = ANCHOR / "policy.json"
        archive.add(payload, arcname="anchor/policy.json")


def run_pipeline(
    tmp_path: Path,
    files: dict[str, str] | None = None,
    *,
    message: str = "candidate",
    manifest: str = "",
    floor: list[str] | None = None,
    docker_config: dict | None = None,
    leak_everywhere: bool = False,
    policy_overrides: dict | None = None,
    candidate: str | None = None,
) -> Run:
    repository = tmp_path / "private-source"
    sha = make_candidate(repository, files, message)
    candidate = sha if candidate is None else candidate

    root = tmp_path / "runner"
    private = root / "anchor-private"
    sandbox = root / "anchor-sandbox"
    public = root / "public"
    for directory in (private, private / "fetch", sandbox, public):
        directory.mkdir(parents=True, exist_ok=True)

    default_floor = floor or (list(files) if files else ["src/alpha.py", "src/beta.py", "src/gamma.py"])
    policy = make_policy(root, floor=default_floor, **(policy_overrides or {}))
    (private / "governance.json").write_text(
        json.dumps(governed_observation()), encoding="utf-8"
    )
    report = root / "docker-report.jsonl"
    config = root / "docker-config.json"
    config.write_text(json.dumps({**(docker_config or {}), "report": str(report)}), encoding="utf-8")
    outputs = root / "outputs.txt"
    outputs.write_text("", encoding="utf-8")
    _seal_archive(public / "anchor-tree.tar")

    base = good_environment(GITHUB_OUTPUT=str(outputs))
    secrets = {
        "GITHUB_TOKEN": FAKE_GITHUB_TOKEN,
        "ANCHOR_GOVERNANCE_TOKEN": FAKE_GOVERNANCE_TOKEN,
    }
    capture_env = {**base, **secrets, "ATLAS_DEPLOY_KEY": FAKE_KEY}
    later_env = {**base, **(secrets | {"ATLAS_DEPLOY_KEY": FAKE_KEY} if leak_everywhere else {})}
    docker = json.dumps([sys.executable, str(FAKE_DOCKER), "--config", str(config)])

    run = Run(root, private, sandbox, public, policy, candidate, manifest, report, outputs)
    run.steps["capture"] = run_entry(
        "capture.py",
        "--policy", str(policy),
        "--governance", str(private / "governance.json"),
        f"--candidate={candidate}",
        f"--inputs-manifest={manifest}",
        "--workdir", str(private / "fetch"),
        "--scope-dir", str(sandbox / "candidate"),
        "--capture", str(private / "capture.json"),
        "--source", repository.as_uri(),
        env=capture_env,
    )
    run.steps["sandbox"] = run_entry(
        "sandbox.py",
        "--policy", str(policy),
        "--anchor-code", str(ANCHOR),
        "--capture", str(private / "capture.json"),
        f"--candidate={candidate}",
        f"--inputs-manifest={manifest}",
        "--scope-dir", str(sandbox / "candidate"),
        "--child-dir", str(sandbox / "child"),
        "--evidence-dir", str(sandbox / "evidence"),
        "--record", str(private / "sandbox.json"),
        "--name", "atlas-anchor-4242-1",
        "--docker-command", docker,
        "--uid", "1001",
        "--gid", "65534",
        env=later_env,
    )
    run.steps["verify"] = run_entry(
        "verify.py",
        "--policy", str(policy),
        f"--candidate={candidate}",
        f"--inputs-manifest={manifest}",
        "--capture", str(private / "capture.json"),
        f"--capture-digest={run.output('capture_digest') or '0' * 64}",
        f"--capture-result={'success' if run.steps['capture'].returncode == 0 else 'failure'}",
        "--sandbox-record", str(private / "sandbox.json"),
        "--scope-dir", str(sandbox / "candidate"),
        "--child-dir", str(sandbox / "child"),
        "--docker-command", docker,
        "--evidence-dir", str(sandbox / "evidence"),
        "--verdict", str(public / "verdict.json"),
        "--public-capture", str(public / "public-capture.json"),
        env=later_env,
    )
    shutil.copyfile(policy, public / "policy.json")
    run.steps["seal"] = run_entry(
        "preserve.py", "build",
        "--verdict", str(public / "verdict.json"),
        "--public-capture", str(public / "public-capture.json"),
        "--policy", str(public / "policy.json"),
        "--anchor-archive", str(public / "anchor-tree.tar"),
        "--out", str(public / "evidence.json"),
        env=later_env,
    )
    run.steps["check"] = run_entry("preserve.py", "check", "--package", str(public), env=later_env)
    run.steps["audit"] = run_entry(
        "publish.py", "audit",
        "--public-dir", str(public),
        "--private-dir", str(sandbox / "candidate"),
        "--capture", str(private / "capture.json"),
        "--policy", str(public / "policy.json"),
        env=later_env,
    )
    return run

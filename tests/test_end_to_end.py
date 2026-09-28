"""The whole `qualify` job, replayed: the honest run, and the shapes it must refuse.

These tests drive every entry point in workflow order over a synthetic private
candidate with a stand-in `docker`. The honest run is the only place ACCEPT is
produced, reached the way the workflow reaches it.
"""

from __future__ import annotations

import json

import pytest

from pipeline import run_pipeline
from support import ALPHA, BETA, GAMMA


def test_an_honest_candidate_is_accepted_end_to_end(tmp_path):
    run = run_pipeline(tmp_path)
    for name, process in run.steps.items():
        assert process.returncode == 0, f"{name}: {process.stdout}{process.stderr}"
    verdict = run.verdict
    assert verdict["verdict"] == "ACCEPT"
    assert verdict["reasons"] == []
    assert verdict["candidate_sha"] == run.candidate
    assert verdict["sandbox"]["hardened"] is True
    assert verdict["sandbox"]["exit_code"] == 0
    assert run.output("capture_digest") and "capture_digest" not in verdict
    assert run.output("public_digest")


def test_the_public_directory_is_exactly_the_allow_listed_set(tmp_path):
    run = run_pipeline(tmp_path)
    assert sorted(path.name for path in run.public.iterdir()) == [
        "anchor-tree.tar",
        "evidence.json",
        "policy.json",
        "public-capture.json",
        "verdict.json",
    ]


def test_the_candidate_is_frozen_from_the_object_store_not_the_working_tree(tmp_path):
    run = run_pipeline(tmp_path)
    (tmp_path / "private-source" / ALPHA).write_text("A = 999\n", encoding="utf-8")
    capture = json.loads((run.private / "capture.json").read_text(encoding="utf-8"))
    assert {entry["relative_path"] for entry in capture["inputs"]} == {ALPHA, BETA, GAMMA}


def test_a_candidate_missing_a_floor_input_is_refused_with_a_fixed_code(tmp_path):
    run = run_pipeline(tmp_path, files={ALPHA: "A = 1\n"}, floor=[ALPHA, BETA])
    assert run.steps["verify"].returncode == 1
    assert run.verdict["verdict"] == "REFUSE"
    assert "INPUT_ABSENT" in run.verdict["reasons"]


def test_a_sandbox_that_fails_to_pull_its_image_cannot_be_accepted(tmp_path):
    run = run_pipeline(tmp_path, docker_config={"pull_fails": True})
    assert run.verdict["verdict"] == "REFUSE"
    assert "SANDBOX_IMAGE_UNAVAILABLE" in run.verdict["reasons"]
    assert run.steps["sandbox"].returncode == 2


@pytest.mark.parametrize("candidate", ["abc123", "A" * 40, "z" * 40, ""])
def test_a_malformed_candidate_is_refused_before_anything_is_fetched(tmp_path, candidate):
    run = run_pipeline(tmp_path, candidate=candidate)
    assert run.steps["capture"].returncode == 2
    assert not (run.private / "capture.json").exists()


def test_a_candidate_sha_that_does_not_exist_is_refused_as_a_fetch_failure(tmp_path):
    run = run_pipeline(tmp_path, candidate="f" * 40)
    assert run.steps["capture"].returncode == 2
    assert "TARGET_FETCH_FAILED" in run.steps["capture"].stdout

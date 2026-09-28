"""Each layer of a defence, tested on its own - so removing one layer is noticed.

Mutation testing found predicates whose removal nothing noticed, for three kinds of
reason, and each is fixed here rather than argued away:

* two checks guard a size (the stat, and the length actually read), so either alone
  is redundant. The stat layer exists so a huge file is never read at all; the read
  layer exists because a stat can be stale. Each is tested with the other made
  unable to help.
* symlink refusal is done by lstat as well as by O_NOFOLLOW, and the tests that
  create a real symlink skip on hosts that cannot. These stub lstat, so they run
  everywhere.
* an identity check that only matters for one shape of input (a tag object, whose
  `^{commit}` peels to a different commit) needs that input.
"""

from __future__ import annotations

import copy
import os
import stat

import pytest

from support import ALPHA, FAKE_KEY, _git, make_candidate, make_policy

import capture as capture_module  # noqa: E402
import evidence as evidence_module  # noqa: E402
import governance as governance_module  # noqa: E402
import policy as policy_module  # noqa: E402
import publog  # noqa: E402
import runner as runner_module  # noqa: E402
import target  # noqa: E402
from policy import PolicyError  # noqa: E402
from test_policy_and_governance import ENV, REPO, base_answers, loaded, refused  # noqa: E402
from support import good_environment  # noqa: E402


def stat_result(mode, size=0):
    return os.stat_result((mode, 0, 0, 1, 0, 0, size, 0, 0, 0))


def place_evidence(tmp_path, payload):
    directory = tmp_path / "ev"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "evidence.json").write_bytes(payload)
    return directory


def child_tree(tmp_path, files):
    root = tmp_path / "tree"
    for relative_path, body in files.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    return root


# ==========================================================================
# the evidence reader
# ==========================================================================


def test_a_symlinked_evidence_directory_is_refused_by_lstat_alone(tmp_path, monkeypatch):
    directory = place_evidence(tmp_path, b"{}").resolve()
    real = os.lstat

    def lstat(path, *args, **kwargs):
        if str(path) == str(directory):
            return stat_result(stat.S_IFLNK | 0o777)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(evidence_module.os, "lstat", lstat)
    assert evidence_module.read_directory(directory, 65536).problems == ("EVIDENCE_SYMLINK",)


def test_a_symlinked_evidence_file_is_refused_by_the_directory_scan_alone(tmp_path, monkeypatch):
    class Entry:
        name = evidence_module.FILENAME

        def is_symlink(self):
            return True

        def is_file(self, follow_symlinks=True):
            return follow_symlinks

    class Scan:
        def __enter__(self):
            return iter([Entry()])

        def __exit__(self, *_):
            return False

    directory = place_evidence(tmp_path, b"{}")
    monkeypatch.setattr(evidence_module.os, "scandir", lambda _: Scan())
    result = evidence_module.read_directory(directory, 65536)
    assert result.evidence is None and "EVIDENCE_SYMLINK" in result.problems


def test_an_oversized_file_is_refused_before_a_single_byte_of_it_is_read(tmp_path, monkeypatch):
    """The stat layer exists so that a huge file is never read at all."""
    directory = place_evidence(tmp_path, b'{"p": "' + b"x" * 5000 + b'"}')

    def forbidden(*_):
        raise AssertionError("a read was attempted on a file the stat showed was too big")

    monkeypatch.setattr(evidence_module.os, "read", forbidden)
    assert evidence_module.read_directory(directory, 1024).problems == ("EVIDENCE_OVERSIZED",)


def test_an_oversized_file_is_still_refused_when_its_stat_lies(tmp_path, monkeypatch):
    """The read layer: a file that grew after it was stat'd, or a stat that under-reports."""
    directory = place_evidence(tmp_path, b'{"p": "' + b"x" * 5000 + b'"}')
    real = os.fstat
    monkeypatch.setattr(
        evidence_module.os, "fstat", lambda descriptor: stat_result(real(descriptor).st_mode, size=10)
    )
    assert evidence_module.read_directory(directory, 1024).problems == ("EVIDENCE_OVERSIZED",)


# ==========================================================================
# the child
# ==========================================================================


def test_the_child_refuses_a_symlink_by_lstat_alone_on_any_host(tmp_path, monkeypatch):
    scope = child_tree(tmp_path, {"link.py": b"x = 1\n"})
    real = os.lstat

    def lstat(path, *args, **kwargs):
        if str(path).endswith("link.py"):
            return stat_result(stat.S_IFLNK | 0o777)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(runner_module.os, "lstat", lstat)
    document = runner_module.observe(scope, "a" * 40, "b" * 40, ["link.py"], 1 << 20)
    assert document["inputs_unreadable"] == [{"relative_path": "link.py", "reason": "NOT_REGULAR"}]


def test_the_child_never_reads_a_file_its_stat_shows_is_too_big(tmp_path, monkeypatch):
    scope = child_tree(tmp_path, {ALPHA: b"x" * 500})

    def forbidden(*_):
        raise AssertionError("read attempted")

    monkeypatch.setattr(runner_module.os, "read", forbidden)
    document = runner_module.observe(scope, "a" * 40, "b" * 40, [ALPHA], 50)
    assert document["inputs_unreadable"] == [{"relative_path": ALPHA, "reason": "TOO_LARGE"}]


def test_the_child_still_refuses_a_big_file_when_its_stat_lies(tmp_path, monkeypatch):
    scope = child_tree(tmp_path, {ALPHA: b"x" * 500})
    real = os.fstat
    monkeypatch.setattr(
        runner_module.os, "fstat", lambda descriptor: stat_result(real(descriptor).st_mode, size=3)
    )
    document = runner_module.observe(scope, "a" * 40, "b" * 40, [ALPHA], 50)
    assert document["inputs_unreadable"] == [{"relative_path": ALPHA, "reason": "TOO_LARGE"}]


# ==========================================================================
# an object that is not the commit it points at
# ==========================================================================


def tagged(tmp_path):
    root = tmp_path / "candidate"
    commit = make_candidate(root)
    _git(root, "tag", "-a", "-m", "release", "v1")
    tag_object = _git(root, "rev-parse", "v1")
    assert tag_object != commit
    return root, commit, tag_object


def test_a_tag_object_is_not_the_commit_it_points_at(tmp_path):
    """`git rev-parse <tag-object-id>^{commit}` peels the tag to a commit, so the
    freeze would judge a commit the caller did not name. The identity check is what
    notices, and it must refuse rather than freeze the peeled commit."""
    root, _, tag_object = tagged(tmp_path)
    (tmp_path / "home").mkdir()
    environment = target.git_environment(tmp_path / "home", {"PATH": os.environ["PATH"]})
    with pytest.raises(publog.TargetError) as error:
        capture_module.capture(environment, root, tag_object, [ALPHA], 1 << 20, tmp_path / "scope")
    assert error.value.code == "TARGET_IDENTITY_MISMATCH"


def test_a_fetch_of_a_tag_object_never_yields_a_repository_for_the_commit_it_peels_to(tmp_path):
    root, _, tag_object = tagged(tmp_path)
    workdir = tmp_path / "work"
    workdir.mkdir()
    environment = {"PATH": os.environ["PATH"], "ATLAS_DEPLOY_KEY": FAKE_KEY}
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    with pytest.raises(publog.TargetError) as error:
        target.fetch_candidate(
            policy_module.load(make_policy(tmp_path)), environment, tag_object, workdir, root.as_uri()
        )
    assert error.value.code in {"TARGET_FETCH_FAILED", "TARGET_IDENTITY_MISMATCH"}


# ==========================================================================
# governance: an answer is only an answer if its status says so
# ==========================================================================


def test_an_environment_that_is_not_restricted_is_refused_even_when_the_listing_says_main(tmp_path):
    def mutate(answers):
        answers[f"/repos/{REPO}/environments/{ENV}"]["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }

    refused(tmp_path, mutate, match="does not restrict")


ENDPOINTS = [
    f"/repos/{REPO}",
    f"/repos/{REPO}/rules/branches/main",
    f"/repos/{REPO}/rulesets/1",
    f"/repos/{REPO}/environments/{ENV}",
    f"/repos/{REPO}/environments/{ENV}/deployment-branch-policies",
    f"/repos/{REPO}/actions/secrets",
]


@pytest.mark.parametrize("status", [201, 202, 204, 301, 304, 500, 502])
@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_an_answer_whose_status_is_not_200_is_refused_even_when_its_body_looks_valid(
    tmp_path, endpoint, status
):
    """A proxy, a cache or a half-failed response can carry a valid-looking body under
    the wrong status. The body is not read until the status has said it is an answer."""
    answers = copy.deepcopy(base_answers())

    def fetch(path):
        return (status if path == endpoint else 200), answers[path]

    with pytest.raises(PolicyError, match="could not be read"):
        governance_module.observe(loaded(tmp_path), good_environment(), fetch)

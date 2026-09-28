"""Does any private byte reach a public surface? Asked of the OUTPUTS, not the source.

N14 was found by reading a workflow: a public anchor uploaded a plaintext private
bundle. It stays closed because the transport is gone, and it stays closed here
because these tests build a synthetic private candidate full of unique sentinels,
run the real entry points over it - success and every failure path - and then scan
everything that would be public:

  * the console: every line every step printed to stdout or stderr
  * every file in the public directory, including the verdict and the package
  * the attestation subject: the file name and digest the signer would be given
  * the error summaries: the reason codes in the verdict and on the console

A grep of the source for "we never print it" would prove nothing about a library
that quotes a byte string in an exception. Nothing is asserted about the source.

The hostile scripts play the sandboxed child: they read the real private file,
echo it, put it in a traceback, name a file after it, and try to write it into the
evidence in several malformed ways. Every one of them is refused, with a fixed code.
"""

from __future__ import annotations

import json

import pytest

from support import ANCHOR, good_environment, make_policy, run_entry, sha256_hex  # noqa: I001

import disclosure
import publog
from pipeline import run_pipeline

S_SOURCE = "PRIVATE_SENTINEL_SOURCE_7f3a9c1e5b2d40861f"
S_SECRET = "PRIVATE_SENTINEL_SECRET_a91c3e7b52d84f06e2"
S_TRACEBACK = "PRIVATE_SENTINEL_TRACEBACK_2d8e5c1a7f394b60d1"
S_FILENAME = "PRIVATE_SENTINEL_FILENAME_c4a1e9d3b7f25806a9"
S_COMMIT = "PRIVATE_SENTINEL_COMMITMSG_5b9d2e8a1c7f4630b7"
S_STDOUT = "PRIVATE_SENTINEL_STDOUT_e0b6a3d95c1f4728"
S_STDERR = "PRIVATE_SENTINEL_STDERR_83c7f1a5d92e4b06"
S_EVIDENCE = "PRIVATE_SENTINEL_EVIDENCE_1d5f8a2c6e094b73"
S_MALFORMED = "PRIVATE_SENTINEL_MALFORMED_9a4e7c2b5d183f60"
ALL_SENTINELS = [
    S_SOURCE, S_SECRET, S_TRACEBACK, S_FILENAME, S_COMMIT, S_STDOUT, S_STDERR, S_EVIDENCE,
    S_MALFORMED,
]

ONE, TWO = "scripts/one.py", "scripts/two.py"
FILES = {
    ONE: f"# {S_SOURCE} is private source that must never be published\nSECRET = '{S_SECRET}'\n",
    TWO: (
        "# Traceback (most recent call last):\n"
        "#   File \"private.py\", line 1, in <module>\n"
        f"#   ValueError: {S_TRACEBACK}\n"
    ),
    f"private_notes/{S_FILENAME}.txt": f"{S_SOURCE}\n",
}


def surfaces(run) -> dict[str, str]:
    """Every would-be-public surface of a run, as text."""
    found = {"console": run.console}
    for path in sorted(run.public.iterdir()):
        found[f"public/{path.name}"] = path.read_bytes().decode("latin-1")
    verdict = run.public / "verdict.json"
    if verdict.is_file():
        # What the signer is given: the subject's name and digest, and nothing else.
        found["attestation-subject"] = f"{verdict.name} sha256:{sha256_hex(verdict.read_bytes())}"
        found["reasons"] = " ".join(json.loads(verdict.read_text(encoding="utf-8"))["reasons"])
    return found


def assert_nothing_private_is_public(run) -> None:
    for name, text in surfaces(run).items():
        for sentinel in ALL_SENTINELS:
            assert sentinel not in text, f"{sentinel} appears on public surface {name}"
        for prefix in ("PRIVATE_SENTINEL_",):
            assert prefix not in text, f"a private sentinel appears on public surface {name}"


def pipeline(tmp_path, script=None, **kwargs):
    config = {"mode": "script", "script": script} if script else None
    return run_pipeline(
        tmp_path,
        files=FILES,
        message=f"commit message carrying {S_COMMIT}",
        floor=[ONE, TWO],
        docker_config=config,
        **kwargs,
    )


HOSTILE = {
    "echoes-private-source-to-stdout-and-stderr": (
        f"import sys\ndata = read_container('/candidate/{ONE}').decode()\n"
        "print(data)\nprint(data, file=sys.stderr)\nfinish()\nsys.exit(1)\n"
    ),
    "prints-its-own-sentinels": (
        f"import sys\nprint('{S_STDOUT}')\nprint('{S_STDERR}', file=sys.stderr)\nfinish()\nsys.exit(1)\n"
    ),
    "dies-with-a-traceback-quoting-private-text": (
        f"data = read_container('/candidate/{TWO}').decode()\nraise ValueError(data + '{S_TRACEBACK}')\n"
    ),
    "writes-private-source-into-evidence-fields": (
        "import json\n"
        f"secret = read_container('/candidate/{ONE}').decode()\n"
        "evidence = {'evidence_version': 'atlas-anchor-evidence/2',"
        f" 'candidate_sha': secret, 'candidate_tree': '{S_EVIDENCE}',"
        f" 'inputs_requested': ['{S_EVIDENCE}'],"
        " 'inputs_observed': [{'relative_path': secret, 'blob': secret, 'sha256': secret, 'size': 1}],"
        f" 'inputs_unreadable': [{{'relative_path': '{S_EVIDENCE}', 'reason': secret}}]}}\n"
        "attempt_write('/evidence/evidence.json', json.dumps(evidence).encode())\nfinish()\n"
    ),
    "writes-malformed-evidence-that-is-not-utf8": (
        f"attempt_write('/evidence/evidence.json', b'\\xff\\xfe{S_MALFORMED}\\x80')\nfinish()\n"
    ),
    "writes-evidence-with-a-sentinel-key-and-an-authority-field": (
        "import json\n"
        f"attempt_write('/evidence/evidence.json', json.dumps({{'{S_EVIDENCE}': 1,"
        " 'verdict': 'ACCEPT', 'anchor': {}}).encode())\nfinish()\n"
    ),
    "writes-evidence-with-duplicate-keys": (
        "attempt_write('/evidence/evidence.json',"
        f" b'{{\"evidence_version\": \"{S_EVIDENCE}\", \"evidence_version\": \"x\"}}')\nfinish()\n"
    ),
    "writes-a-file-named-after-the-secret": (
        f"attempt_write('/evidence/{S_FILENAME}.json', b'{{}}')\n"
        f"attempt_write('/evidence/evidence.json', b'{{\"{S_MALFORMED}\": [')\nfinish()\n"
    ),
    "writes-truncated-json": "attempt_write('/evidence/evidence.json', b'{\"a\": ')\nfinish()\n",
    "writes-nothing": "finish()\n",
}


def test_an_honest_run_publishes_nothing_private(tmp_path):
    run = pipeline(tmp_path)
    assert run.verdict["verdict"] == "ACCEPT", run.console
    assert_nothing_private_is_public(run)


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_child_cannot_put_private_bytes_on_a_public_surface(tmp_path, name):
    run = pipeline(tmp_path, HOSTILE[name])
    verdict = run.verdict
    assert verdict is not None, run.console
    assert verdict["verdict"] == "REFUSE", f"{name} was not refused"
    assert verdict["reasons"], "a refusal with no reason is not a refusal anyone can act on"
    assert_nothing_private_is_public(run)


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_every_reason_a_hostile_run_is_refused_for_is_a_fixed_code(tmp_path, name):
    run = pipeline(tmp_path, HOSTILE[name])
    for reason in run.verdict["reasons"]:
        assert publog.CODE.match(reason), f"{reason!r} is not a fixed reason code"


def test_a_child_that_floods_its_output_is_stopped_and_still_publishes_nothing(tmp_path):
    run = run_pipeline(
        tmp_path,
        files=FILES,
        message=S_COMMIT,
        floor=[ONE, TWO],
        docker_config={"mode": "flood", "bytes": 1 << 20},
    )
    assert run.verdict["verdict"] == "REFUSE"
    assert "SANDBOX_OUTPUT_LIMIT" in run.verdict["reasons"]
    assert_nothing_private_is_public(run)
    assert run.verdict["sandbox"]["stdout_bytes"] > 0


def test_a_child_that_never_finishes_is_killed_by_the_wall_clock(tmp_path):
    run = run_pipeline(
        tmp_path,
        files=FILES,
        floor=[ONE, TWO],
        docker_config={"mode": "hang"},
        policy_overrides={
            "sandbox": {
                "image": "python:3.12-slim-bookworm@sha256:" + "1" * 64,
                "timeout_seconds": 1,
                "memory_mb": 256,
                "cpus": 1,
                "pids_limit": 64,
                "max_output_bytes": 4096,
                "max_file_bytes": 1048576,
                "tmpfs_mb": 8,
            }
        },
    )
    assert run.verdict["verdict"] == "REFUSE"
    assert "SANDBOX_TIMEOUT" in run.verdict["reasons"]


def test_the_console_carries_only_allow_listed_line_shapes(tmp_path):
    """Every console line is `[PHASE] STATUS code=... key=int-or-digest`, and
    nothing else - no free text an attacker-controlled value could ride in."""
    run = pipeline(tmp_path, HOSTILE["prints-its-own-sentinels"])
    shape = __import__("re").compile(
        r"\A\[[A-Z]+\] (PASS|REFUSE|INFO)( code=[A-Z][A-Z0-9_]+)?"
        r"( [a-z][a-z0-9_]*=(true|false|[0-9]+|[0-9a-f]{40}|[0-9a-f]{64}))*"
        r"( detail=[^\n]*)?\Z"
    )
    for name, process in run.steps.items():
        for line in (process.stdout + process.stderr).splitlines():
            assert shape.match(line), f"{name} printed a line outside the allow-list: {line!r}"


# --------------------------------------------------------------------------
# the door: the allow-list and the tripwire
# --------------------------------------------------------------------------


def test_the_tripwire_fires_when_a_private_line_reaches_a_public_file(tmp_path):
    run = pipeline(tmp_path)
    capture = run.public / "public-capture.json"
    document = json.loads(capture.read_text(encoding="utf-8"))
    leaked = FILES[ONE].splitlines()[0]
    document["floor_absent"] = [leaked]
    capture.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    problems = disclosure.audit_public_directory(run.public, run.sandbox / "candidate")
    assert "DISCLOSURE_TRIPWIRE" in problems


def test_the_tripwire_sees_a_json_escaped_leak(tmp_path):
    run = pipeline(tmp_path)
    verdict = run.public / "verdict.json"
    document = json.loads(verdict.read_text(encoding="utf-8"))
    document["interpreter"] = "line with \"quotes\" and \\ backslash " + S_SOURCE + " padding here"
    verdict.write_text(json.dumps(document), encoding="utf-8")
    private = run.sandbox / "candidate" / ONE
    private.chmod(0o644)
    private.write_text(document["interpreter"] + "\n", encoding="utf-8")
    assert "DISCLOSURE_TRIPWIRE" in disclosure.audit_public_directory(
        run.public, run.sandbox / "candidate"
    )


def test_a_field_nobody_listed_cannot_be_published(tmp_path):
    run = pipeline(tmp_path)
    verdict = run.public / "verdict.json"
    document = json.loads(verdict.read_text(encoding="utf-8"))
    document["private_note"] = "anything"
    verdict.write_text(json.dumps(document), encoding="utf-8")
    assert "PUBLIC_SCHEMA" in disclosure.audit_public_directory(run.public, None)


def test_a_file_nobody_listed_cannot_be_published(tmp_path):
    run = pipeline(tmp_path)
    (run.public / "candidate.bundle").write_bytes(b"PRIVATE")
    assert "PUBLIC_FILE_SET" in disclosure.audit_public_directory(run.public, None)


def test_the_audit_step_refuses_and_publishes_no_digest_when_the_door_is_shut(tmp_path):
    run = pipeline(tmp_path)
    (run.public / "candidate.bundle").write_bytes(b"PRIVATE")
    outputs = run.root / "second-outputs.txt"
    outputs.write_text("", encoding="utf-8")
    process = run_entry(
        "publish.py", "audit", "--public-dir", str(run.public),
        "--private-dir", str(run.sandbox / "candidate"),
        env=good_environment(GITHUB_OUTPUT=str(outputs)),
    )
    assert process.returncode == 1
    assert outputs.read_text(encoding="utf-8") == ""


def test_the_extra_inputs_a_caller_asks_for_are_never_published_as_digests(tmp_path):
    files = {**FILES, "docs/extra.txt": "a caller chose to widen the run to this file\n"}
    run = run_pipeline(tmp_path, files=files, floor=[ONE, TWO], manifest="docs/extra.txt")
    public = json.loads((run.public / "public-capture.json").read_text(encoding="utf-8"))
    assert public["extra_scope_count"] == 1
    assert {entry["relative_path"] for entry in public["floor_inputs"]} == {ONE, TWO}
    assert sha256_hex(files["docs/extra.txt"].encode()) not in json.dumps(public)


# --------------------------------------------------------------------------
# the log cannot be forged
# --------------------------------------------------------------------------


def test_a_dispatch_input_cannot_forge_a_workflow_command_in_the_log(tmp_path):
    """A manifest is a dispatch input, so it is public and attacker-shaped. A line
    starting `::` would be executed by the runner as a workflow command."""
    policy = make_policy(tmp_path)
    process = run_entry(
        "verify.py", "--policy", str(policy), "--candidate", "a" * 40,
        "--inputs-manifest", "::add-mask::x\n::error::forged.py",
        "--capture", str(tmp_path / "none.json"), "--capture-digest", "0" * 64,
        "--capture-result", "success", "--scope-dir", str(tmp_path / "s"), "--child-dir", str(tmp_path / "c"), "--evidence-dir", str(tmp_path / "none"),
        env=good_environment(),
    )
    assert process.returncode == 1
    for line in (process.stdout + process.stderr).splitlines():
        assert "::" not in line, line


def test_the_console_emitter_refuses_free_text():
    for bad in ("a sentence", "path/with/slash", "PRIVATE_SENTINEL", "x" * 41):
        with pytest.raises(ValueError):
            publog.line("VERIFY", "INFO", None, value=bad)
    with pytest.raises(ValueError):
        publog.line("VERIFY", "INFO", "not a code")
    with pytest.raises(ValueError):
        publog.line("SOMEWHERE", "PASS")


def test_an_unexpected_exception_prints_a_fixed_code_and_no_traceback(capsys):
    def explode(_):
        raise UnicodeDecodeError("utf-8", b"\xff" + S_SOURCE.encode(), 0, 1, "invalid start byte")

    assert publog.guarded("VERIFY", explode, []) == 2
    out = capsys.readouterr()
    assert S_SOURCE not in out.out + out.err
    assert "INTERNAL_ERROR" in out.out
    assert "Traceback" not in out.out + out.err


def test_a_target_error_never_renders_its_detail():
    error = publog.TargetError("TARGET_FETCH_FAILED", f"fatal: bad object {S_SOURCE}")
    assert S_SOURCE not in str(error)
    assert S_SOURCE not in repr(error.args)


def test_no_trusted_entry_point_prints_outside_the_emitter():
    """A bare print() is a free-text channel. Only publog owns one."""
    import ast

    for path in sorted(ANCHOR.glob("*.py")):
        if path.name in {"publog.py", "runner.py"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prints = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ]
        assert not prints, f"{path.name} prints directly at lines {prints}"


# --------------------------------------------------------------------------
# non-vacuity: the leak vectors were real
# --------------------------------------------------------------------------


def _child_output(run) -> dict:
    return next(entry for entry in run.report() if entry["kind"] == "child-output")


def _evidence_dir_bytes(run) -> dict[str, bytes]:
    from support import tree_bytes

    return tree_bytes(run.sandbox / "evidence")


@pytest.mark.parametrize(
    "name, where, sentinel",
    [
        ("echoes-private-source-to-stdout-and-stderr", "stdout", S_SOURCE),
        ("echoes-private-source-to-stdout-and-stderr", "stderr", S_SOURCE),
        ("prints-its-own-sentinels", "stdout", S_STDOUT),
        ("prints-its-own-sentinels", "stderr", S_STDERR),
        ("dies-with-a-traceback-quoting-private-text", "stderr", S_TRACEBACK),
    ],
)
def test_the_hostile_child_really_emitted_the_sentinel_and_it_still_stayed_private(
    tmp_path, name, where, sentinel
):
    """If the script had crashed on a typo, it would be 'refused' and clean for the
    wrong reason. This shows each one actually held and printed the private text
    inside the box, and that none of it got out."""
    run = pipeline(tmp_path, HOSTILE[name])
    assert sentinel in _child_output(run)[where]
    assert_nothing_private_is_public(run)


@pytest.mark.parametrize(
    "name, needle",
    [
        ("writes-private-source-into-evidence-fields", S_SOURCE.encode()),
        ("writes-malformed-evidence-that-is-not-utf8", S_MALFORMED.encode()),
        ("writes-a-file-named-after-the-secret", S_FILENAME.encode()),
    ],
)
def test_the_hostile_evidence_really_carried_the_sentinel_and_it_still_stayed_private(
    tmp_path, name, needle
):
    run = pipeline(tmp_path, HOSTILE[name])
    on_disk = _evidence_dir_bytes(run)
    assert any(needle in name_.encode() or needle in content for name_, content in on_disk.items())
    assert_nothing_private_is_public(run)


# ==========================================================================
# what an independent review found: a hash is an oracle for anyone who can guess
# ==========================================================================

import hashlib  # noqa: E402

import verify as verify_module  # noqa: E402
from support import policy_document  # noqa: E402

PIN_PATH = "secret/pin.txt"
PIN_BODY = "PIN=4821\n"


def blob_of(body: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(body) + body, usedforsecurity=False).hexdigest()


def public_text(run) -> str:
    return "\n".join(
        path.read_bytes().decode("latin-1") for path in sorted(run.public.iterdir())
    )


def test_a_small_secret_file_cannot_be_recovered_from_anything_published(tmp_path):
    """The reproduction: a caller widens the run to a private file that holds a 4-digit
    PIN. Ten thousand guesses were enough to confirm it against a published digest.
    Nothing published may be recomputable from a guess of the file's content."""
    files = {**FILES, PIN_PATH: PIN_BODY}
    run = run_pipeline(tmp_path, files=files, floor=[ONE, TWO], manifest=PIN_PATH)
    assert run.verdict["verdict"] == "ACCEPT", run.console
    published = public_text(run)
    assert run.output("public_digest")

    hits = []
    for guess in range(10000):
        body = f"PIN={guess:04d}\n".encode()
        for token in (hashlib.sha256(body).hexdigest(), blob_of(body)):
            if token in published:
                hits.append((guess, token))
    assert hits == [], "a published value confirms a guess of a private file's content"


def test_no_field_that_carried_an_extras_digest_survives(tmp_path):
    files = {**FILES, PIN_PATH: PIN_BODY}
    run = run_pipeline(tmp_path, files=files, floor=[ONE, TWO], manifest=PIN_PATH)

    def keys(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                yield key
                yield from keys(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from keys(inner)

    seen = set()
    for name in ("verdict.json", "public-capture.json", "evidence.json"):
        seen.update(keys(json.loads((run.public / name).read_text(encoding="utf-8"))))
    for banned in (
        "capture_digest", "extra_inputs_digest", "observation_evidence_digest", "required_inputs",
        "scope", "absent", "extra_inputs_count", "extra_absent_count",
    ):
        assert banned not in seen, banned


def test_the_paths_and_existence_of_extra_inputs_are_not_published(tmp_path):
    """The manifest names a file that exists and one that does not. An outsider must not
    learn either name from the artifacts, nor which of them is real."""
    files = {**FILES, "secret/ACME_acquisition_target.txt": "x = 1\n"}
    manifest = "secret/ACME_acquisition_target.txt\nsecret/layoffs_plan_Q3.md"
    run = run_pipeline(tmp_path, files=files, floor=[ONE, TWO], manifest=manifest)
    published = public_text(run)
    for needle in ("ACME_acquisition_target", "layoffs_plan_Q3"):
        assert needle not in published, needle
    capture = json.loads((run.public / "public-capture.json").read_text(encoding="utf-8"))
    assert capture["extra_scope_count"] == 2
    assert capture["floor_scope"] == [ONE, TWO] and capture["floor_absent"] == []
    verdict = run.verdict
    assert verdict["required_floor"] == [ONE, TWO] and verdict["extra_inputs_requested"] == 2
    assert verdict["verdict"] == "REFUSE" and "INPUT_ABSENT" in verdict["reasons"]


def test_an_absent_floor_input_is_named_because_the_floor_is_public_policy(tmp_path):
    run = run_pipeline(tmp_path, files={ALPHA_ONLY: "x = 1\n"}, floor=[ALPHA_ONLY, "scripts/missing.py"])
    capture = json.loads((run.public / "public-capture.json").read_text(encoding="utf-8"))
    assert capture["floor_absent"] == ["scripts/missing.py"]


ALPHA_ONLY = "scripts/present.py"


def test_the_digests_of_an_extra_input_trip_the_wire_if_they_ever_reach_a_public_file(tmp_path):
    files = {**FILES, PIN_PATH: PIN_BODY}
    run = run_pipeline(tmp_path, files=files, floor=[ONE, TWO], manifest=PIN_PATH)
    capture = json.loads((run.private / "capture.json").read_text(encoding="utf-8"))
    tokens = disclosure.extra_digests(capture, policy_document(floor=[ONE, TWO]))
    assert hashlib.sha256(PIN_BODY.encode()).hexdigest() in tokens and blob_of(PIN_BODY.encode()) in tokens
    assert disclosure.audit_public_directory(run.public, run.sandbox / "candidate", tokens) == []

    verdict = run.public / "verdict.json"
    document = json.loads(verdict.read_text(encoding="utf-8"))
    document["interpreter"] = sorted(tokens)[0]
    verdict.write_text(json.dumps(document), encoding="utf-8")
    assert "DISCLOSURE_TRIPWIRE" in disclosure.audit_public_directory(
        run.public, run.sandbox / "candidate", tokens
    )


def test_the_floor_is_the_only_thing_described_by_digest():
    policy = policy_document(floor=["a.py", "b.py"])
    tokens = disclosure.extra_digests(
        {"inputs": [
            {"relative_path": "a.py", "sha256": "1" * 64, "blob": "2" * 40},
            {"relative_path": "x.py", "sha256": "3" * 64, "blob": "4" * 40},
        ]},
        policy,
    )
    assert tokens == {"3" * 64, "4" * 40}


def test_the_audit_refuses_to_pass_when_the_private_directory_it_compares_with_is_missing(tmp_path):
    run = pipeline(tmp_path)
    assert "PRIVATE_DIRECTORY_MISSING" in disclosure.audit_public_directory(run.public, tmp_path / "gone")


def test_the_audit_step_refuses_when_it_is_told_of_a_private_directory_but_not_the_freeze(tmp_path):
    run = pipeline(tmp_path)
    process = run_entry(
        "publish.py", "audit", "--public-dir", str(run.public),
        "--private-dir", str(run.sandbox / "candidate"), env=good_environment(),
    )
    assert process.returncode == 1 and "PRIVATE_INPUTS_INCOMPLETE" in process.stdout


LONG_FLOOR = "scripts/a_long_named_floor_input_file_for_the_tripwire_test.py"
OTHER_FLOOR = "scripts/another_floor_input_file_for_the_tripwire_test.py"


def test_a_floor_file_that_quotes_the_anchors_own_policy_is_not_a_leak(tmp_path):
    """A floor file whose lines also appear in public policy - a path list, say - would
    trip a naive tripwire on every run until the file changed. Text that is already
    public cannot be a disclosure."""
    files = {
        LONG_FLOOR: f'FLOOR = [\n    "{LONG_FLOOR}",\n    "{OTHER_FLOOR}",\n]\n{OTHER_FLOOR}\n',
        OTHER_FLOOR: "X = 1\n",
    }
    run = run_pipeline(tmp_path, files=files, floor=[LONG_FLOOR, OTHER_FLOOR])
    assert run.verdict["verdict"] == "ACCEPT", run.console
    assert run.steps["audit"].returncode == 0, run.steps["audit"].stdout


def test_the_tripwire_still_fires_for_a_private_line_that_is_not_public_anywhere(tmp_path):
    files = {
        LONG_FLOOR: f'FLOOR = ["{LONG_FLOOR}"]\nSECRET_NOTE = "{S_SOURCE}"\n',
        OTHER_FLOOR: "X = 1\n",
    }
    run = run_pipeline(tmp_path, files=files, floor=[LONG_FLOOR, OTHER_FLOOR])
    capture = run.public / "public-capture.json"
    document = json.loads(capture.read_text(encoding="utf-8"))
    document["floor_absent"] = [f'SECRET_NOTE = "{S_SOURCE}"']
    capture.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    assert "DISCLOSURE_TRIPWIRE" in disclosure.audit_public_directory(run.public, run.sandbox / "candidate")


S_UNICODE = "PRIVATE_SENTINEL_日本語_7c2d5e9a1f3b4680"


def test_a_private_line_of_non_ascii_text_is_caught_when_it_would_be_json_escaped(tmp_path):
    files = {ONE: f"# {S_UNICODE} is a long private comment line in Japanese 日本語\n", TWO: "X = 1\n"}
    run = run_pipeline(tmp_path, files=files, floor=[ONE, TWO])
    verdict = run.public / "verdict.json"
    document = json.loads(verdict.read_text(encoding="utf-8"))
    document["interpreter"] = f"# {S_UNICODE} is a long private comment line in Japanese 日本語"
    verdict.write_text(json.dumps(document), encoding="utf-8")  # ensure_ascii: \uXXXX escapes
    assert b"\\u65e5" in verdict.read_bytes()
    assert "DISCLOSURE_TRIPWIRE" in disclosure.audit_public_directory(run.public, run.sandbox / "candidate")


def test_non_ascii_private_text_never_appears_on_a_public_surface_even_decoded(tmp_path):
    files = {ONE: f"# {S_UNICODE} is a long private comment line in Japanese 日本語\n", TWO: "X = 1\n"}
    run = run_pipeline(
        tmp_path, files=files, floor=[ONE, TWO],
        docker_config={"mode": "script", "script": (
            "import sys\nprint(read_container('/candidate/scripts/one.py').decode('utf-8'))\nfinish()\nsys.exit(1)\n"
        )},
    )
    decoded = [run.console]
    for path in sorted(run.public.iterdir()):
        raw = path.read_bytes().decode("latin-1")
        decoded.append(raw)
        if path.suffix == ".json":
            decoded.append(json.dumps(json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False))
    for text in decoded:
        assert "日本語" not in text and "PRIVATE_SENTINEL" not in text


# ==========================================================================
# the log cannot be forged - not by a value shaped like an option either
# ==========================================================================


@pytest.mark.parametrize(
    "hostile",
    [
        "--c=\n::error::FORGED\n::add-mask::x",
        "-x\n::warning::FORGED",
        "--\n::error::FORGED",
        "--candidate\n::error::FORGED",
        "::error::FORGED",
    ],
)
@pytest.mark.parametrize("attached", [False, True])
def test_an_option_shaped_dispatch_input_cannot_forge_a_log_command(tmp_path, hostile, attached):
    """argparse quotes the argument it rejects. An input shaped like an option, followed
    by a line break and `::error::`, was printed at the start of a line - a forged
    workflow command on a public log. The workflow now passes such values attached
    (`--opt=value`), so they are never parsed as options; and usage errors are a fixed line."""
    policy = make_policy(tmp_path)
    base = ["--policy", str(policy), "--capture", str(tmp_path / "n.json"),
            "--capture-digest", "0" * 64, "--capture-result", "success",
            "--scope-dir", str(tmp_path / "s"), "--child-dir", str(tmp_path / "c"),
            "--evidence-dir", str(tmp_path / "e")]
    if attached:
        arguments = base + [f"--candidate={'a' * 40}", f"--inputs-manifest={hostile}"]
    else:
        arguments = base + ["--candidate", "a" * 40, "--inputs-manifest", hostile]
    process = run_entry("verify.py", *arguments, env=good_environment())
    output = process.stdout + process.stderr
    for line in output.splitlines():
        assert not line.startswith("::") and "::" not in line, line
    assert process.returncode in {1, 2}
    if not attached and hostile.startswith("-"):
        assert "USAGE_ERROR" in process.stdout


@pytest.mark.parametrize("script", ["capture.py", "sandbox.py", "gate.py", "verify.py"])
def test_every_entry_point_reports_a_usage_error_as_one_fixed_line(tmp_path, script):
    process = run_entry(script, "--candidate\n::error::FORGED", env=good_environment())
    assert process.returncode == 2
    assert process.stdout.strip().splitlines() == [f"[{script[:-3].upper()}] REFUSE code=USAGE_ERROR"]
    assert process.stderr == ""


def test_an_abbreviated_option_is_not_accepted(tmp_path):
    process = run_entry("gate.py", "--pol", str(make_policy(tmp_path)), "--identity-only", env=good_environment())
    assert process.returncode == 2 and "USAGE_ERROR" in process.stdout


def test_safe_detail_neutralises_every_command_form():
    for text in ("##[set-output name=x;]y", "::error::x", ":::error:::x", "a\n::b", "\r::c", "x::::::y", "#[a]"):
        out = publog.safe_detail(text)
        assert "::" not in out and "#" not in out and "[" not in out and "]" not in out
        assert "\n" not in out and "\r" not in out

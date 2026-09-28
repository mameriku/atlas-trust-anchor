"""Mutation testing of the anchor's authority predicates.

A test suite that stays green when a predicate is deleted is not testing the
predicate. Each entry below is ONE edit that removes or inverts a check the anchor's
authority rests on - identity, governance, the box, the evidence boundary, the
disclosure allow-list, the credential's lifetime, the workflow's structure - together
with the test files that must notice.

Each mutant is applied to a throwaway copy of the repository and only the named
tests are run, so a killed mutant costs seconds. The outcome is one of:

  KILLED     the named tests failed: the predicate is defended
  SURVIVED   they passed: the predicate is undefended, or the edit is equivalent
  INVALID    the text to edit was not found exactly once: the catalog has rotted

Run:   python tests/mutation.py            (all; exits 1 if any survivor or invalid)
       python tests/mutation.py policy      (only ids containing "policy")
"""

from __future__ import annotations

import concurrent.futures
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKERS = 4

FAMILIES = {
    "anchor/policy.py": ["tests/test_policy_and_governance.py", "tests/test_single_operator_governance.py"],
    "anchor/policy.json": ["tests/test_policy_and_governance.py", "tests/test_workflow_and_accept.py", "tests/test_single_operator_governance.py"],
    "governance/ruleset-main.json": ["tests/test_workflow_and_accept.py", "tests/test_single_operator_governance.py"],
    "anchor/governance.py": ["tests/test_policy_and_governance.py", "tests/test_layers.py", "tests/test_review_round_two.py", "tests/test_single_operator_governance.py"],
    "anchor/governance_record.py": ["tests/test_policy_and_governance.py", "tests/test_capture_and_child.py", "tests/test_single_operator_governance.py"],
    "anchor/sandbox_spec.py": ["tests/test_sandbox_and_evidence.py", "tests/test_review_round_two.py"],
    "anchor/sandbox.py": ["tests/test_sandbox_and_evidence.py", "tests/test_credentials.py", "tests/test_review_round_two.py"],
    "anchor/evidence.py": ["tests/test_sandbox_and_evidence.py", "tests/test_layers.py"],
    "anchor/verify.py": ["tests/test_verify_and_preserve.py", "tests/test_review_round_two.py"],
    "anchor/capture.py": ["tests/test_capture_and_child.py", "tests/test_layers.py", "tests/test_review_round_two.py"],
    "anchor/target.py": ["tests/test_credentials.py", "tests/test_capture_and_child.py", "tests/test_layers.py"],
    "anchor/publog.py": ["tests/test_disclosure.py"],
    "anchor/disclosure.py": ["tests/test_disclosure.py", "tests/test_verify_and_preserve.py", "tests/test_review_round_two.py"],
    "anchor/preserve.py": ["tests/test_verify_and_preserve.py"],
    "anchor/accept.py": ["tests/test_workflow_and_accept.py"],
    "anchor/pinlint.py": ["tests/test_workflow_and_accept.py", "tests/test_review_round_two.py"],
    "anchor/runner.py": ["tests/test_capture_and_child.py", "tests/test_layers.py"],
    ".github/workflows/qualify.yml": ["tests/test_workflow_and_accept.py"],
    ".github/workflows/test.yml": ["tests/test_workflow_and_accept.py"],
}


@dataclass(frozen=True)
class Mutant:
    name: str
    path: str
    old: str
    new: str

    @property
    def tests(self) -> list[str]:
        return FAMILIES[self.path]


def m(name: str, path: str, old: str, new: str) -> Mutant:
    return Mutant(name, path, old, new)


def off(name: str, path: str, condition: str) -> Mutant:
    """Switch a whole `if`/`elif` condition off."""
    keyword = "elif" if condition.startswith("elif ") else "if"
    body = condition.split(" ", 1)[1] if condition.startswith(("if ", "elif ")) else condition
    return Mutant(name, path, f"{keyword} {body}", f"{keyword} False:")


CATALOG: list[Mutant] = [
    # ---- identity: who may run this ---------------------------------------
    off("policy/repository-id", "anchor/policy.py", 'if observed_id != str(anchor["repository_id"]):'),
    off("policy/repository-name", "anchor/policy.py", 'if environ.get("GITHUB_REPOSITORY", "").casefold() != anchor["repository"].casefold():'),
    off("policy/workflow-ref", "anchor/policy.py", 'if observed_ref != anchor["workflow_ref"]:'),
    off("policy/ref", "anchor/policy.py", 'if environ.get("GITHUB_REF", "") != anchor["ref"]:'),
    off("policy/workflow-sha-is-head", "anchor/policy.py", "if workflow_sha != head_sha:"),
    off("policy/event", "anchor/policy.py", 'if environ.get("GITHUB_EVENT_NAME", "") != trigger["event"]:'),
    off("policy/actors", "anchor/policy.py", 'if environ.get(variable, "") not in trigger["actors"]:'),
    off("policy/github-hosted-runner", "anchor/policy.py", 'if environ.get("RUNNER_ENVIRONMENT", "") != "github-hosted":'),
    # ---- policy: the shapes it must never have ----------------------------
    off("policy/topology", "anchor/policy.py", 'if anchor.get("visibility") != "public" or target.get("visibility") != "private":'),
    m("policy/private-transport", "anchor/policy.py", 'if not isinstance(disclosure, dict) or disclosure.get("private_transport") != "none":', "if not isinstance(disclosure, dict):"),
    off("policy/image-pinned", "anchor/policy.py", 'if not PINNED_IMAGE.match(str(sandbox.get("image", ""))):'),
    off("policy/host-key-pinned", "anchor/policy.py", 'if not HOST_KEY.match(str(credential.get("host_key", ""))):'),
    m("policy/scope-floor-union", "anchor/policy.py", "return sorted(set(requested) | set(floor))", "return sorted(set(requested))"),
    off("policy/manifest-duplicates", "anchor/policy.py", "if len(set(requested)) != len(requested):"),
    off("policy/path-control-characters", "anchor/policy.py", "if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):"),
    m("policy/shipped-transport", "anchor/policy.json", '"private_transport": "none"', '"private_transport": "upload"'),
    m("policy/shipped-topology", "anchor/policy.json", '"visibility": "public"\n  },\n  "target"', '"visibility": "private"\n  },\n  "target"'),
    # ---- governance: is the anchor actually protected ---------------------
    off("governance/bypass-list-empty", "anchor/governance.py", "elif bypass:"),
    off("governance/bypass-list-disclosed", "anchor/governance.py", "if not isinstance(bypass, list):"),
    off("governance/ruleset-active", "anchor/governance.py", 'if enforcement != "active":'),
    m("governance/anchor-is-public", "anchor/governance.py", 'if described.get("private") is not False or described.get("visibility") not in (', 'if False and described.get("visibility") not in ('),
    off("governance/default-branch", "anchor/governance.py", 'if described.get("default_branch") != branch:'),
    off("governance/status-checks", "anchor/governance.py", "if context not in contexts:"),
    m("governance/approval-count", "anchor/governance.py", 'approvals < required["required_approvals"]', "False"),
    m("governance/stale-reviews", "anchor/governance.py", 'if required["require_dismiss_stale_reviews"] and not parameters.get(', "if False and not parameters.get("),
    off("governance/environment-branches", "anchor/governance.py", 'if len(named) != len(entries) or named != sorted(spec["deployment_branches"]):'),
    m("governance/environment-restricted", "anchor/governance.py", 'restriction.get("custom_branch_policies") is not True', "False"),
    off("governance/repository-id", "anchor/governance.py", 'if described.get("id") != anchor["repository_id"]:'),
    off("governance/status-200", "anchor/governance.py", "if status != 200:"),
    off("governance/required-rules", "anchor/governance.py", "if rule_type not in index:"),
    # ---- a recorded observation the verifier reads ------------------------
    off("record/digest", "anchor/governance_record.py", 'if observation.get("observation_digest") != _digest(observation):'),
    off("record/public", "anchor/governance_record.py", 'if observation.get("repository_private") is not False:'),
    m("record/bypass-count-type", "anchor/governance_record.py", 'type(entry.get("bypass_actor_count")) is not int\n            or entry.get("bypass_actor_count") != 0', 'entry.get("bypass_actor_count") != 0'),
    m("record/bypass-count-value", "anchor/governance_record.py", 'or entry.get("bypass_actor_count") != 0', "or False"),
    m("record/environment", "anchor/governance_record.py", 'or environment.get("deployment_branches") != sorted(expected["deployment_branches"])', "or False"),
    off("record/required-rules", "anchor/governance_record.py", 'if any(rule not in in_force for rule in required["required_rules"]):'),
    m("record/approvals", "anchor/governance_record.py", 'approvals < required["required_approvals"]', "False"),
    # ---- the box ----------------------------------------------------------
    off("box/network", "anchor/sandbox_spec.py", 'if _single(options, "--network") != "none":'),
    off("box/capabilities", "anchor/sandbox_spec.py", 'if options.get("--cap-drop") != ["ALL"]:'),
    m("box/non-root", "anchor/sandbox_spec.py", "if not match or int(match.group(1)) == 0 or int(match.group(2)) != UNPRIVILEGED_GID:", "if not match:"),
    off("box/read-only-root", "anchor/sandbox_spec.py", 'if "--read-only" not in flags:'),
    off("box/no-new-privileges", "anchor/sandbox_spec.py", 'if options.get("--security-opt") != ["no-new-privileges"]:'),
    off("box/image-digest", "anchor/sandbox_spec.py", 'if image != box["image"]:'),
    m("box/unknown-options", "anchor/sandbox_spec.py", '            problems.append("SANDBOX_UNKNOWN_OPTION")', "            pass"),
    off("box/candidate-mount-read-only", "anchor/sandbox_spec.py", 'if role != "evidence" and not readonly:'),
    off("box/mount-set", "anchor/sandbox_spec.py", "if sorted(seen) != sorted(TARGETS.values()) or len(mounts) != len(TARGETS):"),
    m("box/exit-code-is-a-real-zero", "anchor/sandbox_spec.py", "if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code != 0:", "if exit_code != 0:"),
    off("box/timeout-recorded", "anchor/sandbox_spec.py", 'if record.get("timed_out") is not False:'),
    off("box/output-limit-recorded", "anchor/sandbox_spec.py", 'if record.get("output_exceeded") is not False:'),
    off("box/docker-socket", "anchor/sandbox_spec.py", 'if any("docker.sock" in token for token in client_side):'),
    off("box/pid-limit", "anchor/sandbox_spec.py", 'if _single(options, "--pids-limit") != str(box["pids_limit"]):'),
    off("box/memory-limit", "anchor/sandbox_spec.py", 'if _single(options, "--memory") != memory or _single(options, "--memory-swap") != memory:'),
    off("box/pull-never", "anchor/sandbox_spec.py", 'if _single(options, "--pull") != "never":'),
    m("box/no-root-launch", "anchor/sandbox.py", "if uid == 0 or gid == 0:", "if False:"),
    m("box/client-environment-allow-list", "anchor/sandbox.py", "return {name: parent[name] for name in _CLIENT_ENVIRONMENT if name in parent}", "return dict(parent)"),
    m("box/container-removed", "anchor/sandbox.py", '[*docker, "rm", "--force", name],', '[*docker, "ps", "--all"],'),
    # ---- the evidence boundary --------------------------------------------
    off("evidence/directory-symlink", "anchor/evidence.py", "if stat.S_ISLNK(status.st_mode):"),
    off("evidence/unexpected-files", "anchor/evidence.py", "if entry.name != FILENAME:"),
    off("evidence/size-stat", "anchor/evidence.py", "if status.st_size > limit:"),
    off("evidence/size-read", "anchor/evidence.py", "if total > limit:"),
    off("evidence/duplicate-keys", "anchor/evidence.py", "if len(keys) != len(set(keys)):"),
    off("evidence/authority-fields", "anchor/evidence.py", "if unknown & AUTHORITY_KEYS:"),
    off("evidence/unknown-fields", "anchor/evidence.py", "if unknown - AUTHORITY_KEYS:"),
    off("evidence/version", "anchor/evidence.py", 'if document["evidence_version"] != EVIDENCE_VERSION:'),
    m("evidence/bool-is-not-a-size", "anchor/evidence.py", 'or not _is_int(record["size"])', "or False"),
    m("evidence/strict-encoding", "anchor/evidence.py", 'text = payload.decode("utf-8")', 'text = payload.decode("utf-8", errors="replace")'),
    m("evidence/non-finite-numbers", "anchor/evidence.py", "text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant", "text, object_pairs_hook=_reject_duplicates"),
    off("evidence/too-many-files", "anchor/evidence.py", "if seen > _MAX_DIRECTORY_ENTRIES:"),
    # ---- the verdict ------------------------------------------------------
    off("verify/capture-commit", "anchor/verify.py", 'if capture.get("candidate_sha") != candidate:'),
    off("verify/capture-scope", "anchor/verify.py", 'if capture.get("scope") != scope:'),
    off("verify/absent-inputs", "anchor/verify.py", 'if capture.get("absent") != []:'),
    off("verify/capture-outcome", "anchor/verify.py", 'if capture_result != "success":'),
    m("verify/observation-matches-freeze", "anchor/verify.py", "elif frozen != record:", "elif False:"),
    off("verify/scope-covered", "anchor/verify.py", "if any(path not in covered for path in scope):"),
    off("verify/scope-not-exceeded", "anchor/verify.py", "if any(path not in scope for path in covered):"),
    off("verify/no-duplicate-observations", "anchor/verify.py", "if len(covered) != len(set(covered)):"),
    off("verify/unreadable-inputs", "anchor/verify.py", 'if evidence["inputs_unreadable"]:'),
    off("verify/evidence-tree", "anchor/verify.py", 'if evidence["candidate_tree"] != capture.get("candidate_tree"):'),
    off("verify/evidence-commit", "anchor/verify.py", 'if evidence["candidate_sha"] != candidate:'),
    off("verify/evidence-scope-is-not-believed", "anchor/verify.py", 'if evidence["inputs_requested"] != scope:'),
    m("verify/sandbox-binding", "anchor/verify.py", 'params.get("candidate") != candidate or params.get("tree") != tree', "False"),
    m("verify/sandbox-record-required", "anchor/verify.py", 'return ["SANDBOX_RECORD_MISSING"]', "return []"),
    off("verify/observation-flood", "anchor/verify.py", 'if len(observed) > limits["max_observations"]:'),
    off("verify/capture-digest", "anchor/verify.py", "if hashlib.sha256(payload).hexdigest() != expected_digest:"),
    m("verify/verdict-follows-reasons", "anchor/verify.py", "return (ACCEPT if not unique else REFUSE), unique", "return ACCEPT, unique"),
    m("verify/missing-evidence-is-a-reason", "anchor/verify.py", 'reasons.extend(evidence.problems or ("EVIDENCE_MISSING",))', "reasons.extend(evidence.problems)"),
    m("verify/run-identifiers-are-numbers", "anchor/verify.py", '"run_id": _number(environ.get("GITHUB_RUN_ID")),', '"run_id": environ.get("GITHUB_RUN_ID"),'),
    # ---- the freeze and the fetch -----------------------------------------
    m("capture/regular-files-only", "anchor/capture.py", "if entry is None or entry[0] not in _REGULAR_MODES:", "if entry is None:"),
    off("capture/size-bound", "anchor/capture.py", "if size > limit:"),
    off("capture/exact-commit", "anchor/capture.py", "if resolved != candidate:"),
    off("capture/export-stays-inside", "anchor/capture.py", "if scope_dir.resolve() not in destination.parents:"),
    m("capture/governance-required", "anchor/capture.py", "    if reasons:\n        raise PolicyError(f\"the governance observation does not establish", "    if False:\n        raise PolicyError(f\"the governance observation does not establish"),
    m("target/key-required", "anchor/target.py", 'if key_problem and not url.startswith("file://"):', "if False:"),
    m("target/source-restricted", "anchor/target.py", 'if source == ssh_url(policy) or source.startswith("file://"):', "if True:"),
    m("target/key-destroyed", "anchor/target.py", "        _destroy(key_path)\n        shutil.rmtree(ssh_dir, ignore_errors=True)", "        pass"),
    off("target/config-audited", "anchor/target.py", "if _PERSISTED.search(text):"),
    off("target/exact-commit", "anchor/target.py", "if resolved != candidate:"),
    m("target/git-environment-rebuilt", "anchor/target.py", '    environment = {\n        "PATH": parent.get("PATH", os.defpath),', '    environment = {\n        **parent,\n        "PATH": parent.get("PATH", os.defpath),'),
    m("target/host-key-checked", "anchor/target.py", '"StrictHostKeyChecking=yes",', '"StrictHostKeyChecking=no",'),
    # ---- the child --------------------------------------------------------
    # child/symlinks is EQUIVALENT: a symlink also fails the S_ISREG / S_ISDIR check that follows,
    # so removing the lstat symlink test alone changes nothing observable.
    off("child/size", "anchor/runner.py", "if status.st_size > limit:"),
    m("child/blob-id", "anchor/runner.py", 'header = b"blob " +', 'header = b"bloc " +'),
    m("child/evidence-exclusive", "anchor/runner.py", "os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY,", "os.O_WRONLY | os.O_CREAT | _NOFOLLOW | _BINARY,"),
    # ---- what may leave the runner ----------------------------------------
    m("publog/digests-only", "anchor/publog.py", "if isinstance(value, str) and _DIGEST.match(value):", "if isinstance(value, str):"),
    m("publog/workflow-commands", "anchor/publog.py", '    while "::" in reduced:\n        reduced = reduced.replace("::", ":")\n', "    pass\n"),
    m("publog/no-tracebacks", "anchor/publog.py", "except BaseException:  # noqa: BLE001 - the point is that nothing escapes", "except ZeroDivisionError:"),
    m("disclosure/allow-listed-keys", "anchor/disclosure.py", "if not isinstance(document, dict) or set(document) != keys:", "if not isinstance(document, dict):"),
    off("disclosure/allow-listed-files", "anchor/disclosure.py", "if set(entries) != set(PUBLIC_FILES):"),
    m("disclosure/tripwire", "anchor/disclosure.py", "if private.is_file() and _tripped(texts, reference, private.read_bytes()):", "if False:"),
    m("disclosure/extras-are-not-floor", "anchor/disclosure.py", 'if entry["relative_path"] in floor:', "if True:"),
    off("preserve/public-capture-bound", "anchor/preserve.py", 'if verdict.get("public_capture_digest") != digest(public_capture_path):'),
    off("preserve/policy-bound", "anchor/preserve.py", 'if verdict.get("policy_digest") != digest(policy_path):'),
    off("preserve/seal", "anchor/preserve.py", 'if package.get("evidence_digest") != _seal(package):'),
    m("preserve/members", "anchor/preserve.py", 'elif digest(path) != entry["sha256"] or path.stat().st_size != entry["size"]:', "elif False:"),
    off("preserve/schema", "anchor/preserve.py", "if set(package) != disclosure.PACKAGE_KEYS:"),
    # ---- attestation acceptance -------------------------------------------
    m("accept/certificate-values", "anchor/accept.py", "elif cert[field].casefold() != wanted.casefold():", "elif False:"),
    off("accept/signature-verified", "anchor/accept.py", "if completed.returncode != 0:"),
    off("accept/certificate-present", "anchor/accept.py", "if not certificates:"),
    # ---- the lint ---------------------------------------------------------
    m("lint/public-roots", "anchor/pinlint.py", 'PUBLIC_ROOTS = ("public", "attestation")', 'PUBLIC_ROOTS = ("public", "attestation", ".")'),
    off("lint/pinned-actions", "anchor/pinlint.py", "if not PINNED.match(reference):"),
    m("lint/continue-on-error", "anchor/pinlint.py", 'if "continue-on-error" in stripped and not commented:', "if False:"),
    m("lint/secret-bindings", "anchor/pinlint.py", "if SECRET_REFERENCE.search(line) and not (secrets_allowed and SECRET_BINDING.match(line)):", "if False:"),
    m("lint/shell-tracing", "anchor/pinlint.py", "if TRACING.search(line) or BARE_ENV.search(line):", "if False:"),
    m("lint/docker-outside-sandbox", "anchor/pinlint.py", "if not commented and DOCKER.search(line):", "if False:"),
    # ---- the workflow's structure -----------------------------------------
    m("workflow/environment-gate", ".github/workflows/qualify.yml", "    environment: atlas-qualification\n", ""),
    m("workflow/fork-trigger", ".github/workflows/qualify.yml", "on:\n  workflow_dispatch:", "on:\n  pull_request:\n  workflow_dispatch:"),
    m("workflow/read-only-token", ".github/workflows/qualify.yml", "permissions:\n  contents: read\n\nconcurrency", "permissions:\n  contents: read\n  id-token: write\n\nconcurrency"),
    m("workflow/key-in-sandbox-step", ".github/workflows/qualify.yml", "        id: sandbox\n        env:\n", "        id: sandbox\n        env:\n          ATLAS_DEPLOY_KEY: ${{ secrets.ATLAS_DEPLOY_KEY }}\n"),
    m("workflow/upload-private-directory", ".github/workflows/qualify.yml", "          path: public/\n          if-no-files-found: error\n\n      - name: Scrub", "          path: ${{ runner.temp }}/anchor-sandbox/\n          if-no-files-found: error\n\n      - name: Scrub"),
    m("workflow/upload-after-audit", ".github/workflows/qualify.yml", "if: always() && steps.audit.outcome == 'success'", "if: always()"),
    m("workflow/persisted-credentials", ".github/workflows/qualify.yml", "          path: anchor\n          persist-credentials: false\n\n      # Before", "          path: anchor\n          persist-credentials: true\n\n      # Before"),
    m("workflow/unpinned-action", ".github/workflows/qualify.yml", "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2", "actions/attest-build-provenance@v4"),
    m("workflow/attest-scope", ".github/workflows/qualify.yml", "subject-path: public/verdict.json", "subject-path: public/"),
    m("workflow/candidate-bundle", ".github/workflows/qualify.yml", "          git archive --format=tar -o ../public/anchor-tree.tar HEAD", "          git bundle create ../public/candidate.bundle --all"),
    m("workflow/test-with-secrets", ".github/workflows/test.yml", "      - name: Run the suite\n        run: python3 -m pytest tests -q", "      - name: Run the suite\n        env:\n          K: ${{ secrets.ATLAS_DEPLOY_KEY }}\n        run: python3 -m pytest tests -q"),
    # ---- what an independent review found ---------------------------------
    off("box/docker-client-prefix", "anchor/sandbox_spec.py", "if prefix != list(docker):"),
    off("box/ulimits-exact", "anchor/sandbox_spec.py", 'if options.get("--ulimit") != [f"fsize={box[\'max_file_bytes\']}", "nofile=256", "core=0"]:'),
    off("box/workdir", "anchor/sandbox_spec.py", 'if _single(options, "--workdir") != "/tmp":'),
    off("box/hostname", "anchor/sandbox_spec.py", 'if _single(options, "--hostname") != "anchor-child":'),
    off("box/name", "anchor/sandbox_spec.py", 'if not _NAME.match(_single(options, "--name") or ""):'),
    m("box/command-head", "anchor/sandbox_spec.py", "or list(command[: len(_COMMAND_HEAD)]) != _COMMAND_HEAD:", "or False:"),
    off("box/commit-bound", "anchor/sandbox_spec.py", "if candidate is not None and tail[1] != candidate:"),
    off("box/tree-bound", "anchor/sandbox_spec.py", "if tree is not None and tail[3] != tree:"),
    off("box/mount-line-breaks", "anchor/sandbox_spec.py", "if any(character in mount for character in MOUNT_BREAKERS[1:]):"),
    m("box/unprivileged-gid", "anchor/sandbox.py", "return os.getuid(), _UNPRIVILEGED_GID", "return os.getuid(), os.getgid()"),
    m("box/daemon-selecting-environment", "anchor/sandbox.py", '    "HOME",\n    "USERPROFILE",', '    "HOME",\n    "DOCKER_HOST",\n    "USERPROFILE",'),
    m("verify/evidence-directory-bound", "anchor/verify.py", '_same_directory(layout.get("evidence"), evidence_dir)', "True"),
    m("verify/forbidden-mounts", "anchor/verify.py", "\n        and not _contains_forbidden(layout, forbidden_roots, private_roots)", ""),
    m("verify/client-audited", "anchor/verify.py", "record, policy, docker, candidate, tree if isinstance(tree, str) else None", 'record, policy, ("docker",), candidate, tree if isinstance(tree, str) else None'),
    m("verify/candidate-validated", "anchor/verify.py", '"candidate_sha": arguments.candidate if FULL_SHA.match(arguments.candidate) else None,', '"candidate_sha": arguments.candidate,'),
    m("verify/capture-result-enum", "anchor/verify.py", "        if arguments.capture_result in CAPTURE_RESULTS\n        else None,", "        if True\n        else None,"),
    off("disclosure/private-directory-required", "anchor/disclosure.py", "if not private_directory.is_dir():"),
    m("disclosure/extra-digest-tripwire", "anchor/disclosure.py", 'if any(token.encode("ascii") in document for document in documents):', "if False:"),
    m("disclosure/public-text-is-not-a-leak", "anchor/disclosure.py", "        if fragment in reference:\n            continue", "        if False:\n            continue"),
    m("disclosure/no-extra-counts", "anchor/disclosure.py", '        "extra_scope_count": len(extras),', '        "extra_scope_count": len(extras),\n        "extra_inputs_count": len(record["inputs"]),'),
    off("governance/repository-secret-scope", "anchor/governance.py", "if forbidden & names:"),
    off("governance/secrets-complete", "anchor/governance.py", "if not complete:"),
    off("governance/environment-admin-bypass", "anchor/governance.py", 'if environment.get("can_admins_bypass") is not False:'),
    m("governance/integration-pinned", "anchor/governance.py", 'and check.get("integration_id") == integration', "and True"),
    m("governance/last-push-approval", "anchor/governance.py", '        if required["require_last_push_approval"] and parameters.get(\n            "require_last_push_approval"\n        ) is not True:\n            problems.append(', '        if False:\n            problems.append('),
    m("governance/last-push-policy-ignored", "anchor/governance.py", 'if required["require_last_push_approval"] and parameters.get(', "if True and parameters.get("),
    off("governance/strict-checks", "anchor/governance.py", 'if (rule.get("parameters") or {}).get("strict_required_status_checks_policy") is not True:'),
    off("record/last-push", "anchor/governance_record.py", 'if required["require_last_push_approval"] and observation.get("last_push_approval") is not True:'),
    m("record/last-push-policy-ignored", "anchor/governance_record.py", 'if required["require_last_push_approval"] and observation', "if True and observation"),
    off("record/strict-checks", "anchor/governance_record.py", 'if observation.get("strict_status_checks") is not True:'),
    off("record/secret-scope", "anchor/governance_record.py", 'if observation.get("credential_only_in_environment") is not True:'),
    m("policy/canonical-rules", "anchor/policy.py", "    if missing:\n", "    if False:\n"),
    # ---- single-operator governance: zero approvals is a value, not a way to drop a rule -----
    m("policy/approvals-not-negative", "anchor/policy.py", "or approvals < 0:", "or False:"),
    m("policy/approvals-not-bool", "anchor/policy.py", "if isinstance(approvals, bool) or not isinstance(approvals, int)", "if not isinstance(approvals, int)"),
    m("policy/last-push-flag-typed", "anchor/policy.py", '("require_last_push_approval", "require_dismiss_stale_reviews", "require_empty_bypass")', '("require_dismiss_stale_reviews", "require_empty_bypass")'),
    m("policy/shipped-approvals", "anchor/policy.json", '"required_approvals": 0,', '"required_approvals": 1,'),
    m("policy/shipped-last-push", "anchor/policy.json", '"require_last_push_approval": false,', '"require_last_push_approval": true,'),
    m("policy/shipped-pull-request-rule", "anchor/policy.json", '"pull_request",', '"pull_request_dropped",'),
    m("ruleset/pull-request-rule", "governance/ruleset-main.json", '"type": "pull_request",', '"type": "pull_request_disabled",'),
    m("ruleset/deletion-rule", "governance/ruleset-main.json", '"type": "deletion"', '"type": "deletion_disabled"'),
    m("ruleset/force-push-rule", "governance/ruleset-main.json", '"type": "non_fast_forward"', '"type": "non_fast_forward_disabled"'),
    m("ruleset/status-check-rule", "governance/ruleset-main.json", '"type": "required_status_checks",', '"type": "required_status_checks_disabled",'),
    m("ruleset/bypass-list", "governance/ruleset-main.json", '"bypass_actors": [],', '"bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],'),
    m("ruleset/enforcement", "governance/ruleset-main.json", '"enforcement": "active",', '"enforcement": "evaluate",'),
    m("ruleset/target-branch", "governance/ruleset-main.json", '"~DEFAULT_BRANCH"', '"refs/heads/other"'),
    m("ruleset/approval-count", "governance/ruleset-main.json", '"required_approving_review_count": 0,', '"required_approving_review_count": 1,'),
    m("ruleset/last-push", "governance/ruleset-main.json", '"require_last_push_approval": false,', '"require_last_push_approval": true,'),
    m("ruleset/thread-resolution", "governance/ruleset-main.json", '"required_review_thread_resolution": true', '"required_review_thread_resolution": false'),
    m("ruleset/stale-dismissal", "governance/ruleset-main.json", '"dismiss_stale_reviews_on_push": true,', '"dismiss_stale_reviews_on_push": false,'),
    m("ruleset/strict-checks", "governance/ruleset-main.json", '"strict_required_status_checks_policy": true,', '"strict_required_status_checks_policy": false,'),
    m("ruleset/integration", "governance/ruleset-main.json", '"integration_id": 15368', '"integration_id": 1'),
    m("policy/integration-pinned", "anchor/policy.json", '"required_status_check_integration_id": 15368', '"required_status_check_integration_id": 1'),
    off("accept/candidate-bound", "anchor/accept.py", 'if verdict.get("candidate_sha") != candidate:'),
    off("accept/schema-version", "anchor/accept.py", 'if verdict.get("verdict_version") != disclosure.VERDICT_VERSION:'),
    m("accept/consistent-verdict", "anchor/accept.py", 'elif (stated == "ACCEPT") != (verdict.get("reasons") == []):', "elif False:"),
    off("accept/policy-bound", "anchor/accept.py", 'if policy_sha256 is not None and verdict.get("policy_digest") != policy_sha256:'),
    off("preserve/exact-members", "anchor/preserve.py", "if sorted(map(str, names)) != sorted(disclosure.MEMBERS):"),
    m("preserve/consistency", "anchor/preserve.py", 'problems = ["PACKAGE_INCONSISTENT"] if any(package.get(k) != v for k, v in expected.items()) else []', "problems = []"),
    m("publog/overlapping-colons", "anchor/publog.py", '    while "::" in reduced:', '    if "::" in reduced:'),
    m("publog/no-abbreviations", "anchor/publog.py", 'keywords.setdefault("allow_abbrev", False)', 'keywords.setdefault("allow_abbrev", True)'),
    m("publog/usage-errors-are-fixed", "anchor/publog.py", '        emit(self._phase, "REFUSE", "USAGE_ERROR")\n', "        pass\n"),
    m("lint/secret-spellings", "anchor/pinlint.py", 'SECRET_REFERENCE = re.compile(r"secrets\\s*(?:\\.(?!GITHUB_TOKEN\\b)|\\[)|toJSON\\(\\s*secrets", re.IGNORECASE)', 'SECRET_REFERENCE = re.compile(r"secrets\\.(?!GITHUB_TOKEN\\b)")'),
    off("lint/test-seam", "anchor/pinlint.py", "if TEST_SEAM.search(line):"),
    off("lint/containers", "anchor/pinlint.py", "if CONTAINER_KEYS.match(line):"),
    off("lint/flow-steps-and-aliases", "anchor/pinlint.py", "if FLOW_STEP.match(line) or YAML_ALIAS.search(line):"),
    m("workflow/options-attached", ".github/workflows/qualify.yml", '            --candidate="$CANDIDATE_SHA" \\\n            --inputs-manifest="$INPUTS_MANIFEST" \\\n            --workdir', '            --candidate "$CANDIDATE_SHA" \\\n            --inputs-manifest "$INPUTS_MANIFEST" \\\n            --workdir'),
    m("workflow/verify-scope-dir", ".github/workflows/qualify.yml", '            --scope-dir "$RUNNER_TEMP/anchor-sandbox/candidate" \\\n            --evidence-dir "$RUNNER_TEMP/anchor-sandbox/evidence" \\\n            --verdict', '            --evidence-dir "$RUNNER_TEMP/anchor-sandbox/evidence" \\\n            --verdict'),
    m("workflow/audit-freeze", ".github/workflows/qualify.yml", ' \\\n            --capture "$RUNNER_TEMP/anchor-private/capture.json" \\\n            --policy anchor/anchor/policy.json\n\n      - name: Upload the public package', '\n\n      - name: Upload the public package'),
    off("governance/other-environment-secrets", "anchor/governance.py", "if forbidden & others:"),
    off("governance/organisation-secrets", "anchor/governance.py", "if not org_complete or forbidden & org:"),
    off("governance/environments-complete", "anchor/governance.py", "if total != len(environments):"),
    off("box/socket-parents", "anchor/sandbox_spec.py", 'if _reaches_docker_socket(fields.get("source", "")):'),
    m("verify/child-directory-bound", "anchor/verify.py", '\n        and _same_directory(layout.get("child"), child_dir)', ""),
    m("verify/private-roots-descendants", "anchor/verify.py", " or target in resolved.parents:", ":"),
    m("capture/nonce", "anchor/capture.py", 'record["nonce"] = secrets.token_hex(32)', 'record["nonce"] = "0" * 64'),
    m("verify/redacted-sandbox-digest", "anchor/verify.py", "sandbox_spec.public_digest_of(record)", "sandbox_spec.digest_of(record)"),
    m("lint/multi-line-expressions", "anchor/pinlint.py", "for match in EXPRESSION_BLOCK.finditer(text):", "for match in []:"),
    m("lint/yaml-suffix", "anchor/pinlint.py", '*root.rglob("*.yaml")', "*[]"),
    m("disclosure/view-honours-policy", "anchor/disclosure.py", 'dict(entry) if policy["disclosure"]["publish_floor_digests"]', "dict(entry) if True"),
]


def copy_tree(destination: Path) -> None:
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "*.pyc", "_old_*"
        ),
    )


def pytest_command(selectors: list[str], basetemp: Path) -> list[str]:
    return [
        sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider",
        "--basetemp", str(basetemp), *selectors,
    ]


def run_mutant(mutant: Mutant) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="mutant-") as directory:
        work = Path(directory) / "repo"
        copy_tree(work)
        target = work / mutant.path
        text = target.read_text(encoding="utf-8")
        if text.count(mutant.old) != 1:
            return "INVALID", f"found {text.count(mutant.old)} times"
        target.write_text(text.replace(mutant.old, mutant.new), encoding="utf-8")
        try:
            completed = subprocess.run(
                pytest_command(mutant.tests, Path(directory) / "bt"),
                cwd=work, capture_output=True, text=True, check=False, timeout=900,
            )
        except subprocess.TimeoutExpired:
            # A mutant that makes the code hang (a deleted loop body) has been noticed:
            # the suite did not pass.
            return "KILLED", "timeout"
        if completed.returncode == 0:
            return "SURVIVED", ""
        if completed.returncode == 1:
            return "KILLED", ""
        return "ERROR", completed.stdout[-300:]


def baseline() -> bool:
    with tempfile.TemporaryDirectory(prefix="baseline-") as directory:
        work = Path(directory) / "repo"
        copy_tree(work)
        selectors = sorted({test for tests in FAMILIES.values() for test in tests})
        completed = subprocess.run(
            pytest_command(selectors, Path(directory) / "bt"),
            cwd=work, capture_output=True, text=True, check=False,
        )
        if completed.returncode != 0:
            print(completed.stdout[-2000:])
        return completed.returncode == 0


def main(argv: list[str]) -> int:
    selected = [mutant for mutant in CATALOG if not argv or any(part in mutant.name for part in argv)]
    if not baseline():
        print("the unmutated suite does not pass; mutation results would mean nothing")
        return 2
    results: dict[str, tuple[str, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(run_mutant, mutant): mutant for mutant in selected}
        for future in concurrent.futures.as_completed(futures):
            mutant = futures[future]
            results[mutant.name] = future.result()
            print(f"{results[mutant.name][0]:9} {mutant.name}", flush=True)

    tally: dict[str, int] = {}
    for status, _ in results.values():
        tally[status] = tally.get(status, 0) + 1
    print("\n" + ", ".join(f"{count} {status}" for status, count in sorted(tally.items())))
    for name, (status, note) in sorted(results.items()):
        if status != "KILLED":
            print(f"  {status}: {name} {note}")
    return 0 if set(tally) <= {"KILLED"} else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

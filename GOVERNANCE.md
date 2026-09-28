# Governance

This repository is the trust root for Atlas release qualification. Nothing in the
code can defend that position — whoever can change the default branch can change
the judge. The defence is access control and review, which are facts about this
repository's settings, not properties the code proves about itself.

This file records what those settings must be, so that a wrong setting is a visible
discrepancy rather than an unstated assumption. **Everything here is available on
GitHub Free.** Nothing asks which plan the account is on; `anchor/governance.py`
asks whether the protection is *enforced*, and refuses if it cannot get a straight
answer.

## 1. Topology, and why it is safe to be public

| | visibility | why |
|---|---|---|
| `mameriku/atlas-trust-anchor` (this repo) | **public** | rulesets and environment branch policies are free on public repositories |
| `mameriku/atlas` (the target) | **private** | unchanged |

A public anchor's Actions logs and artifacts are readable by anyone without
authentication (verified: `GET /repos/{o}/{r}/actions/artifacts` answers `200`
anonymously). The earlier private-anchor design moved the candidate between jobs as
a git bundle artifact, so a public anchor would have published the private
repository. That finding (N14) stands and stays closed. What changed is that the
transport is gone rather than the disclosure being accepted:

* the candidate is fetched, frozen, sandboxed and judged on **one ephemeral runner**;
* the sandbox is a **container** on that runner, not a second job;
* the only bytes that leave are an **allow-listed public package** (see §6), built
  by the anchor from fields the anchor chose, and checked at the door;
* nothing a candidate produced is ever printed: the console carries fixed reason
  codes, bounded counts and digests, and nothing else.

`disclosure.private_transport` in `anchor/policy.json` has exactly one legal value,
`none`. There is no setting that permits private bytes to cross a public boundary,
and the workflow lint makes the old mistake unwritable: an `upload-artifact` step
may only upload from `public/` or `attestation/`.

## 2. Required branch protection

A ruleset on the default branch (`main`), applied from
[`governance/ruleset-main.json`](governance/ruleset-main.json):

| rule | required value |
|---|---|
| restrict deletions | on |
| block force pushes | on |
| require a pull request before merging | on |
| required approvals | **at least 1**, from someone who is not the last pusher |
| dismiss stale approvals on new commits | on |
| require last-push approval | on |
| require conversation resolution | on |
| require status checks to pass | on, up to date with the base branch: the check named `test`, **from the GitHub Actions integration (id 15368)** - a check identified by name alone can be satisfied by anyone who can post a commit status |
| bypass list | **empty**, and readable by the token that checks it |

The ruleset must cover the default branch, which contains `.github/workflows/**`
and `anchor/**`.

### The one thing that needs a second person

Requiring one approval **from someone who did not push the change** cannot be met
by a repository with a single collaborator: GitHub does not let an author approve
their own pull request, and the bypass list must stay empty. This requirement is
**not** lowered to fit. The free prerequisite is:

> **A second GitHub account with Write access to this repository, whose approval is
> the required review.** Collaborators on a public repository are free.

Until that account exists, `main` can be created (bootstrap step 1) but no later
change to `anchor/**` or `.github/workflows/**` can be merged, which is the intended
failure mode: an unreviewable judge stays as it was.

### Change control is not independent review

Two different things are easy to conflate, and this document keeps them apart:

| | what it is | who enforces it | what it proves |
|---|---|---|---|
| **Ruleset approval** | change control: who may merge into `main` | GitHub, mechanically | that some account other than the last pusher approved |
| **Independent review evidence** | a technical review by someone who did not author the change | a recorded review (SkillOS independent-review record, ADR-0004) | that a genuinely independent reviewer examined these exact bytes |

GitHub cannot tell whether two accounts belong to one person, so the ruleset alone
cannot establish independence, and it is not asked to. Consequently:

* A second account controlled by the **same person** satisfies the ruleset
  *mechanically* and is **not independent review evidence**. It must not be created for
  that purpose, must not be recorded as independent review, and nothing in this
  repository recommends one.
* The requirement is not lowered. If no genuinely independent human collaborator
  exists, N2 stays **BLOCKED**; the ruleset is not weakened, and a same-person account is
  not accepted as the resolution.
* Independent technical review remains separate evidence bound to a candidate commit and
  tree. Its reviewer class is recorded honestly - a fresh model reviewer with no
  authorship of the change is *independent of the author* but is not a human, and is
  recorded as exactly that. The two review rounds of the initial candidate were of that
  class; they are evidence about the bytes, not an approval of them.
* What only a human can give, and the ruleset requires, is **approval as change
  control**: an accountable person other than the pusher accepting the change into the
  trust root.

A non-empty bypass list is not automatically wrong, but it is an exception and must
be recorded here with who holds it and why. There is no such exception today.

## 3. Bootstrap

In order. Steps 1–3 are the trust-on-first-use moment: a human reviews what is
pushed, once, and everything after is verified against what that review established.

1. **Create `mameriku/atlas-trust-anchor` as PUBLIC and empty** (no README, licence
   or `.gitignore`, no initial commit) and read its numeric id:
   `gh api repos/mameriku/atlas-trust-anchor --jq .id`. It is `1392950051`.
2. **Bind the id, then push.** `anchor/policy.json` carries it as
   `anchor.repository_id`, committed *before* the first push, so the first public
   `main` already names its own repository; review it like any other change. This
   repository's history is a single parentless root commit that carries it: nothing
   earlier is pushed with it.
   Nothing is protected yet, and the governance check refuses until steps 3–5 have
   put the ruleset, the environment and the credential in place.
3. **Add the second collaborator** (§2), then **apply the ruleset**:

   ```
   gh api -X POST repos/mameriku/atlas-trust-anchor/rulesets --input governance/ruleset-main.json
   ```

4. **Create the environment** that will hold the credential and release it to `main`
   and nothing else:

   ```
   gh api -X PUT  repos/mameriku/atlas-trust-anchor/environments/atlas-qualification \
     -F 'deployment_branch_policy[protected_branches]=false' \
     -F 'deployment_branch_policy[custom_branch_policies]=true' \
     -F can_admins_bypass=false
   gh api -X POST repos/mameriku/atlas-trust-anchor/environments/atlas-qualification/deployment-branch-policies \
     -f name=main -f type=branch
   ```

5. **Create the target credential** (§4) as an **environment** secret, never a
   repository secret. The gate checks: if `ATLAS_DEPLOY_KEY` or
   `ANCHOR_GOVERNANCE_TOKEN` also exists as a **repository secret** it refuses, because
   a repository secret is released to every workflow on every branch and a write
   collaborator could print it from a branch of their own, with no review - and with
   the lint that would catch it inside the very file they edited.
6. **Dispatch one run** against a known-good Atlas commit and confirm ACCEPT, then
   confirm the attestation with `anchor/accept.py` (§7).
7. **Dispatch the refusal cases** in §8 and confirm each one refuses.

## 4. The target credential

Atlas is private and `GITHUB_TOKEN` is scoped to the repository running the
workflow, so reading Atlas needs a credential of its own.

**A repository-scoped, read-only deploy key.** It grants access to `mameriku/atlas`
and nothing else, cannot write, and cannot speak to the GitHub API at all — so it is
useless for anything but the one `git fetch` it exists for. It is preferred over a
personal access token, which is user-wide in reach unless carefully scoped and can
be used for far more. A token would be adopted only if the deploy key were shown
unable to serve the required Git operation; it is not.

Create it on your own machine, so the private half never touches this repository or
a chat window. It exists on disk for the length of these commands only:

```
ssh-keygen -t ed25519 -N "" -C "atlas-trust-anchor (read-only)" -f "$TMP/atlas_anchor_key"
gh repo deploy-key add "$TMP/atlas_anchor_key.pub" -R mameriku/atlas -t "atlas-trust-anchor (read-only)"
gh secret set ATLAS_DEPLOY_KEY --env atlas-qualification -R mameriku/atlas-trust-anchor < "$TMP/atlas_anchor_key"
rm -f "$TMP/atlas_anchor_key" "$TMP/atlas_anchor_key.pub"
```

`gh repo deploy-key add` registers the key **read-only** unless `--allow-write` is
passed. Do not pass it.

How the run keeps it:

* it is bound as **one step's** environment variable — the capture step — never a
  job's or the workflow's, and no other step's environment names it;
* `anchor/target.py` writes it to a 0600 file outside the workspace for the length
  of one `git fetch`, overwrites it, and removes it in a `finally`;
* git is started with a **rebuilt** environment that contains neither this key nor
  any token; the key reaches git only as a file named in `GIT_SSH_COMMAND`;
* the server is authenticated against the host key **pinned in policy**
  (`credential.host_key`), never trusted on first use;
* afterwards the fetched repository's config is audited and refused if it names a
  remote or a credential, and the container is started with no environment at all.

Rotate it on a calendar. If it is ever exposed, delete the deploy key from
`mameriku/atlas` first, then the secret.

### The governance token (only if the first live run asks for it)

`GITHUB_TOKEN` may or may not be allowed to read this repository's rulesets and
environments; GitHub's REST reference does not say, and `administration` is not a
permission a workflow can grant its own token. It does not need resolving in
advance, because the failure is a refusal that names the endpoint. If the gate
refuses with a `403`, add a **fine-grained personal access token restricted to this
one repository** with read-only repository permissions — Administration (rulesets),
Actions (environments), Secrets (to confirm the credential is not also a repository
secret), plus Metadata — as the *environment* secret `ANCHOR_GOVERNANCE_TOKEN`. Add
only what the refusal names. It is read-only, cannot touch Atlas, and
`anchor/governance.py` prefers it when present.

A ruleset response that does not include `bypass_actors` is **not** read as an empty
bypass list: GitHub omits the field from callers who may not see it, and treating
omission as emptiness would turn a token's lack of permission into a passing check.
That case refuses, and is the most likely reason a first run wants this token.

## 5. What the run enforces about itself

`gate.py` runs before the credential is touched, and `capture.py` refuses unless the
observation it records still establishes all of:

* repository id **and** name, visibility `public`, default branch `main`
* deletion and force-push blocked; a pull request required with ≥ 1 approval
  **from someone other than the last pusher**, stale approvals dismissed; the `test`
  status check required, from the GitHub Actions integration, and up to date
* the values RECORDED are what GitHub reported (the weakest pull-request rule in force,
  the `private` flag as returned), not policy's own numbers copied back - so the
  verifier is never comparing policy with itself
* every ruleset `active`, targeting a branch, with a **readable, empty** bypass list
* the environment that holds the credential releases it to `main` and nothing else,
  and administrators cannot bypass it (`can_admins_bypass` is false)
* the credential exists **only** as an environment secret (no repository secret of the
  names in `environment_only_secrets`)
* the run is `workflow_dispatch`, at `refs/heads/main`, started by a principal named
  in `trigger.actors`, on a **GitHub-hosted** runner

A failure, an unreadable answer, or an ambiguous one is a refusal. The observation
travels inside the capture, so it inherits the capture digest, and the verifier
refuses any run whose capture carries no positive observation.

## 6. What may become public

Exactly five files, checked before upload by `anchor/publish.py`:

| file | what it is |
|---|---|
| `verdict.json` | ACCEPT/REFUSE, fixed reason codes, identities, counts, digests |
| `public-capture.json` | the candidate commit and tree, the floor inputs' digests, governance |
| `evidence.json` | the sealed package binding all of the above |
| `policy.json` | this anchor's own policy (already public in the tree) |
| `anchor-tree.tar` | `git archive` of this public repository at the commit that ran |

Each JSON document has an **exact** key set defined once in `anchor/disclosure.py`;
a field nobody listed cannot be published. The projection of the private freeze is
*constructed* from listed fields, never filtered.

**A digest is an oracle for anyone who can guess.** Publishing the sha256 of a small
private file - a PIN, a token, a flag - does not protect it, it *confirms* it: a
review reproduced recovering `PIN=4821` from ten thousand guesses against a published
digest. The same holds for any hash of a structure that *contains* that digest, which
is why the freeze's own digest and the evidence file's digest are not published either.
So only inputs the anchor's own public policy names (the floor, which is source code)
are described by digest. An **extra input** a caller added to the manifest is described
by nothing except that N were asked for: no path, no digest, and no separate
found/absent count that would reveal whether a single path exists. (The verdict still
says whether every input was present; that is what a verdict is for.) The public
evidence commitment is a digest over a *view* of the evidence that omits everything
about extras.

Two facts stay visible regardless: GitHub prints a step's `env:` block in its log
header, so **the manifest paths themselves are public through the run log** - do not
put a sensitive file name in a manifest - and the candidate commit and tree ids are
public.

A tripwire additionally refuses the run if any private file the runner holds - or any
long line of one - appears in any public document, raw or JSON-escaped, or if any
digest of an extra input does. A line that also appears in the anchor's own public
policy or tree is already public and is not counted. The tripwire is not what keeps the
boundary; the allow-list is. It exists so a mistake in the allow-list is a refused run
and not a disclosure, and it refuses when it has nothing to compare against rather
than passing.

## 7. Provenance and evidence retention

Artifacts expire, and a verdict is only as good as the proof of who made it.

**Attestation.** After `qualify` publishes a digest of the public directory, a second
job that holds no credential and no private byte recomputes it and has GitHub sign
`verdict.json` with `actions/attest-build-provenance` (Free on public repositories).
The signature covers the verdict alone; the candidate's bytes are never in that job.
The bundle is uploaded beside the verdict, and is verifiable **offline**.

**Acceptance.** A consumer of a verdict must run

```
python -I -S -B anchor/accept.py --policy anchor/policy.json \
    --verdict verdict.json --bundle attestation.jsonl --candidate <the 40-hex commit>
```

`--candidate` is required. A validly signed ACCEPT for commit X is not evidence about
commit Y, and the artifacts are public, so without it every genuine verdict ever issued
could be replayed as proof of any other commit. The verdict must also carry this
schema version, be internally consistent (an ACCEPT has no reasons), and - unless
`--allow-older-policy` is given - have been made under the policy the consumer holds.

which asks `gh attestation verify` to check the signature, then reads **only the
signing certificate** — never the predicate, which the GitHub documentation is
explicit is user-controllable — and requires it to name this repository (by URI and
numeric id), the `main` ref, this workflow, the `workflow_dispatch` trigger, a
GitHub-hosted runner, public visibility, the workflow commit the verdict names, and
the run and attempt it names. It is a provenance check, not a second judge, and it
does not recurse: the trusted thing is GitHub's signer.

**Retention.** Copy `public-*/` and `attestation-*/` somewhere durable before the
retention window closes. The package checks itself offline
(`anchor/preserve.py check`), and its `anchor-tree.tar` makes the evaluator bytes
recoverable even if this repository's history is later rewritten.

## 8. Refusal cases to re-confirm after any change

Each of these must refuse. A change that makes one pass is a regression in the trust
boundary, not a convenience. All are covered by the suite; running them against the
live workflow after bootstrap is step 7 of §3.

1. dispatch at `ref` = any branch other than `main`
2. dispatch at `ref` = a tag
3. a branch that edits only `anchor/verify.py`
4. a branch that edits only `.github/workflows/qualify.yml`
5. a candidate that deletes a path in `required_inputs_floor`
6. a candidate whose child writes flawless evidence and then exits non-zero
7. a manifest naming one trivial path (must still qualify the whole floor)
8. a dispatch by an account not named in `trigger.actors`
9. a sandbox record whose command lacks any required hardening flag

Cases 1–4 are refused by the **environment**: a workflow on any other ref is stopped
before it has a step to run, so the credential is not reachable by a branch that
edited the workflow to skip its own gate.

## 9. Updating the anchor

Changes to `anchor/**` and `.github/workflows/**` go through a pull request with an
independent approval, and the `test` check must pass. There is no dispatch input that
selects an evaluator revision, and there must never be one: the evaluator is whatever
is on the protected branch at the moment GitHub resolves the workflow, and the
identity gate refuses any run where that is not true.

`.github/workflows/test.yml` runs on pull requests, **including from forks**, so it is
secretless by construction: no secret, no environment, no `id-token`, and the lint
refuses a secret reference in any workflow but the qualification one.

When a pinned action is upgraded, the new pin is a full 40-hex commit SHA with the
version in a trailing comment. `anchor/pinlint.py` runs inside the workflow itself and
fails the run on a tag, a short SHA, a `continue-on-error`, shell tracing or an
environment dump, a secret used other than as one step's environment binding, an
upload from outside `public/`/`attestation/`, docker in a workflow, or a workflow
expression spliced into a shell command.

## 10. What this governance cannot do

It cannot make GitHub trustworthy, and it does not try. The following are trusted
without proof, and are named so that they are assumptions on a list rather than gaps
nobody wrote down:

* GitHub's control plane, its access control, and the account that administers this
  repository
* GitHub's Sigstore signer, and the certificate it issues to a workflow
* the GitHub-hosted runner image, its `git`, `ssh` and `python3`
* **the container runtime, the Linux kernel and the hypervisor.** A sandbox escape is
  outside what this repository can prove, and no verifier of Docker is built here. The
  box is hardened, audited from its command line, and given nothing worth escaping
  to — but a kernel or runtime compromise is an infrastructure trust assumption, not a
  property of this code.

### Residuals that are accepted, stated

* **The freeze's digest is public** (the capture step prints it and the verify step's
  `env:` echoes it), so the private capture record carries a random 256-bit `nonce`
  that no public value depends on; without it the digest would confirm a guess of any
  extra input's content. The nonce is never published.
* **Whether an extra input exists is visible through the verdict itself** (`INPUT_ABSENT`
  is a reason code) and its path is visible in the run log. Nothing published adds to
  that, but nothing can remove it without hiding the verdict.
* **A developer machine's docker config** (`~/.docker`) can still select a daemon; the
  hosted runner has none, and the audit refuses any client option before `run`.
* **The evidence directory has no total quota**, only a per-file cap and a wall clock,
  so a hostile child can fill the runner's disk for two minutes. The result is a
  refusal, not a pass.
* The `--source`, `--uid`, `--gid` and `--docker-command` options exist so the suite
  can run without GitHub or a container runtime; the workflow lint refuses any
  workflow that uses one.

## 11. The live-only unknowns

Three things only a real run can settle. Each fails closed:

1. whether `GITHUB_TOKEN` can read this repository's rulesets and environments (§4:
   a refusal that names the endpoint; supply `ANCHOR_GOVERNANCE_TOKEN`)
2. the exact field names in the attestation certificate `gh` prints (matching is
   case-insensitive and a missing field refuses; a first live run confirms the set)
3. that the pinned Docker image runs as the runner's user with the hardened flags on
   the `ubuntu-latest` image

## History

The first design made both repositories private, which made ruleset enforcement
depend on the account's plan. That design was kept as internal research. It is not
part of this repository and is not reachable through its commit graph, which begins
at a single root commit. Qualification here is bound to the tree, not to commit
history: no check in this repository depends on a commit's parent, ancestry or
message. This document supersedes the first design's governance; the N14 disclosure
finding is unchanged and is the reason for §1 and §6.

# atlas-trust-anchor

The judge for Atlas release qualification. It lives here, in a different
repository from the thing it judges, because that is the only arrangement that
survived review.

**This repository is public. The thing it judges is private.** That is safe because
no private byte is ever transported through a public surface — see below.

## Why this repository exists

Atlas candidates were qualified by a Python file in a session scratch directory.
It had no commit, no reviewer, and it decided its own verdict. Nine defects were
found in it. Each repair was defeated by a different spelling of one idea: the
thing being judged could reach the judge.

Two later attempts moved the judge into the Atlas repository itself. Both were
broken the same way, one level up each time:

- the first let the caller pass `--anchor <commit>`, so a candidate carrying a
  three-line always-accept verifier could be named as its own judge
- the second resolved a *configured ref name* — `origin/main` — inside a
  **caller-supplied repository**. A reviewer built a repository containing the
  byte-identical launcher beside a hostile verifier, pointed the local
  remote-tracking ref at it, and the unmodified launcher printed
  `VERDICT ACCEPTED` and stamped the record authoritative

A ref name is not a trust root when the caller supplies the object store it is
resolved in. Inside one repository there was nowhere left to stand.

## The arrangement

```
Atlas candidate SHA (a dispatch input: what is judged, never who judges)
        |
        v
  qualify  -- ONE ephemeral GitHub-hosted runner; private bytes never leave it
        |
        +-- gate      identity, trigger, GitHub-hosted, and this anchor's own
        |             governance - all BEFORE the credential is touched
        |
        +-- capture   the only step holding the read-only deploy key. Fetches
        |             exactly the requested commit, destroys the key, freezes the
        |             scope from git's object store, exports ONLY that scope
        |
        +-- sandbox   a hardened container: no network, non-root, read-only root,
        |             all capabilities dropped, no new privileges, no docker socket,
        |             no credential, no environment; the candidate mounted
        |             read-only, one writable evidence directory. Its output is
        |             counted and discarded, never printed
        |
        +-- verify    trusted, after the sandbox is gone. No subprocess, no network,
        |             and nothing it imports has either. Compares every claim with
        |             the freeze and the host's record; the child never decides
        |
        +-- publish   an allow-listed public package, checked at the door
        |
        v
  attest   a second runner with no credential and no private byte: GitHub signs
           the sanitized verdict. Anyone can verify it offline.
        |
        v
  ACCEPT / REFUSE
```

The candidate chooses **what** is judged. It never chooses **who** judges. It may
also *widen* a run by naming extra inputs; it can never narrow one, because the
required scope is the anchor's floor unioned with whatever was asked for.

## Why a public anchor does not publish the private candidate

Artifacts and run logs on a public repository are readable by anyone without
authentication. The first version of this design put the candidate in an artifact so
that two jobs could share it; on a public repository that is a disclosure. There is
now only one job that touches private bytes, so there is nothing to ship between jobs,
and the boundary is a container on the same disposable machine.

Confidentiality is structural, not a matter of masking:

- an entry point prints only a phase, `PASS`/`REFUSE`/`INFO`, a fixed reason code,
  bounded integers and hex digests — there is no free-text channel to leak through
- everything the candidate side produced is treated as a claim and reduced to fixed
  codes before anyone can quote it
- what is uploaded is a directory of documents with **exact** key sets, built by the
  anchor from fields it chose, plus a tripwire that refuses the run if any private
  file (or any long line of one) appears in any of them
- the workflow lint refuses an artifact upload from anywhere but `public/` and
  `attestation/`, so the original mistake is unwritable

The suite drives a synthetic private candidate full of unique sentinels through every
entry point — success and every failure path, with a hostile child that echoes,
tracebacks, and writes malformed evidence — and scans the console, every public file,
the attestation subject, and every reason code. See `tests/test_disclosure.py`.

## What is trusted, stated finitely

Trusted:

- GitHub's access control on this repository: who may push to its default branch,
  and the review required before that happens
- GitHub Actions running the workflow **from this repository**, not from the
  candidate, on a **GitHub-hosted** runner
- GitHub's environment protection: the credential is released to `main` and nothing
  else, so a workflow on another ref never has a step to run
- this repository's own committed bytes, resolved by GitHub at checkout
- git's content-addressed object store for reading candidate bytes by SHA
- the host's own record of the sandbox run: the child's exit is observed by the
  anchor, not reported by the child
- GitHub's Sigstore signer, for the provenance of the verdict
- the runner image's own `git`, `ssh` and `python3`

Untrusted:

- the Atlas candidate, its files, and anything it ships under any name
- everything the child says about itself, including any verdict it writes
- any file the child leaves anywhere except the one evidence directory it was given,
  and that directory's contents, all of which are a claim
- the ambient environment of the child, which is empty

### The infrastructure trust assumption

A compromise of the **GitHub-hosted runner, the container runtime, the Linux kernel
or the hypervisor** is outside what this repository proves, and it is an
**infrastructure trust assumption** rather than a gap. The box is hardened, audited
from its command line by code that shares nothing with the code that builds it, and
given nothing worth escaping to — but no verifier of Docker or of Linux is built
here, because that would be a verifier of a verifier of a verifier, and the recursion
does not end. It is named so that it is an assumption on a list.

## What this does not claim

The judge's code is protected by **access control and review**, which are governance
facts enforced by GitHub, not properties this code can prove about itself. What *is*
signed is the **verdict**: GitHub's signer attests to it from inside this
repository's workflow run, and a consumer checks the signing certificate offline
(`anchor/accept.py`) — never the attestation predicate, which the workflow could have
written freely.

It does not claim a hostile child cannot misbehave inside its own process. It
claims such misbehaviour cannot buy an ACCEPT, because the verdict is computed
outside the sandbox, from evidence, after the child is gone, by code the child could
not reach.

And it cannot bootstrap itself. Whoever can push to this repository can change
the judge. That is the finite, nameable root the previous attempts lacked — not
the absence of a root, but a root that can be pointed at and defended.

## Governance

The settings that make this repository a trust root — the ruleset, review, an empty
and *readable* bypass list, the environment that releases the credential, the
read-only deploy key, the bootstrap order — are in [GOVERNANCE.md](GOVERNANCE.md).
Everything in it is available on GitHub Free, and it is written for one operator: no
second account is required. What that gives up - no second party approves a change to
the judge - is stated in GOVERNANCE.md, not hidden.

Until `anchor/policy.json` names this repository's numeric id, every entry point
refuses. That is deliberate: an anchor that does not know its own identity cannot
assert it.

## Layout

| path | role |
|---|---|
| `anchor/policy.py`, `policy.json` | identity, trigger, credential, box and scope floor |
| `anchor/governance.py` | asks GitHub whether the protection is real (network) |
| `anchor/governance_record.py` | reads a recorded observation (no network) |
| `anchor/gate.py` | identity and governance, before the credential |
| `anchor/target.py`, `capture.py` | fetch one commit, destroy the key, freeze and export the scope |
| `anchor/sandbox_spec.py` | what the box must be, and the pure audit of it |
| `anchor/sandbox.py` | builds and runs the box; counts and discards output |
| `anchor/runner.py` | the child: observes, decides nothing |
| `anchor/evidence.py` | the hostile evidence directory, reduced to fixed codes |
| `anchor/verify.py` | the verdict |
| `anchor/disclosure.py`, `publish.py` | the public allow-list, the tripwire, the digest |
| `anchor/preserve.py` | the offline-checkable evidence package |
| `anchor/accept.py` | the consumer's attestation check |
| `anchor/publog.py` | the only thing a trusted script may say on a public console |
| `anchor/pinlint.py` | the workflow lint |
| `tests/` | the adversarial suite; `tests/mutation.py` proves the predicates are defended |

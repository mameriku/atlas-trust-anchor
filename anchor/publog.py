"""The only thing a trusted entry point may say on a public console.

This repository is public, so its Actions logs are an external disclosure surface
readable by anyone without authentication. A run judges a PRIVATE repository, and
GitHub's secret masking is a convenience that cannot be the confidentiality
boundary: it matches literal registered values, and nothing here can register the
contents of a private file, a filename, a commit message or a traceback.

So confidentiality is structural. An entry point never prints a value it received
from, or derived from, the target. It prints what this module lets it print: a
phase, PASS / REFUSE / INFO, a fixed reason code, and integers and digests. There
is no free-text channel to leak through, and a test drives hostile input through
every entry point and scans what came out.

Two kinds of failure exist and they are kept apart on purpose:

  PolicyError    a fact about the anchor itself - its policy, its identity, its
                 governance, a dispatch input. Public by construction, so its
                 message may be shown, after the same character filter.
  TargetError    anything learned from the private repository or from the code that
                 ran against it. Only its fixed code is ever shown.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Callable, NoReturn, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy import PolicyError  # noqa: E402

PHASES = frozenset(
    {"GATE", "CAPTURE", "SANDBOX", "VERIFY", "PRESERVE", "PINLINT", "PUBLISH", "ATTEST", "ACCEPT"}
)
STATUSES = frozenset({"PASS", "REFUSE", "INFO"})

CODE = re.compile(r"\A[A-Z][A-Z0-9_]{2,47}\Z")
_DIGEST = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_KEY = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")

# Anchor-side messages only. Deliberately narrow: no control characters, so a
# dispatch input cannot smuggle a `::command::` line or a newline into the log, and
# none of `#`, `[`, `]`, whose combination (`##[...]`) is a legacy command form the
# runner has parsed at the start of a line.
_SAFE_DETAIL = re.compile(r"[^A-Za-z0-9 _.,:;/@=()'\"{}+*%&!?~-]")
_MAX_DETAIL = 400
_MAX_INT = 10**9


class TargetError(RuntimeError):
    """Something learned from the private target, or from code run against it.

    What leaves the process is `code`, and nothing else. The free-text detail is
    kept on the instance for a debugger and is never rendered by this module.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        if not CODE.match(code):
            raise ValueError(f"{code!r} is not a reason code")
        super().__init__(code)
        self.code = code
        self.detail = detail


def _clean(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if not 0 <= value <= _MAX_INT:
            raise ValueError("a count outside the bounded range")
        return str(value)
    if isinstance(value, str) and _DIGEST.match(value):
        return value
    raise ValueError("only bounded integers, booleans and hex digests may be printed")


def line(phase: str, status: str, code: str | None = None, **fields: object) -> str:
    """One console line, or a programming error if it is not allow-listed."""
    if phase not in PHASES or status not in STATUSES:
        raise ValueError("unknown phase or status")
    parts = [f"[{phase}]", status]
    if code is not None:
        if not CODE.match(code):
            raise ValueError(f"{code!r} is not a reason code")
        parts.append(f"code={code}")
    for key in sorted(fields):
        if not _KEY.match(key):
            raise ValueError(f"{key!r} is not a field name")
        parts.append(f"{key}={_clean(fields[key])}")
    return " ".join(parts)


def emit(phase: str, status: str, code: str | None = None, **fields: object) -> None:
    print(line(phase, status, code, **fields), flush=True)


def safe_detail(message: str) -> str:
    """An anchor-side message reduced to a charset that cannot forge a log command."""
    reduced = _SAFE_DETAIL.sub("?", " ".join(str(message).split()))
    # `:::` is `::` after one pass, so collapse until nothing changes: a single
    # replace() leaves overlapping runs behind.
    while "::" in reduced:
        reduced = reduced.replace("::", ":")
    return reduced[:_MAX_DETAIL]


def emit_policy_refusal(phase: str, code: str, message: str) -> None:
    """A PolicyError is about the anchor, so it may explain itself - filtered."""
    print(f"{line(phase, 'REFUSE', code)} detail={safe_detail(message)}", flush=True)


class Parser(argparse.ArgumentParser):
    """An argument parser whose errors are a fixed code, not an echo of the input.

    argparse quotes the offending argument in its error message, and the arguments
    of these scripts include dispatch inputs - text a caller chose, on a public
    console. An input shaped like an option (`--c=` then a newline and `::error::`)
    is enough to get a forged workflow command printed at the start of a line. So
    abbreviations are off, and every usage error is one fixed line.
    """

    def __init__(self, phase: str, description: str | None = None, **keywords: object) -> None:
        keywords.setdefault("allow_abbrev", False)
        keywords.setdefault("add_help", False)
        super().__init__(description=description, **keywords)  # type: ignore[arg-type]
        self._phase = phase

    def error(self, message: str) -> NoReturn:
        emit(self._phase, "REFUSE", "USAGE_ERROR")
        raise SystemExit(2)


def guarded(phase: str, main: Callable[[Sequence[str]], int], argv: Sequence[str]) -> int:
    """Run an entry point so that no traceback can reach the console.

    An unexpected exception is exactly the case where a library helpfully quotes
    the offending bytes - a UnicodeDecodeError shows them, a parser shows a
    fragment. That text may be private. It is replaced by a fixed code.
    """
    try:
        return main(argv)
    except SystemExit:
        raise
    except PolicyError as error:
        # A fact about the anchor, public by construction. Shown, filtered - this
        # is how "the interpreter is not isolated" reaches an operator instead of
        # being flattened into an anonymous internal error.
        emit_policy_refusal(phase, "ANCHOR_REFUSED", str(error))
        return 2
    except BaseException:  # noqa: BLE001 - the point is that nothing escapes
        emit(phase, "REFUSE", "INTERNAL_ERROR")
        return 2

"""Find probable targets in a command line. Conservative: unknown shapes fail closed."""
from __future__ import annotations

import os
import re

from .scope import HOST_RE, NOT_TLD_EXT, normalise_target

LIST_FLAGS = {"-il", "-l", "--list", "--target-file", "--targets-file", "--input-list"}
RANDOM_FLAGS = {"-ir"}
IP_LIKE = re.compile(r"^[0-9a-f:.\[\]]+(/\d{1,3})?(:\d+)?$", re.I)


def _candidates(tok):
    """Strings inside one argv token that might be a target."""
    out = []
    parts = [tok]
    if tok.startswith("-") and "=" in tok:
        parts = [tok.split("=", 1)[1]]
    elif tok.startswith("-"):
        return []
    for p in parts:
        if "@" in p and "://" not in p:
            p = p.split("@", 1)[1]
        for piece in p.split(","):
            if piece:
                out.append(piece)
    return out


def extract_targets(argv, read_file=None):
    """Returns (targets, problems). `problems` are reasons the command cannot be verified."""
    targets, problems = [], []
    read_file = read_file or _read_lines
    expect_list = False
    for tok in argv[1:]:
        low = tok.lower()
        if low in RANDOM_FLAGS or low.startswith("-ir"):
            problems.append("random target selection (-iR) cannot be checked against a scope")
            continue
        if low in LIST_FLAGS:
            expect_list = True
            continue
        if expect_list:
            expect_list = False
            try:
                for line in read_file(tok):
                    targets.append(line)
            except OSError as e:
                problems.append(f"cannot read target list {tok!r}: {e.strerror}")
            continue
        for c in _candidates(tok):
            if "://" in c:
                targets.append(c)
                continue
            if c.startswith(("./", "../", "~")) or (os.sep in c and not re.fullmatch(r"[0-9a-fA-F:.\[\]]+/\d{1,3}", c)):
                continue
            base = c
            if base.count(":") == 1 and IP_LIKE.match(base) is None:
                base = base.split(":")[0]
            try:
                kind, _ = normalise_target(base)
            except ValueError:
                continue
            if kind == "host" and base.rsplit(".", 1)[-1].lower() in NOT_TLD_EXT:
                continue
            if kind in ("ip", "net", "host"):
                if kind == "ip" and re.fullmatch(r"\d+\.\d+", base):
                    continue
                targets.append(c)
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq, problems


def _read_lines(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]

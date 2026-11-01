"""Append-only, hash-chained JSON-lines log.

Each entry's hash covers its own content and the previous hash. Editing or
removing an entry in the middle breaks the chain. Truncating the end, or
rewriting the whole file, is only detectable if you recorded the head hash
elsewhere (see `verify --expect-head`).

Optionally an entry is also sealed with an HMAC-SHA256 of its hash under a
secret key (`--key-file`). Someone who rewrites the whole file but does not
hold the key cannot produce valid seals. The key is symmetric: whoever can
verify can also forge, so a seal is not proof of who wrote an entry.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone

GENESIS = "0" * 64
try:
    import fcntl
except ImportError:          # Windows: single writer assumed
    fcntl = None


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def entry_hash(entry):
    body = {k: v for k, v in entry.items() if k not in ("hash", "mac")}
    return hashlib.sha256(canonical(body).encode("ascii")).hexdigest()


MIN_KEY_BYTES = 16


def load_key(path):
    """Read a key file (surrounding whitespace is ignored). Raises ValueError if unusable."""
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
    except OSError as e:
        raise ValueError(f"key file {path}: {e.strerror}") from e
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"key file {path}: key is shorter than {MIN_KEY_BYTES} bytes; create one with `scopekeeper keygen`")
    return key


def generate_key(path):
    """Write 32 random bytes as hex to a new file readable only by the owner."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(secrets.token_hex(32) + "\n")


def seal(key, entry_hash_hex):
    return hmac.new(key, entry_hash_hex.encode("ascii"), hashlib.sha256).hexdigest()


def read_entries(path):
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"line {n}: not valid JSON ({e.msg})") from e
    return entries


def verify(path, expect_head=None, key=None):
    """Returns {"ok", "entries", "head", "error", "sealed", "seals_verified"}.

    `sealed` is how many entries carry a seal. With `key`, every entry must
    carry a valid seal; without it, seals are counted but cannot be checked
    (`seals_verified` is False).
    """
    try:
        entries = read_entries(path)
    except (OSError, ValueError) as e:
        return {"ok": False, "entries": 0, "head": None, "error": str(e), "sealed": 0, "seals_verified": False}
    sealed = sum(1 for e in entries if isinstance(e, dict) and "mac" in e)

    def fail(msg, head=None):
        return {"ok": False, "entries": len(entries), "head": head, "error": msg, "sealed": sealed, "seals_verified": False}
    prev = GENESIS
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or e.get("seq") != i + 1:
            return fail(f"entry {i + 1}: sequence number is not {i + 1}")
        if e.get("prev") != prev:
            return fail(f"entry {i + 1}: previous-hash link is broken")
        if e.get("hash") != entry_hash(e):
            return fail(f"entry {i + 1}: content does not match its hash")
        if key is not None:
            mac = e.get("mac")
            if not isinstance(mac, str) or not hmac.compare_digest(mac, seal(key, e["hash"])):
                return fail(f"entry {i + 1}: seal is missing or does not match the key")
        prev = e["hash"]
    if expect_head and expect_head != prev:
        return fail("head hash differs from the one you recorded: entries were added, removed or rewritten", prev)
    return {"ok": True, "entries": len(entries), "head": prev, "error": None, "sealed": sealed, "seals_verified": key is not None and bool(entries)}


def append(path, kind, data, actor, now=None, key=None):
    """Append one entry and return it. Refuses to extend a broken chain.

    With `key` the entry is sealed. A log is either sealed throughout or not at
    all: a sealed log refuses an unsealed append, and a key refuses to extend a
    log whose existing entries do not verify under it.
    """
    now = now or datetime.now(timezone.utc)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a+", encoding="utf-8") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        if lines:
            v = verify(path, key=key)
            if not v["ok"]:
                raise ValueError(f"log is not intact, refusing to append: {v['error']}")
            if key is None and v["sealed"]:
                raise ValueError("log is sealed; pass --key-file so the new entry is sealed too")
            last = json.loads(lines[-1])
            prev, seq = last["hash"], last["seq"] + 1
        else:
            prev, seq = GENESIS, 1
        entry = {"seq": seq, "ts": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "actor": actor, "kind": kind, "data": data, "prev": prev}
        entry["hash"] = entry_hash(entry)
        if key is not None:
            entry["mac"] = seal(key, entry["hash"])
        fh.write(canonical(entry) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
        return entry


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

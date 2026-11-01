from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from . import __version__, chain
from .extract import extract_targets
from .scope import ScopeError, check_target, load_scope, parse_time

TEMPLATE = {
    "engagement": "Example engagement (replace)",
    "authorized_by": "Name and role of the person who authorised this test, and the reference of the written authorisation",
    "window": {"start": "2026-11-01T09:00:00Z", "end": "2026-11-05T17:00:00Z"},
    "in_scope": {"domains": ["app.example.com", "*.test.example.com"], "cidrs": ["10.10.0.0/24"], "ips": []},
    "out_of_scope": {"domains": ["payments.example.com"], "cidrs": [], "ips": ["10.10.0.1"]},
}


def _now(args):
    return parse_time(args.at, "--at") if getattr(args, "at", None) else datetime.now(timezone.utc)


def _key(args):
    path = getattr(args, "key_file", None) or os.environ.get("SCOPEKEEPER_KEY_FILE")
    return chain.load_key(path) if path else None


def _actor(args):
    return args.actor or getpass.getuser()


def cmd_init(a):
    if os.path.exists(a.file) and not a.force:
        print(f"scopekeeper: {a.file} exists (use --force to overwrite)", file=sys.stderr)
        return 2
    with open(a.file, "w", encoding="utf-8") as fh:
        json.dump(TEMPLATE, fh, indent=2)
        fh.write("\n")
    print(f"wrote template {a.file}. Edit it to match your written authorisation.")
    return 0


def cmd_check(a):
    scope, now = load_scope(a.scope), _now(a)
    results = [check_target(scope, t, now) for t in a.targets]
    if a.json:
        print(json.dumps({"scope_sha256": scope["raw_sha256"], "results": results}, indent=2))
    else:
        for r in results:
            print(f"{'IN ' if r['verdict'] == 'in' else 'OUT'}  {r['target']}  ({r['reason']})")
    if a.log:
        chain.append(a.log, "check", {"scope_sha256": scope["raw_sha256"], "results": results}, _actor(a), now, key=_key(a))
    return 0 if all(r["verdict"] == "in" for r in results) else 1


def cmd_run(a):
    scope, now = load_scope(a.scope), _now(a)
    key = _key(a)
    argv = a.command
    targets, problems = extract_targets(argv)
    targets += [t for t in a.target]
    results = [check_target(scope, t, now) for t in targets]
    if not targets and not a.allow_no_target:
        problems.append("no target found in the command; pass --target or --allow-no-target")
    bad = [r for r in results if r["verdict"] != "in"]
    base = {"argv": argv, "scope_sha256": scope["raw_sha256"], "engagement": scope["engagement"], "results": results, "problems": problems}
    if a.dry_run:
        print(json.dumps({"targets": results, "problems": problems}, indent=2))
        return 0 if not bad and not problems else 3
    if bad or problems:
        chain.append(a.log, "refused", base, _actor(a), now, key=key)
        for r in bad:
            print(f"scopekeeper: refused: {r['target']}: {r['reason']}", file=sys.stderr)
        for p in problems:
            print(f"scopekeeper: refused: {p}", file=sys.stderr)
        return 3
    chain.append(a.log, "run", base, _actor(a), now, key=key)
    t0 = time.monotonic()
    try:
        code = subprocess.call(argv)            # argv list, never a shell
    except OSError as e:
        chain.append(a.log, "exit", {"error": e.strerror, "seconds": round(time.monotonic() - t0, 2)}, _actor(a), key=key)
        print(f"scopekeeper: could not start {argv[0]!r}: {e.strerror}", file=sys.stderr)
        return 127
    chain.append(a.log, "exit", {"code": code, "seconds": round(time.monotonic() - t0, 2)}, _actor(a), key=key)
    return code


def cmd_note(a):
    data = {"note": a.text}
    if a.evidence:
        try:
            data["evidence"] = {"path": a.evidence, "sha256": chain.sha256_file(a.evidence), "bytes": os.path.getsize(a.evidence)}
        except OSError as e:
            print(f"scopekeeper: evidence {a.evidence}: {e.strerror}", file=sys.stderr)
            return 2
    e = chain.append(a.log, "note", data, _actor(a), key=_key(a))
    print(f"entry {e['seq']} recorded, hash {e['hash']}")
    return 0


def cmd_verify(a):
    v = chain.verify(a.log, a.expect_head, key=_key(a))
    if a.json:
        print(json.dumps(v, indent=2))
        return 0 if v["ok"] else 1
    if v["ok"]:
        seals = ("seals verified" if v["seals_verified"] else f"{v['sealed']} sealed entries, not checked (no key given)") if v["sealed"] else "not sealed"
        print(f"OK: {v['entries']} entries, chain intact, {seals}.\nHead hash (record this somewhere the log's holder cannot edit): {v['head']}")
        return 0
    print(f"FAILED: {v['error']}", file=sys.stderr)
    return 1


def cmd_keygen(a):
    try:
        chain.generate_key(a.file)
    except FileExistsError:
        print(f"scopekeeper: {a.file} exists; refusing to overwrite a key", file=sys.stderr)
        return 2
    print(f"wrote key {a.file} (owner-only). Keep it away from the log's holder and from the machine under test; anyone with the key can forge seals.")
    return 0


def cmd_report(a):
    v = chain.verify(a.log, key=_key(a))
    entries = chain.read_entries(a.log) if v["ok"] else []
    if a.format == "json":
        print(json.dumps({"ok": v["ok"], "entries_count": v["entries"], "head": v.get("head"),
                           "error": v.get("error"), "entries": entries}, indent=2))
        return 0 if v["ok"] else 1
    out = ["# Engagement log", "", f"Chain: {'intact' if v['ok'] else 'NOT INTACT: ' + str(v['error'])}", f"Entries: {v['entries']}", f"Head hash: `{v['head']}`", "",
           "| # | Time (UTC) | Actor | Kind | Summary |", "| --- | --- | --- | --- | --- |"]
    for e in entries:
        d = e["data"]
        if e["kind"] in ("run", "refused"):
            s = " ".join(d["argv"]) + ("" if e["kind"] == "run" else " — " + "; ".join(r["reason"] for r in d["results"] if r["verdict"] != "in" or True)[:120])
        elif e["kind"] == "note":
            s = d["note"] + (f" (evidence sha256 {d['evidence']['sha256'][:12]}…)" if "evidence" in d else "")
        elif e["kind"] == "exit":
            s = f"exit code {d.get('code', d.get('error'))}"
        else:
            s = ", ".join(f"{r['target']}: {r['verdict']}" for r in d.get("results", []))
        out.append(f"| {e['seq']} | {e['ts']} | {e['actor']} | {e['kind']} | {s.replace('|', '/')} |")
    print("\n".join(out))
    return 0 if v["ok"] else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="scopekeeper", description="Scope guard and tamper-evident log for AUTHORISED security testing. It does not scan or attack anything.")
    p.add_argument("--version", action="version", version=f"scopekeeper {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    def common(sp, scope=True, log=True, keyed=True):
        if scope:
            sp.add_argument("scope", help="scope file (JSON)")
        sp.add_argument("--actor", help="name recorded in the log (default: OS user)")
        sp.add_argument("--at", help=argparse.SUPPRESS)
        if keyed:
            sp.add_argument("--key-file", help="secret key file used to seal (and, for verify/report, check) log entries; env SCOPEKEEPER_KEY_FILE")
    i = sub.add_parser("init", help="write a scope file template"); i.add_argument("file"); i.add_argument("--force", action="store_true")
    c = sub.add_parser("check", help="check targets against the scope"); common(c); c.add_argument("targets", nargs="+"); c.add_argument("--log"); c.add_argument("--json", action="store_true", help="print results as JSON (for CI)")
    r = sub.add_parser("run", help="check the command's targets, then run it and log it"); common(r)
    r.add_argument("--log", required=True); r.add_argument("--target", action="append", default=[], help="extra target to check (repeatable)")
    r.add_argument("--dry-run", action="store_true"); r.add_argument("--allow-no-target", action="store_true")
    n = sub.add_parser("note", help="record a note, optionally with the SHA-256 of an evidence file"); common(n, scope=False)
    n.add_argument("log"); n.add_argument("text"); n.add_argument("--evidence")
    kg = sub.add_parser("keygen", help="create a random secret key file for sealing log entries"); kg.add_argument("file")
    v = sub.add_parser("verify", help="verify the log's hash chain"); v.add_argument("log"); v.add_argument("--expect-head"); v.add_argument("--key-file", help="check every entry's seal with this key (env SCOPEKEEPER_KEY_FILE)"); v.add_argument("--json", action="store_true", help="print the result as JSON (for CI)")
    rp = sub.add_parser("report", help="print the log as Markdown or JSON"); rp.add_argument("log"); rp.add_argument("--key-file", help="check seals with this key (env SCOPEKEEPER_KEY_FILE)"); rp.add_argument("--format", choices=["markdown", "json"], default="markdown")
    argv = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in argv:                      # everything after the first -- is the command, untouched
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    a = p.parse_args(argv)
    a.command = command
    if a.cmd == "run" and not command:
        p.error("run needs a command after --")
    try:
        return {"init": cmd_init, "check": cmd_check, "run": cmd_run, "note": cmd_note, "verify": cmd_verify, "report": cmd_report, "keygen": cmd_keygen}[a.cmd](a)
    except (ScopeError, ValueError, OSError) as e:
        print(f"scopekeeper: {e}", file=sys.stderr)
        return 2

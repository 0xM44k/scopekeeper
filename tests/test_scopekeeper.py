import json, os, subprocess, sys, tempfile, unittest
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
from scopekeeper import chain
from scopekeeper.extract import extract_targets
from scopekeeper.scope import ScopeError, check_target, load_scope, normalise_target

NOW = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
BASE = {"engagement": "t", "authorized_by": "x", "window": {"start": "2026-11-01T09:00:00Z", "end": "2026-11-05T17:00:00Z"},
        "in_scope": {"domains": ["app.example.com", "*.test.example.com"], "cidrs": ["10.10.0.0/24", "fd00::/64"]},
        "out_of_scope": {"domains": ["x.test.example.com"], "ips": ["10.10.0.1"]}}


def mk(obj=None):
    p = os.path.join(tempfile.mkdtemp(), "s.json")
    json.dump(obj or BASE, open(p, "w"))
    return p


def verdict(t, now=NOW, obj=None):
    return check_target(load_scope(mk(obj)), t, now)["verdict"]


class Scope(unittest.TestCase):
    def test_matching(self):
        cases = {"app.example.com": "in", "APP.Example.com.": "in", "a.b.test.example.com": "in", "test.example.com": "out",
                 "example.com": "out", "evilapp.example.com": "out", "x.test.example.com": "out",
                 "10.10.0.5": "in", "10.10.0.1": "out", "10.10.1.5": "out", "10.10.0.0/25": "in", "10.10.0.0/16": "out",
                 "fd00::5": "in", "fd01::5": "out", "https://app.example.com:8443/path": "in", "10.10.0.5:22": "in",
                 "[fd00::5]": "in", "not a target": "out", "": "out"}
        for t, v in cases.items():
            self.assertEqual(verdict(t), v, t)

    def test_window_enforced_both_ends(self):
        self.assertEqual(verdict("10.10.0.5", datetime(2026, 10, 31, tzinfo=timezone.utc)), "out")
        self.assertEqual(verdict("10.10.0.5", datetime(2026, 11, 6, tzinfo=timezone.utc)), "out")

    def test_exclusion_overrides_inclusion(self):
        self.assertEqual(verdict("10.10.0.1"), "out")

    def test_validation_errors(self):
        bad = [dict(BASE, window={"start": "2026-11-01T09:00:00", "end": "2026-11-05T17:00:00Z"}),
               dict(BASE, window={"start": "2026-11-05T09:00:00Z", "end": "2026-11-01T17:00:00Z"}),
               dict(BASE, in_scope={"domains": ["not_a_domain"]}), dict(BASE, in_scope={"cidrs": ["999.1.1.1/8"]}),
               dict(BASE, in_scope={}), {k: v for k, v in BASE.items() if k != "authorized_by"}]
        for obj in bad:
            with self.assertRaises(ScopeError):
                load_scope(mk(obj))

    def test_no_dns(self):
        import socket
        orig = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(AssertionError("DNS lookup attempted"))
        try:
            verdict("app.example.com")
        finally:
            socket.getaddrinfo = orig


class Extract(unittest.TestCase):
    def t(self, *argv, **kw):
        return extract_targets(["tool", *argv], **kw)

    def test_shapes(self):
        t, p = self.t("-sV", "-p", "80,443", "10.10.0.5", "https://app.example.com/x", "admin@host.test.example.com", "--url=http://10.10.0.9:8080", "-oN", "out.txt", "./local.sh", "10.10.0.0/28")
        self.assertEqual(sorted(t), sorted(["10.10.0.5", "https://app.example.com/x", "host.test.example.com", "http://10.10.0.9:8080", "10.10.0.0/28"]))
        self.assertEqual(p, [])

    def test_random_targets_refused(self):
        self.assertTrue(self.t("-iR", "100")[1])

    def test_target_list_file(self):
        t, p = self.t("-iL", "list.txt", read_file=lambda f: ["10.10.0.7", "evil.example.org"])
        self.assertEqual(t, ["10.10.0.7", "evil.example.org"])
        t, p = self.t("-iL", "missing.txt")
        self.assertTrue(p)

    def test_version_numbers_not_targets(self):
        self.assertEqual(self.t("--version", "1.2")[0], [])


class Chain(unittest.TestCase):
    def log(self, n=4):
        p = os.path.join(tempfile.mkdtemp(), "l.jsonl")
        for i in range(n):
            chain.append(p, "note", {"note": f"n{i}"}, "me", NOW)
        return p

    def test_intact(self):
        v = chain.verify(self.log())
        self.assertTrue(v["ok"])
        self.assertEqual(v["entries"], 4)

    def test_edit_middle_detected(self):
        p = self.log()
        lines = open(p).read().splitlines()
        lines[1] = lines[1].replace("n1", "nX")
        open(p, "w").write("\n".join(lines) + "\n")
        v = chain.verify(p)
        self.assertFalse(v["ok"])
        self.assertIn("entry 2", v["error"])

    def test_delete_middle_detected(self):
        p = self.log()
        lines = open(p).read().splitlines()
        open(p, "w").write("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertFalse(chain.verify(p)["ok"])

    def test_truncation_only_detected_with_recorded_head(self):
        p = self.log()
        head = chain.verify(p)["head"]
        lines = open(p).read().splitlines()
        open(p, "w").write("\n".join(lines[:-1]) + "\n")
        self.assertTrue(chain.verify(p)["ok"])                       # documented limitation
        self.assertFalse(chain.verify(p, expect_head=head)["ok"])    # caught when head was recorded

    def test_refuses_to_extend_broken_chain(self):
        p = self.log()
        lines = open(p).read().splitlines()
        open(p, "w").write("\n".join(lines[1:]) + "\n")
        with self.assertRaises(ValueError):
            chain.append(p, "note", {"note": "late"}, "me")


KEY = b"0123456789abcdef0123456789abcdef"
OTHER = b"fedcba9876543210fedcba9876543210"


class Seal(unittest.TestCase):
    """Optional HMAC seals: defeat a whole-file rewrite by someone without the key."""

    def sealed(self, n=3, key=KEY):
        p = os.path.join(tempfile.mkdtemp(), "l.jsonl")
        for i in range(n):
            chain.append(p, "note", {"note": f"n{i}"}, "me", NOW, key=key)
        return p

    def rewrite_without_key(self, p):
        """Attacker rebuilds a self-consistent chain with different content and no key."""
        entries = chain.read_entries(p)
        prev, out = chain.GENESIS, []
        for e in entries:
            e = {k: v for k, v in e.items() if k != "mac"}
            e["data"] = {"note": "forged"}
            e["prev"] = prev
            e["hash"] = chain.entry_hash(e)
            prev = e["hash"]
            out.append(chain.canonical(e))
        open(p, "w").write("\n".join(out) + "\n")

    def test_sealed_log_verifies_with_key(self):
        v = chain.verify(self.sealed(), key=KEY)
        self.assertTrue(v["ok"])
        self.assertEqual((v["sealed"], v["seals_verified"]), (3, True))

    def test_wrong_key_fails(self):
        v = chain.verify(self.sealed(), key=OTHER)
        self.assertFalse(v["ok"])
        self.assertIn("entry 1", v["error"])

    def test_without_key_chain_passes_but_seals_are_not_claimed_as_checked(self):
        v = chain.verify(self.sealed())
        self.assertTrue(v["ok"])
        self.assertEqual((v["sealed"], v["seals_verified"]), (3, False))

    def test_whole_file_rewrite_is_caught_only_by_the_key(self):
        p = self.sealed()
        self.rewrite_without_key(p)
        self.assertTrue(chain.verify(p)["ok"])                       # hash chain alone is fooled
        v = chain.verify(p, key=KEY)
        self.assertFalse(v["ok"])
        self.assertIn("seal", v["error"])

    def test_unsealed_log_fails_key_verification(self):
        p = os.path.join(tempfile.mkdtemp(), "l.jsonl")
        chain.append(p, "note", {"note": "x"}, "me", NOW)
        self.assertFalse(chain.verify(p, key=KEY)["ok"])

    def test_sealed_log_refuses_unsealed_append_and_wrong_key_append(self):
        p = self.sealed(2)
        with self.assertRaises(ValueError):
            chain.append(p, "note", {"note": "x"}, "me")
        with self.assertRaises(ValueError):
            chain.append(p, "note", {"note": "x"}, "me", key=OTHER)
        chain.append(p, "note", {"note": "ok"}, "me", key=KEY)
        self.assertEqual(chain.verify(p, key=KEY)["entries"], 3)

    def test_seal_edit_detected(self):
        p = self.sealed()
        lines = open(p).read().splitlines()
        e = json.loads(lines[1]); e["mac"] = "0" * 64
        lines[1] = chain.canonical(e)
        open(p, "w").write("\n".join(lines) + "\n")
        self.assertIn("entry 2", chain.verify(p, key=KEY)["error"])

    def test_key_file_rules(self):
        d = tempfile.mkdtemp(); kf = os.path.join(d, "k")
        chain.generate_key(kf)
        self.assertEqual(oct(os.stat(kf).st_mode & 0o777), "0o600")
        self.assertGreaterEqual(len(chain.load_key(kf)), 32)
        with self.assertRaises(FileExistsError):
            chain.generate_key(kf)
        short = os.path.join(d, "s"); open(short, "w").write("abc\n")
        with self.assertRaises(ValueError):
            chain.load_key(short)
        with self.assertRaises(ValueError):
            chain.load_key(os.path.join(d, "missing"))

    def test_cli_end_to_end(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        run = lambda *a: subprocess.run([sys.executable, "-m", "scopekeeper", *a], capture_output=True, text=True, env=env)
        d = tempfile.mkdtemp(); kf = os.path.join(d, "k"); log = os.path.join(d, "l.jsonl")
        self.assertEqual(run("keygen", kf).returncode, 0)
        self.assertEqual(run("keygen", kf).returncode, 2)            # never overwrites a key
        self.assertEqual(run("note", log, "first", "--key-file", kf).returncode, 0)
        self.assertEqual(run("note", log, "second", "--key-file", kf).returncode, 0)
        ok = run("verify", log, "--key-file", kf)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("seals verified", ok.stdout)
        self.assertIn("not checked", run("verify", log).stdout)
        self.assertEqual(run("note", log, "unsealed").returncode, 2)  # sealed log refuses an unsealed entry
        other = os.path.join(d, "k2"); run("keygen", other)
        bad = run("verify", log, "--key-file", other)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("FAILED", bad.stderr)
        self.assertEqual(run("report", log, "--key-file", kf).returncode, 0)
        self.assertEqual(run("report", log, "--key-file", other).returncode, 1)
        env2 = dict(env, SCOPEKEEPER_KEY_FILE=kf)
        self.assertEqual(subprocess.run([sys.executable, "-m", "scopekeeper", "verify", log], capture_output=True, text=True, env=env2).returncode, 0)


class Cli(unittest.TestCase):
    def run_cli(self, *a):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        return subprocess.run([sys.executable, "-m", "scopekeeper", *a], capture_output=True, text=True, env=env)

    def test_run_in_scope_executes_and_logs_exit_code(self):
        d = tempfile.mkdtemp(); log = os.path.join(d, "l.jsonl"); sc = mk()
        p = self.run_cli("run", sc, "--log", log, "--at", "2026-11-02T10:00:00Z", "--actor", "me", "--target", "10.10.0.5", "--", sys.executable, "-c", "import sys; sys.exit(7)")
        # python executable path is not a target; extra --target is checked
        self.assertEqual(p.returncode, 7, p.stderr)
        kinds = [e["kind"] for e in chain.read_entries(log)]
        self.assertEqual(kinds, ["run", "exit"])
        self.assertTrue(chain.verify(log)["ok"])

    def test_run_out_of_scope_refuses_without_executing(self):
        d = tempfile.mkdtemp(); log = os.path.join(d, "l.jsonl"); marker = os.path.join(d, "ran")
        p = self.run_cli("run", mk(), "--log", log, "--at", "2026-11-02T10:00:00Z", "--target", "198.51.100.7", "--", sys.executable, "-c", f"open({marker!r},'w')")
        self.assertEqual(p.returncode, 3)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual([e["kind"] for e in chain.read_entries(log)], ["refused"])

    def test_run_outside_window_refuses(self):
        p = self.run_cli("run", mk(), "--log", os.path.join(tempfile.mkdtemp(), "l"), "--at", "2026-12-01T00:00:00Z", "--", "echo", "10.10.0.5")
        self.assertEqual(p.returncode, 3)

    def test_no_target_refused_unless_allowed(self):
        d = tempfile.mkdtemp()
        p = self.run_cli("run", mk(), "--log", os.path.join(d, "l"), "--at", "2026-11-02T10:00:00Z", "--", "echo", "hello")
        self.assertEqual(p.returncode, 3)
        p = self.run_cli("run", mk(), "--log", os.path.join(d, "l"), "--at", "2026-11-02T10:00:00Z", "--allow-no-target", "--", "echo", "hello")
        self.assertEqual(p.returncode, 0)

    def test_no_shell_interpretation(self):
        d = tempfile.mkdtemp(); marker = os.path.join(d, "pwned")
        self.run_cli("run", mk(), "--log", os.path.join(d, "l"), "--at", "2026-11-02T10:00:00Z", "--allow-no-target", "--", "echo", f"x; touch {marker}")
        self.assertFalse(os.path.exists(marker))

    def test_note_with_evidence_hash_and_report_and_verify(self):
        d = tempfile.mkdtemp(); log = os.path.join(d, "l"); ev = os.path.join(d, "shot.txt"); open(ev, "w").write("proof")
        self.assertEqual(self.run_cli("note", log, "found X", "--evidence", ev, "--actor", "me").returncode, 0)
        v = self.run_cli("verify", log)
        self.assertEqual(v.returncode, 0)
        head = v.stdout.split()[-1]
        self.assertEqual(self.run_cli("verify", log, "--expect-head", head).returncode, 0)
        self.assertEqual(self.run_cli("verify", log, "--expect-head", "0" * 64).returncode, 1)
        self.assertIn("found X", self.run_cli("report", log).stdout)

    def test_init_refuses_overwrite(self):
        f = os.path.join(tempfile.mkdtemp(), "e.json")
        self.assertEqual(self.run_cli("init", f).returncode, 0)
        self.assertEqual(self.run_cli("init", f).returncode, 2)
        load_scope(f)  # template itself is valid

    def test_check_json_output(self):
        p = self.run_cli("check", mk(), "10.10.0.5", "198.51.100.7", "--json", "--at", "2026-11-02T10:00:00Z")
        self.assertEqual(p.returncode, 1)  # one target out of scope
        data = json.loads(p.stdout)
        self.assertEqual(len(data["results"]), 2)
        self.assertEqual(data["results"][0]["verdict"], "in")
        self.assertEqual(data["results"][1]["verdict"], "out")
        self.assertIn("scope_sha256", data)

    def test_verify_json_output(self):
        d = tempfile.mkdtemp(); log = os.path.join(d, "l")
        self.run_cli("note", log, "hello", "--actor", "me")
        p = self.run_cli("verify", log, "--json")
        data = json.loads(p.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["entries"], 1)
        bad = self.run_cli("verify", log, "--expect-head", "0" * 64, "--json")
        self.assertEqual(bad.returncode, 1)
        self.assertFalse(json.loads(bad.stdout)["ok"])

    def test_report_json_output(self):
        d = tempfile.mkdtemp(); log = os.path.join(d, "l")
        self.run_cli("note", log, "found X", "--actor", "me")
        p = self.run_cli("report", log, "--format", "json")
        data = json.loads(p.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["entries_count"], 1)
        self.assertEqual(data["entries"][0]["data"]["note"], "found X")


if __name__ == "__main__":
    unittest.main()

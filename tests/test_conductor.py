"""The conductor: masking, the proven step/route/vote decisions, the sandbox, masked work cross-checked across
providers, split work. Providers are fakes in this process: nothing leaves the machine."""
import json, os, re, shutil, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[0:0] = [str(REPO / "system" / "lib"), str(REPO / "system" / "sbin")]
import zorch, zsandbox, zdecide                                   # noqa: E402

HAVE_BWRAP = bool(zsandbox.bwrap())


class Fake:
    """a provider that records every prompt it was given and answers with a function of it"""
    def __init__(self, answer):
        self.answer, self.seen = answer, []

    def complete(self, prompt):
        self.seen.append(prompt)
        return self.answer(prompt)


def code_reply(body):
    return lambda prompt: "```python\n" + body + "\n```"


def tokens(prompt, prefix):
    return re.findall(r"\[\[((?:" + prefix + r")\d+)\]\]", prompt)


class Masking(unittest.TestCase):
    def test_mask_and_back(self):
        m = zorch.Masker(["Sato Hanako", "Project Kite"])
        t = "Mail sato hanako at hanako@example.jp about Project Kite: 1,250,000 yen on 2026-10-31, call 03-1234-5678."
        x = m.mask(t)
        for real in ("hanako@example.jp", "Project Kite", "1,250,000", "2026-10-31", "03-1234-5678"):
            self.assertNotIn(real, x)
        self.assertNotIn("sato hanako", x.lower())
        self.assertEqual(m.unmask(x), t)
        self.assertEqual(m.leaks(x), [])
        self.assertEqual(m.leaks("about Project Kite"), ["Project Kite"])

    def test_code_literals_escaped(self):
        m = zorch.Masker()
        t = m.token("C", 'he said "hi"')
        self.assertEqual(m.unmask_code(f'x = "{t}"'), 'x = "he said \\"hi\\""')


class Decisions(unittest.TestCase):
    conf = {"allowed": ["a", "b"], "dests": ["mail:me"], "after_taint": []}

    def test_step(self):
        zorch.step(self.conf, "send", "masked", "a", payload_masked=True)
        with self.assertRaises(zorch.Refused):
            zorch.step(self.conf, "send", "masked", "a", payload_masked=False)       # a real value would leave
        with self.assertRaises(zorch.Refused):
            zorch.step(self.conf, "send", "masked", "c", payload_masked=True)        # not allowed
        with self.assertRaises(zorch.Refused):
            zorch.step(self.conf, "send", "pc", "a", payload_masked=True)            # this task stays on the PC
        with self.assertRaises(zorch.Refused):
            zorch.step(self.conf, "act", dest="mail:me")                             # not confirmed
        zorch.step(self.conf, "act", dest="mail:me", confirmed=True)
        with self.assertRaises(zorch.Refused):
            zorch.step(self.conf, "act", dest="mail:me", confirmed=True, tainted=True)   # narrowed after outside content
        with self.assertRaises(zorch.Refused):
            zorch.step(self.conf, "act", dest="mail:attacker", confirmed=True)       # not set by the person

    def test_route_and_assign(self):
        frags = [{"atoms": [{"record": "t", "role": "attr"}]}, {"atoms": [{"record": "t", "role": "ident"}]}]
        w = zorch.Weights(tempfile.mktemp())
        w.w = {"report": {"a": 500, "b": 100}}
        plan = zorch.assign(frags, ["a", "b"], ["a", "b"], w, "report")
        self.assertEqual([f["to"] for f in plan], ["a", "b"])        # the heavier one first, never both halves
        with self.assertRaises(zorch.Refused):
            zorch.assign(frags, ["a"], ["a"], w, "report")           # one provider only: refused, not merged

    def test_vote(self):
        w = {"a": 900, "b": 50, "c": 50}
        self.assertFalse(zorch.vote_ok(w, [("a", "x"), ("b", "y"), ("c", "y")], "x"))   # heavy alone
        self.assertFalse(zorch.vote_ok(w, [("a", "x"), ("b", "y"), ("c", "y")], "y"))   # light pair, not half
        self.assertTrue(zorch.vote_ok(w, [("a", "x"), ("b", "x"), ("c", "y")], "x"))


@unittest.skipUnless(HAVE_BWRAP, "bubblewrap is not installed")
class Sandbox(unittest.TestCase):
    def test_no_network_no_home_no_io_uring(self):
        d = tempfile.mkdtemp()
        Path(d, "in.txt").write_text("hello")
        code = ("import socket, ctypes, os\n"
                "print(open('/work/in/x').read())\n"
                "try:\n socket.socket(socket.AF_INET); print('inet')\nexcept OSError as e: print('noinet', e.errno)\n"
                "socket.socket(socket.AF_UNIX); print('unix')\n"
                "libc = ctypes.CDLL(None, use_errno=True)\n"
                "print('uring', libc.syscall(425, 1, 0), ctypes.get_errno())\n"
                "print('home', os.path.exists('/home'), os.path.exists('/var'))\n")
        r = zsandbox.run(["python3", "-c", code], inputs={"x": str(Path(d, "in.txt"))})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split("\n")[:5], ["hello", "noinet 97", "unix", "uring -1 1", "home False False"])

    @unittest.skipUnless(HAVE_BWRAP, "bubblewrap not installed")
    def test_the_sandbox_has_limits(self):
        code = ("import os\n"
                "try:\n bytearray(6 << 30); print('mem big')\nexcept MemoryError: print('mem refused')\n"
                "try:\n f = open('/tmp/x', 'wb')\n for _ in range(64): f.write(b'0' * (8 << 20))\n f.close(); print('tmp big')\n"
                "except OSError as e: print('tmp refused')\n")
        r = zsandbox.run(["python3", "-c", code])
        self.assertEqual(r.stdout.split("\n")[:2], ["mem refused", "tmp refused"], r.stderr)
        r = zsandbox.run(["python3", "-c", "import sys; sys.stdout.write('x' * (40 << 20))"])
        self.assertLessEqual(len(r.stdout), zsandbox.OUTPUT_BYTES)

    def test_filter_shape(self):
        for arch in ("x86_64", "aarch64"):
            self.assertEqual(len(zsandbox.seccomp_filter(arch)) % 8, 0)


@unittest.skipUnless(HAVE_BWRAP, "bubblewrap is not installed")
class MaskedWork(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        os.environ["ZENOS_CONDUCTOR_STATE"] = str(self.d / "state")
        importlib_reload()
        self.csv = self.d / "sales.csv"
        self.csv.write_text("customer,region,amount\nSato Hanako,Tohoku,1200\nKite Corp,Kanto,3400\nMori,Tohoku,800\n")
        self.conf = {"allowed": ["a", "b", "c"], "terms": ["Sato Hanako"], "dests": [], "after_taint": []}

    def program(self, prompt):
        f = tokens(prompt, "F")[0]
        c = tokens(prompt, "C")                  # customer, region, amount
        t = tokens(prompt, "K")
        return ("import csv\n"
                f"rows = list(csv.DictReader(open('[[{f}]]')))\n"
                f"print(sum(int(r['[[{c[2]}]]']) for r in rows if r['[[{c[1]}]]'] == '[[{t[-1]}]]'))\n")

    def test_agree_and_nothing_real_leaves(self):
        good = lambda p: "```python\n" + self.program(p) + "```"
        a, b, c = Fake(good), Fake(good), Fake(code_reply("print(0)"))
        w = zorch.Weights(self.d / "w.json")
        r = zorch.masked_task(self.conf, "Total amount for Tohoku customers", [str(self.csv)],
                              {"a": a, "b": b, "c": c}, weights=w)
        self.assertTrue(r["accepted"], r)
        self.assertEqual(r["result"], "2000")
        self.assertEqual(r["by"], ["a", "b"])
        for p in a.seen + b.seen + c.seen:
            for real in ("Sato Hanako", "Tohoku", "1200", "customer", "amount", "sales.csv"):
                self.assertNotIn(real, p)
        self.assertGreater(w.get("table", "a"), w.get("table", "c"))      # measured on the PC
        led = [json.loads(l) for l in (self.d / "state" / "ledger.jsonl").read_text().splitlines()]
        self.assertEqual([e["event"] for e in led], ["conductor-task", "conductor-result"])

    def test_one_provider_never_decides(self):
        good = lambda p: "```python\n" + self.program(p) + "```"
        w = zorch.Weights(self.d / "w.json")
        w.w = {"table": {"a": 1000, "b": 1, "c": 1}}
        r = zorch.masked_task(self.conf, "Total amount for Tohoku customers", [str(self.csv)],
                              {"a": Fake(good), "b": Fake(code_reply("print(1)")), "c": Fake(code_reply("print(2)"))},
                              weights=w)
        self.assertFalse(r["accepted"])

    def test_code_cannot_reach_the_network(self):
        evil = code_reply("import urllib.request\nprint(urllib.request.urlopen('http://example.com').read())")
        r = zorch.masked_task(self.conf, "anything", [str(self.csv)], {"a": Fake(evil), "b": Fake(evil)},
                              weights=zorch.Weights(self.d / "w.json"))
        self.assertFalse(r["accepted"])
        self.assertEqual(r["results"], {"a": None, "b": None})

    def test_leak_refused_before_sending(self):
        # a column literally named "number" would show up in the description's own words: when a real value
        # would leave, the proven step refuses and no provider is asked anything
        odd = self.d / "odd.csv"
        odd.write_text("number,amount\n1,1200\n")
        a = Fake(code_reply("print(1)"))
        with self.assertRaises(zorch.Refused):
            zorch.masked_task(self.conf, "Sum amount", [str(odd)], {"a": a, "b": Fake(code_reply("print(1)"))},
                              weights=zorch.Weights(self.d / "w.json"))
        self.assertEqual(a.seen, [])


class SplitWork(unittest.TestCase):
    def test_table_and_text_go_to_different_providers(self):
        d = Path(tempfile.mkdtemp())
        os.environ["ZENOS_CONDUCTOR_STATE"] = str(d / "state")
        importlib_reload()
        t = d / "t.csv"
        t.write_text("branch,q1,q2\nSendai,120,180\nKoriyama,90,60\n")
        text = "Sendai grew from 120 to 180 while Koriyama fell. Contact ceo@kite.example."
        echo = lambda p: p.split("\n\n", 1)[1]
        a, b = Fake(echo), Fake(echo)
        r = zorch.split_report({"allowed": ["a", "b"]}, text, str(t), {"a": a, "b": b},
                               weights=zorch.Weights(d / "w.json"))
        self.assertEqual(set(r["assignment"].values()), {"a", "b"})
        table_side = a.seen[0] if r["assignment"]["table"] == "a" else b.seen[0]
        text_side = b.seen[0] if r["assignment"]["table"] == "a" else a.seen[0]
        self.assertIn("120", table_side)                          # the numbers, without what they are about
        for real in ("Sendai", "Koriyama", "branch", "q1"):
            self.assertNotIn(real, table_side)
        for real in ("120", "180", "ceo@kite.example", "Sendai"):  # what it is about, without the numbers
            self.assertNotIn(real, text_side)
        self.assertEqual(r["text"], text)                          # put back together on the PC


def importlib_reload():
    import importlib
    importlib.reload(zorch)


if __name__ == "__main__":
    unittest.main()

"""The ZENOS conductor (docs/ORCHESTRATOR.md): ZENOS runs a task itself with several frontier models reached over
their APIs, and no provider receives the person's plain data, or enough pieces to put a record back together.

ZENOS holds no AI model. The models write plans and code against tokens ([[F1]], [[C2]], [[T3]] ...); ZENOS
substitutes the real values on the PC, runs the code in the sandbox (zsandbox), compares the results, and gives the
person the result. Every step is decided by the proven functions in formal/ZenosFormal/Orchestrator.lean through
zenos-decide: "step" (what may be sent, run or done), "route" (which provider may get which piece), "vote" (which
cross-checked result is accepted, with each provider's weight).

Configuration: ~/.config/zenos/conductor.json (the person's own; nothing is preset)
  {"providers": [{"name": "a", "kind": "anthropic"|"openai"|"openai-compatible", "model": "...",
                  "url": "https://...", "key_file": "~/.config/zenos/keys/a"}],
   "allowed": ["a", "b"],                  providers this person allows
   "dests": [], "after_taint": [],          destinations a task may reach (and those still open after outside content)
   "terms": ["Sato", "Project Kite"]}      words always masked (names and the like)
API keys are entered by the person into the key files (mode 0600). ZENOS ships with none.
"""
import csv, hashlib, io, json, os, re, time, urllib.request
from pathlib import Path
from urllib.parse import urlparse

import zdecide

STATE = Path(os.environ.get("ZENOS_CONDUCTOR_STATE", os.path.expanduser("~/.local/state/zenos/conductor")))
CONF = Path(os.environ.get("ZENOS_CONDUCTOR_CONF", os.path.expanduser("~/.config/zenos/conductor.json")))

# Providers never used, whatever the configuration says: Google (not chosen for ZENOS), Qwen, and providers under
# laws that let a state compel access to data without due process. Matched on the API host.
DENY_HOSTS = ("googleapis.com", "google.com", "aliyuncs.com", "dashscope", "deepseek.com", "moonshot.cn",
              "bigmodel.cn", "minimax", "baichuan-ai.com", "volces.com", "hunyuan", "qwen")

TOKEN = re.compile(r"\[\[([A-Z]{1,2}\d{1,5})\]\]")
PATTERNS = [
    ("E", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("U", re.compile(r"https?://[^\s\"'<>]+")),
    ("PH", re.compile(r"(?<!\d)(?:\+\d{1,3}[ -]?)?(?:\(?\d{2,4}\)?[ -]?){2,3}\d{3,4}(?!\d)")),
    ("D", re.compile(r"\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\b")),
    ("N", re.compile(r"(?<![\w.])\d{1,3}(?:,\d{3})+(?:\.\d+)?(?![\w.])|(?<![\w.])\d+\.\d+(?![\w.])|(?<![\w.])\d{3,}(?![\w.])")),
]


class Refused(Exception):
    pass


# ---------------- masking ----------------

class Masker:
    """replaces what identifies (names given by the person, addresses, numbers of 3+ digits, dates, URLs, files,
    column names) with tokens; the table stays in this process"""

    def __init__(self, terms=()):
        self.table, self.rev, self.n = {}, {}, {}
        self.terms = sorted({t for t in terms if t.strip()}, key=len, reverse=True)

    def token(self, cls, value):
        if value in self.rev:
            return self.rev[value]
        self.n[cls] = self.n.get(cls, 0) + 1
        t = f"[[{cls}{self.n[cls]}]]"
        self.table[t], self.rev[value] = value, t
        return t

    @staticmethod
    def _word(value):
        # plural and possessive forms too ("customers", "Sato's"): a name must not leave in a longer word
        return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(value) + r"(?:e?s|'s)?(?![A-Za-z0-9_])", re.I)

    def mask(self, text):
        # values already in the table (column names, row names, files) first, then the person's terms
        for value in sorted((v for v in self.rev if len(v) >= 2), key=len, reverse=True):
            text = self._word(value).sub(lambda m, v=value: self.rev[v], text)
        for term in self.terms:
            text = self._word(term).sub(lambda m: self.token("T", m.group(0)), text)
        for cls, rx in PATTERNS:
            text = rx.sub(lambda m: m.group(0) if TOKEN.fullmatch(m.group(0)) else self.token(cls, m.group(0)), text)
        return text

    def unmask(self, text):
        return TOKEN.sub(lambda m: self.table.get(m.group(0), m.group(0)), text)

    def unmask_code(self, code):
        """tokens inside Python string literals become the real values, escaped for the literal"""
        def rep(m):
            v = self.table.get(m.group(0))
            if v is None:
                return m.group(0)
            return v.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n")
        return TOKEN.sub(rep, code)

    def leaks(self, payload, classes=None):
        """real values (of 3+ characters; only of these token classes, if given) found in this payload"""
        return sorted({v for t, v in self.table.items() if len(v) >= 3 and self._word(v).search(payload)
                       and (classes is None or TOKEN.fullmatch(t).group(1).rstrip("0123456789") in classes)})


def describe_csv(path, masker, token):
    """what a model may know about a table: masked column names, a type per column, the row count"""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.reader(f))
    if not rows:
        return f"{token} is an empty CSV file."
    head, body = rows[0], rows[1:]
    cols = []
    for i, name in enumerate(head):
        vals = [r[i] for r in body if i < len(r) and r[i].strip()]
        kind = "number" if vals and all(re.fullmatch(r"-?[\d,]*\.?\d+", v.strip()) for v in vals) else \
            "date" if vals and all(re.fullmatch(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}.*", v.strip()) for v in vals) else "text"
        cols.append(f"{masker.token('C', name)} ({kind})")
    return f"{token} is a CSV file with a header row and {len(body)} data rows. Columns: " + ", ".join(cols) + "."


def known_cells(path, masker, limit=50000):
    """every cell value of a table, so that the task's words cannot carry one out (\"Tohoku\" in \"total for Tohoku\"
    becomes a token; the code then compares with the token, put back on the PC)"""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for i, row in enumerate(csv.reader(f)):
            if i == 0:
                continue
            for v in row:
                v = v.strip()
                if len(v) >= 2 and len(masker.table) < limit:
                    masker.token("V" if re.fullmatch(r"-?[\d,]*\.?\d+", v) else "K", v)


# ---------------- providers ----------------

def provider_ok(p):
    host = (urlparse(p.get("url") or {"anthropic": "https://api.anthropic.com",
                                       "openai": "https://api.openai.com"}.get(p.get("kind"), "")).hostname or "")
    return host and not any(d in host for d in DENY_HOSTS) and not any(d in p.get("name", "").lower() for d in ("qwen", "gemini"))


class HTTPProvider:
    def __init__(self, conf):
        self.name, self.kind, self.model = conf["name"], conf["kind"], conf.get("model", "")
        self.url = conf.get("url")
        kf = conf.get("key_file")
        self.key = Path(os.path.expanduser(kf)).read_text().strip() if kf else ""
        if not provider_ok(conf):
            raise Refused(f"provider {self.name} is not used by ZENOS")
        # the model is called only at the identity pinned in the release ledger (provider, address, model, version),
        # when this PC checks the supply (zmodel.py; /etc/zenos/supply.json)
        import zmodel
        ok, why = zmodel.check_api(conf, 0)
        if not ok:
            record("model-api-refused", provider=self.name, model=self.model, reason=why)
            raise Refused(f"provider {self.name}: the model {self.model} is not pinned in the release ledger ({why})")

    def complete(self, prompt):
        if self.kind == "anthropic":
            url = (self.url or "https://api.anthropic.com") + "/v1/messages"
            body = {"model": self.model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]}
            head = {"x-api-key": self.key, "anthropic-version": "2023-06-01"}
        else:
            url = (self.url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
            body = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
            head = {"Authorization": "Bearer " + self.key} if self.key else {}
        u = urlparse(url)
        if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise Refused("providers are reached over https only")
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"content-type": "application/json", **head})
        with urllib.request.urlopen(req, timeout=180) as r:
            a = json.loads(r.read())
        if self.kind == "anthropic":
            return "".join(c.get("text", "") for c in a.get("content", []))
        return a["choices"][0]["message"]["content"]


# ---------------- weights ----------------

class Weights:
    """per kind of work, per provider: 0..1000, measured on the PC (start 100; +10 when a provider's result was the
    accepted one, -20 when it differed or failed)"""

    def __init__(self, path=None):
        self.path = Path(path or STATE / "weights.json")
        try:
            self.w = json.loads(self.path.read_text())
        except (OSError, ValueError):
            self.w = {}

    def get(self, kind, p):
        return int(self.w.get(kind, {}).get(p, 100))

    def update(self, kind, p, good):
        v = self.get(kind, p) + (10 if good else -20)
        self.w.setdefault(kind, {})[p] = max(0, min(1000, v))

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.w, indent=1))
        os.replace(tmp, self.path)


# ---------------- the proven decisions ----------------

def step(conf, kind, level="masked", provider="", payload_masked=False, route_ok=False, dest="", tainted=False,
         confirmed=False):
    a = zdecide.ask({"op": "step", "kind": kind, "level": level, "provider": provider,
                     "allowed": list(conf.get("allowed", [])), "payload_masked": bool(payload_masked),
                     "route_ok": bool(route_ok), "dest": dest, "dests": list(conf.get("dests", [])),
                     "after_taint": list(conf.get("after_taint", [])), "tainted": bool(tainted),
                     "confirmed": bool(confirmed)})
    if not a.get("allow"):
        raise Refused(f"step refused: {a.get('reason')}")


def route_ok(allowed, frags):
    """frags: [{"to": provider, "atoms": [{"record", "role"}]}]"""
    a = zdecide.ask({"op": "route", "allowed": list(allowed), "frags": frags})
    return bool(a.get("allow")), a.get("reason")


def vote_ok(weights, ballots, answer):
    a = zdecide.ask({"op": "vote", "weights": [{"provider": p, "weight": int(w)} for p, w in weights.items()],
                     "ballots": [{"provider": p, "answer": x} for p, x in ballots], "answer": answer})
    return bool(a.get("accept"))


def assign(frags, providers, allowed, weights, kind):
    """give each fragment a provider: highest weight first, never a linked pair (decideRoute decides; weights only
    order the candidates). frags: [{"atoms": [...]}]. Returns the frags with "to" set."""
    order = sorted(providers, key=lambda p: -weights.get(kind, p))
    out = []
    for f in frags:
        for p in order:
            trial = out + [dict(f, to=p)]
            ok, _ = route_ok(allowed, trial)
            if ok:
                out = trial
                break
        else:
            raise Refused("no provider can take this piece without receiving a linked pair")
    return out


# ---------------- the record of what the conductor did ----------------

def record(event, **kw):
    try:
        import zledger
        zledger.append(str(STATE / "ledger.jsonl"), event, os.environ.get("USER", "person"), "conductor", **kw)
    except Exception:
        pass


def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------- masked work: code on tokens, run on the PC ----------------

CODE_PROMPT = """You write one Python 3 program. It runs in a sandbox with no network, with only the standard library.
Inputs:
{inputs}
Write the result to standard output, nothing else.
Task: {task}

Rules: refer to every file, column and name only by its token exactly as written above (for example "[[F1]]"),
always inside a string literal. Do not guess what the tokens stand for. Reply with the program only, in one
```python block."""

CODE_BLOCK = re.compile(r"```(?:python)?\s*\n(.*?)```", re.S)


def masked_task(conf, task, files, providers, tainted=False, weights=None, kind="table", timeout=120):
    """task: the person's words; files: [paths] (CSV); providers: {name: object with .complete(prompt)}.
    Returns {"result", "accepted", "by", "results"}."""
    from zsandbox import run
    weights = weights or Weights()
    m = Masker(conf.get("terms", []))
    inputs, desc = {}, []
    for i, f in enumerate(files, 1):
        tok = m.token("F", f"/work/in/f{i}.csv")
        inputs[f"f{i}.csv"] = f
        desc.append("- " + describe_csv(f, m, tok))
        known_cells(f, m)
    mt = m.mask(task)
    prompt = CODE_PROMPT.format(inputs="\n".join(desc) or "- none", task=mt)
    leaks = m.leaks(mt + "\n" + "\n".join(desc))          # what came from the person's data (not the fixed wording)
    for name in providers:
        step(conf, "send", "masked", name, payload_masked=not leaks)
    record("conductor-task", level="masked", providers=sorted(providers), prompt=digest(prompt), files=len(files))
    results, ballots = {}, []
    for name, prov in providers.items():
        try:
            reply = prov.complete(prompt)
            mm = CODE_BLOCK.search(reply)
            code = m.unmask_code(mm.group(1) if mm else reply)
            step(conf, "tool", dest="", tainted=tainted)
            r = run(["python3", "-I", "-c", code], inputs=inputs, timeout=timeout)
            out = r.stdout.strip() if r.returncode == 0 else None
        except Refused:
            raise
        except Exception as e:                       # a provider that fails just does not vote
            out = None
            record("conductor-provider-failed", provider=name, error=type(e).__name__)
        results[name] = out
        if out is not None:
            ballots.append((name, digest(out)))
    w = {p: weights.get(kind, p) for p in providers}
    accepted = None
    for p, d in ballots:
        if vote_ok(w, ballots, d):
            accepted = d
            break
    for p in providers:
        weights.update(kind, p, results.get(p) is not None and digest(results[p]) == accepted)
    weights.save()
    by = sorted(p for p, d in ballots if d == accepted)
    record("conductor-result", accepted=bool(accepted), by=by, result=accepted or "")
    res = next((results[p] for p in by), None)
    return {"result": res, "accepted": accepted is not None, "by": by, "results": results}


# ---------------- split work: a table and a text that says what it is ----------------

def split_report(conf, text, table_path, providers, weights=None):
    """the table's numbers go to one provider with labels masked; the text goes to another with numbers masked.
    Returns {"table_notes", "text", "assignment"} with tokens put back on the PC."""
    weights = weights or Weights()
    m = Masker(conf.get("terms", []))
    with open(table_path, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.reader(f))
    head, body = (rows[0], rows[1:]) if rows else ([], [])
    labels = [m.token("C", h) for h in head]
    keys = [m.token("K", r[0]) if r else "" for r in body]          # first column: what each row is about
    table_payload = "\n".join([",".join(labels)] + [",".join([k] + r[1:]) for k, r in zip(keys, body)])
    for r in body:                          # the values too, so that the text cannot carry them
        for v in r[1:]:
            if len(v.strip()) >= 2:
                m.token("V", v.strip())
    masked_text = m.mask(text)              # the table's names and values are already in the token table
    frags = [{"atoms": [{"record": "table", "role": "attr"}]},
             {"atoms": [{"record": "table", "role": "ident"}, {"record": "text", "role": "other"}]}]
    allowed = [p for p in conf.get("allowed", []) if p in providers]
    plan = assign(frags, list(providers), allowed, weights, "report")
    ok, why = route_ok(allowed, plan)
    if not ok:
        raise Refused(f"route refused: {why}")
    a, b = plan[0]["to"], plan[1]["to"]
    tp = ("Here is a table. Row and column names are tokens. Describe in 3 short sentences what the numbers show "
          "(trend, largest, smallest), using the tokens as written.\n\n" + table_payload)
    xp = ("Improve the wording of this text. Keep every token like [[N1]] exactly as written. Reply with the text "
          "only.\n\n" + masked_text)
    if m.leaks(table_payload, {"K", "C", "T", "E", "PH", "U"}) or m.leaks(masked_text):
        raise Refused("a piece would carry what it must not")
    step(conf, "send", "split", a, route_ok=True)
    step(conf, "send", "split", b, route_ok=True)
    record("conductor-split", table_to=a, text_to=b, table=digest(table_payload), text=digest(masked_text))
    notes = m.unmask(providers[a].complete(tp))
    new_text = m.unmask(providers[b].complete(xp))
    return {"table_notes": notes, "text": new_text, "assignment": {"table": a, "text": b}}


# ---------------- configuration ----------------

def load_conf(path=None):
    p = Path(path or CONF)
    try:
        c = json.loads(p.read_text())
    except FileNotFoundError:
        c = {}
    c.setdefault("providers", [])
    c.setdefault("allowed", [])
    c.setdefault("dests", [])
    c.setdefault("after_taint", [])
    c.setdefault("terms", [])
    return c


def load_providers(conf):
    out = {}
    for pc in conf["providers"]:
        if pc.get("name") in conf["allowed"]:
            out[pc["name"]] = HTTPProvider(pc)
    return out

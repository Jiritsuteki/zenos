"""AI models in the release ledger: a model is loaded only when every one of its files is the file that was released.

A model's weights can be rewritten so that it behaves differently while it looks the same: a few weights changed,
a trigger that wakes on one input. Neither a person looking at the file nor a test run is sure to see it. So ZENOS
does not judge what a model does; it checks that the files are, byte for byte, the ones that were released, as it
does for packages (zsupply.py).

A model kept on the PC lives in its own folder under /var/lib/zenos/models (root only writes there): the weights,
the tokenizer, the settings, any adapters (LoRA and the like), and `zenos-model.json`, the release record. The
record lists every file with its SHA-256, the model's name, version, publisher, where it came from, its licence
and the highest level of data it may see. Its identity (`sha256`) is the digest of that files list, and it is
released like a package: two or more release officers sign it, and it goes into the audit nodes' ledgers.

Before a model is loaded, `check(folder, level)` asks the audit nodes for the record of that identity and the
proven decision (formal/ZenosFormal/Model.lean, zenos-decide "model") allows it only when the record is a model
record, every file in the folder is in it with the same SHA-256 and every listed file is there, the data is within
its level, and the ledger holds it as for a package (majority of the nodes, enough officers, not revoked, ring
open). zenos-supplywatch moves a folder that does not pass to quarantine; zenos-integrity checks the files again.

A model called through an API cannot be hashed. What is pinned instead is whom it is called at: the provider,
its address, the model's name and its version (`api_manifest`), released the same way. `check_api(conf, level)`
lets a call go only to that identity (zenos-decide "model_api"), never to a provider ZENOS refuses (zorch.py's
list). When a provider changes the version, the new one is pinned by the officers before it is used.

What this does not catch: a model whose publisher put the trigger in before it was released has the right
fingerprints. See docs/THREAT_MODEL.md.
"""
import json, os, sys, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zsupply  # noqa: E402

MODELS = Path(os.environ.get("ZENOS_MODELS", "/var/lib/zenos/models"))
RECORD = "zenos-model.json"
KIND = "zenos-model"
KIND_API = "zenos-model-api"


class Refused(Exception):
    pass


def files_of(folder):
    """{relative path: SHA-256} of every file in a model's folder (its record left out). A link or anything that
    is not a plain file makes the folder unusable: a link could point a model at a file that was never released."""
    folder = Path(folder)
    out = {}
    for root, dirs, names in os.walk(folder, followlinks=False):
        for d in dirs:
            if os.path.islink(os.path.join(root, d)):
                raise Refused(f"a link in the model's folder: {os.path.relpath(os.path.join(root, d), folder)}")
        for n in names:
            p = Path(root) / n
            rel = p.relative_to(folder).as_posix()
            if rel == RECORD:
                continue
            if p.is_symlink() or not p.is_file():
                raise Refused(f"not a plain file in the model's folder: {rel}")
            out[rel] = zsupply.sha256_file(p)
    return dict(sorted(out.items()))


def model_id(files):
    return zsupply.digest({"kind": KIND, "files": files})


def manifest(folder, name, version, publisher, source, licence, max_level, rings=None):
    files = files_of(folder)
    if not files:
        raise Refused("the folder holds no files")
    return {"kind": KIND, "name": name, "version": version, "publisher": publisher, "source": source,
            "licence": licence, "max_level": int(max_level), "files": files, "sha256": model_id(files),
            "rings": {str(k): int(v) for k, v in (rings or {"0": 0}).items()}, "created": int(time.time())}


DEFAULT_API = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com"}


def api_identity(conf):
    """who a call goes to: provider kind, the whole address (scheme, host, port and path, not the host alone, so the
    same name on another port, over plain HTTP or under another path is another identity), model name and version
    (the version defaults to the model's name, which providers that version their models in the name already carry).
    An address with a user name, a query or a fragment has no identity: it is refused."""
    url = conf.get("url") or conf.get("base_url") or DEFAULT_API.get(conf.get("kind"), "")
    try:
        u = urlparse(str(url))
        port = u.port or {"https": 443, "http": 80}.get(u.scheme, 0)
        bad = u.username is not None or u.password is not None or u.query or u.fragment or not u.hostname
    except ValueError:
        u, port, bad = None, 0, True
    endpoint = "" if bad else "%s://%s:%d%s" % (u.scheme.lower(), u.hostname.lower().rstrip("."), port,
                                                 (u.path or "/").rstrip("/") or "/")
    return {"provider": str(conf.get("kind", "")), "host": "" if bad else u.hostname.lower().rstrip("."),
            "endpoint": endpoint, "model": str(conf.get("model", "")),
            "version": str(conf.get("version") or conf.get("model", ""))}


def api_id(ident):
    return zsupply.digest({"kind": KIND_API, **ident})


def api_manifest(conf, publisher, max_level, rings=None):
    ident = api_identity(conf)
    return {"kind": KIND_API, **ident, "publisher": publisher, "max_level": int(max_level), "sha256": api_id(ident),
            "rings": {str(k): int(v) for k, v in (rings or {"0": 0}).items()}, "created": int(time.time())}


def _ledger(sha, ident, about, c, get, now):
    return zsupply.ledger_candidates(sha, ident, about, zsupply.audit_nodes() if c.get("nodes") is None else c["nodes"],
                                     zsupply.officers() if c.get("keys") is None else c["keys"],
                                     c.get("required", 2), c.get("ring", 1), get, now)


def facts(folder, level, c=None, get=zsupply.fetch, now=None):
    """the facts for every record the nodes hold for the model in `folder`, and what each needs to be loaded"""
    c = c if c is not None else zsupply.conf()
    folder = Path(folder)
    try:
        claimed = json.loads((folder / RECORD).read_text())["manifest"]["sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused("the model has no release record (zenos-model.json)")
    files = files_of(folder)
    mid = model_id(files)
    ident = lambda m: m.get("kind") == KIND and m.get("sha256") == mid
    out = []
    for f in _ledger(claimed, lambda m: m.get("kind") == KIND, {"name": folder.name, "version": ""}, c, get, now):
        rec = f.get("_record") or {}
        m = rec.get("manifest") or {}
        f = dict(f, hash_ok=bool(f["hash_ok"] and ident(m)), kind_ok=m.get("kind") == KIND,
                 files_ok=isinstance(m.get("files"), dict) and m.get("files") == files and mid == claimed,
                 level=max(0, int(level)), max_level=max(0, int(m.get("max_level", 0) or 0)))
        out.append(f)
    return out


def check(folder, level, c=None, get=zsupply.fetch, now=None):
    """(allowed, reason): may the model in `folder` be loaded to see data of `level`? Nothing to decide (the
    supply check is off on this PC) allows; any doubt refuses."""
    import zdecide
    c = c if c is not None else zsupply.conf()
    if c.get("mode", "off") == "off":
        return True, None
    try:
        cands = facts(folder, level, c, get, now)
    except Refused as e:
        return False, str(e)
    first = None
    for f in cands:
        ok, why = zdecide.model(f)
        if ok:
            return True, None
        first = first or why
    return False, first or "ledger"


def check_api(conf, level, c=None, get=zsupply.fetch, now=None):
    """(allowed, reason): may a call go to this API model with data of `level`?"""
    import zdecide, zorch
    c = c if c is not None else zsupply.conf()
    denied = not zorch.provider_ok(conf)
    if c.get("mode", "off") == "off" and not denied:
        return True, None
    ident = api_identity(conf)
    sha = api_id(ident)
    first = "denied" if denied else None
    for f in _ledger(sha, lambda m: m.get("kind") == KIND_API, {"name": ident["model"], "version": ident["version"]},
                     c, get, now):
        m = (f.get("_record") or {}).get("manifest") or {}
        same = bool(ident["endpoint"]) and ident["endpoint"].startswith("https://") and \
            all(m.get(k) == ident[k] for k in ("provider", "host", "endpoint", "model", "version"))
        f = dict(f, kind_ok=m.get("kind") == KIND_API, same_model=same, denied=denied, level=max(0, int(level)),
                 max_level=max(0, int(m.get("max_level", 0) or 0)))
        ok, why = zdecide.model_api(f)
        if ok:
            return True, None
        first = first or why
    return False, first or "ledger"


def offline_check(folder, keys=None, required=None):
    """what zenos-integrity can say without the network: the record in the folder is signed by enough officers
    enrolled on this PC, and every file is the one it lists. [] when all is well, otherwise the findings."""
    folder = Path(folder)
    out = []
    try:
        rec = json.loads((folder / RECORD).read_text())
        m = rec["manifest"]
    except (OSError, ValueError, KeyError, TypeError):
        return [{"kind": "model-unrecorded", "path": str(folder), "detail": "no release record"}]
    keys = zsupply.officers() if keys is None else keys
    required = zsupply.conf().get("required", 2) if required is None else required
    try:
        signed = len(zsupply.valid_signers(rec, keys))
    except ValueError:
        signed = 0
    if m.get("kind") != KIND or signed < max(1, int(required)):
        out.append({"kind": "model-unsigned", "path": str(folder), "detail": f"{signed} of {required} signatures"})
    try:
        files = files_of(folder)
    except Refused as e:
        return out + [{"kind": "model-changed", "path": str(folder), "detail": str(e)}]
    want = m.get("files") or {}
    for rel in sorted(set(files) | set(want)):
        if rel not in want:
            out.append({"kind": "model-changed", "path": str(folder / rel), "detail": "not in the release record"})
        elif rel not in files:
            out.append({"kind": "model-changed", "path": str(folder / rel), "detail": "missing"})
        elif files[rel] != want[rel]:
            out.append({"kind": "model-changed", "path": str(folder / rel), "detail": "not the released file"})
    return out


def models():
    return sorted(p for p in MODELS.iterdir() if p.is_dir()) if MODELS.is_dir() else []

"""The release ledger: what a ZENOS PC lets in, and how a release gets there.

A release record describes one package file exactly: name, version, architecture, SHA-256 of the .deb, SHA-256 of
every file inside it, its configuration files, where it came from (ZENOS, or Debian/NodeSource checked against
their signed indexes), the builds that reproduced it, and when each ring of PCs may install it. Release officers
sign the record's digest each with their own key; a record counts on a PC only with `required` distinct officers'
signatures. Records go into the audit nodes' ledgers (the "releases" chain of the release publisher), so the
history of what was released cannot be rewritten without the audit nodes seeing it.

Before apt installs a package, the PC asks every audit node it is configured with what the ledger says about that
exact file, and the proven decision (formal/ZenosFormal/Supply.lean) lets it in only when a majority of the nodes
answer with the same record, signed by enough officers, the file matches it, nothing revoked it, and its ring is open.

PC configuration: /etc/zenos/supply.json
  {"mode": "enforce" | "warn" | "off", "required": 2, "ring": 1}
  release officers' keys: /etc/zenos/release-keys/<name>.pub (Ed25519, raw 32 bytes)
  audit nodes: the "nodes" of /etc/zenos/audit.json
"""
import base64, hashlib, json, os, re, ssl, subprocess, time, urllib.request
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONF = Path(os.environ.get("ZENOS_SUPPLY_CONF", "/etc/zenos/supply.json"))
KEYS = Path(os.environ.get("ZENOS_RELEASE_KEYS", "/etc/zenos/release-keys"))
AUDIT_CONF = Path(os.environ.get("ZENOS_AUDIT_CONF", "/etc/zenos/audit.json"))
SIG_CONTEXT = b"zenos-release1|"
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def canon(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(obj):
    return hashlib.sha256(canon(obj)).hexdigest()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------- what a package file contains ----------------

def deb_fields(deb):
    out = subprocess.run(["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture"], capture_output=True,
                         text=True, check=True).stdout
    f = dict(l.split(": ", 1) for l in out.splitlines() if ": " in l)
    return f.get("Package", ""), f.get("Version", ""), f.get("Architecture", "")


def deb_files(deb):
    """{path: sha256} for every regular file in the package, and {path: target} for its links"""
    import tarfile
    p = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(deb)], stdout=subprocess.PIPE)
    files, links = {}, {}
    with tarfile.open(fileobj=p.stdout, mode="r|") as t:
        for m in t:
            name = "/" + m.name.lstrip("./")
            if m.isfile():
                files[name] = hashlib.sha256(t.extractfile(m).read()).hexdigest()
            elif m.issym() or m.islnk():
                links[name] = m.linkname
    p.stdout.close()
    p.wait()
    if p.returncode:
        raise ValueError("dpkg-deb could not read %s" % deb)
    return files, links


def deb_conffiles(deb):
    r = subprocess.run(["dpkg-deb", "-I", str(deb), "conffiles"], capture_output=True, text=True)
    return sorted(l.strip() for l in r.stdout.splitlines() if l.strip()) if r.returncode == 0 else []


def apt_index_sha256(name, version):
    """the SHA-256 apt's signed index gives for name=version (Debian, NodeSource), or None"""
    r = subprocess.run(["apt-cache", "show", f"{name}={version}"], capture_output=True, text=True)
    return re.findall(r"^SHA256: ([0-9a-f]{64})$", r.stdout, re.M) if r.returncode == 0 else []


def manifest(deb, origin="zenos", rings=None, buildinfo=None, rebuilt=None, apt_check=False):
    name, version, arch = deb_fields(deb)
    sha = sha256_file(deb)
    files, links = deb_files(deb)
    m = {"kind": "zenos-release", "name": name, "version": version, "arch": arch, "sha256": sha,
         "size": os.path.getsize(deb), "files": files, "links": links, "conffiles": deb_conffiles(deb),
         "origin": origin, "rings": {str(k): int(v) for k, v in (rings or {"0": 0}).items()},
         "buildinfo": buildinfo, "rebuilt": rebuilt or [], "created": int(time.time())}
    if apt_check:
        m["origin_index_ok"] = sha in apt_index_sha256(name, version)
        if not m["origin_index_ok"]:
            raise ValueError(f"{name} {version}: not the file apt's signed index names")
    return m


# ---------------- records and officers' signatures ----------------

def kind(rec):
    """"release", "revoke" or None: a record is one or the other, never both (a release record with a "revoke" field
    added must not pass as a revocation carrying the release's signatures)"""
    if not isinstance(rec, dict):
        return None
    m, r = isinstance(rec.get("manifest"), dict), isinstance(rec.get("revoke"), dict)
    return "release" if m and not r else "revoke" if r and not m else None


def well_formed(rec):
    """a record in the shape the ledger defines (anything else a node serves is skipped, never parsed further): one
    of release or revoke, signatures a list of {"by": str, "sig": str}, rings a map of ring name to a whole number"""
    k = kind(rec)
    if k is None:
        return False
    sigs = rec.get("sigs", [])
    if not isinstance(sigs, list) or not all(isinstance(x, dict) and isinstance(x.get("by"), str)
                                             and isinstance(x.get("sig"), str) for x in sigs):
        return False
    if k == "release":
        rings = rec["manifest"].get("rings", {})
        if rings is not None and not (isinstance(rings, dict) and all(
                isinstance(a, str) and isinstance(b, int) and not isinstance(b, bool) and b >= 0 for a, b in rings.items())):
            return False
    return True


def record_digest(rec):
    k = kind(rec)
    if k is None:
        raise ValueError("not a release or revocation record")
    return digest({"manifest": rec["manifest"]} if k == "release" else {"revoke": rec["revoke"]})


def sign(rec, key, by):
    """add one officer's signature over the record's digest (key: an Ed25519 private key object, or a hardware-key
    signer with .sign(bytes))"""
    if not NAME.match(by):
        raise ValueError("bad officer name")
    d = record_digest(rec)
    rec["digest"] = d
    rec.setdefault("sigs", [])
    rec["sigs"] = [s for s in rec["sigs"] if s.get("by") != by] + [
        {"by": by, "sig": base64.b64encode(key.sign(SIG_CONTEXT + bytes.fromhex(d))).decode()}]
    return rec


def officers(keys_dir=None):
    d = Path(keys_dir or KEYS)
    return {p.stem: p.read_bytes() for p in sorted(d.glob("*.pub"))} if d.is_dir() else {}


def valid_signers(rec, keys):
    """officers (enrolled on this PC) whose signature over this record's digest verifies"""
    d = record_digest(rec)
    out = []
    for s in rec.get("sigs", []) if isinstance(rec.get("sigs"), list) else []:
        if not isinstance(s, dict):
            continue
        by = str(s.get("by", ""))
        if by in keys:
            try:
                Ed25519PublicKey.from_public_bytes(keys[by]).verify(base64.b64decode(s["sig"]), SIG_CONTEXT + bytes.fromhex(d))
                out.append(by)
            except Exception:
                pass
    return sorted(set(out))


# ---------------- asking the audit nodes ----------------

def fetch(node, sha, timeout=15):
    """the node's signed list of release and revocation records for this SHA-256 (raises on any doubt)"""
    u = urlparse(node["url"])
    if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("audit nodes must be reached over https")
    with urllib.request.urlopen(node["url"].rstrip("/") + f"/v1/release/{sha}", timeout=timeout,
                                context=ssl.create_default_context() if u.scheme == "https" else None) as r:
        a = json.loads(r.read())
    Ed25519PublicKey.from_public_bytes(base64.b64decode(node["pub"])).verify(base64.b64decode(a["sig"]),
                                                                             canon(a["release"]))
    if a["release"].get("sha256") != sha:
        raise ValueError("answer about another file")
    return a["release"]["records"]


def candidates(deb, nodes, keys, required, ring, get=fetch, now=None):
    """the facts for every release record any node holds for this file, most widely held first. Each node votes
    for every record it holds (an extra record a node adds cannot hide the real one), and the signatures on all
    copies of the same record are put together (a copy with signatures stripped cannot hide them either)."""
    sha = sha256_file(deb)
    name, version, arch = deb_fields(deb)
    ident = lambda m: m.get("kind", "zenos-release") == "zenos-release" and m.get("sha256") == sha and \
        (m.get("name"), m.get("version"), m.get("arch")) == (name, version, arch)
    return ledger_candidates(sha, ident, {"name": name, "version": version}, nodes, keys, required, ring, get, now)


def ledger_candidates(sha, ident, about, nodes, keys, required, ring, get=fetch, now=None):
    """the same for anything the ledger describes by one SHA-256: a package file, or an AI model (zmodel.py: the
    digest of its files list, or of the API identity it is pinned to). ident(manifest) says whether a record is the
    thing being checked (`hash_ok`); about: {"name", "version"} for the facts."""
    name, version = about.get("name"), about.get("version")
    answers = {}
    for n in nodes:
        try:
            a = get(n, sha)
            answers[n["name"]] = a if isinstance(a, list) else None     # not a list: as good as no answer
        except Exception:
            answers[n["name"]] = None
    held, records, sigs, revoked = {}, {}, {}, False
    for node, recs in answers.items():
        for r in recs or []:
            if not well_formed(r):                     # one node's malformed record is skipped, not trusted or fatal
                continue
            k = kind(r)
            if k == "release" and r["manifest"].get("sha256") == sha:
                d = record_digest(r)
                held.setdefault(d, set()).add(node)
                records.setdefault(d, {"manifest": r["manifest"]})
                for x in r.get("sigs", []):
                    if isinstance(x, dict):
                        sigs.setdefault(d, {})[(x.get("by"), x.get("sig"))] = x
            elif k == "revoke" and r["revoke"].get("sha256") == sha:
                # a revocation signed by enough officers counts wherever it is found: holding it back takes every
                # node, not a majority
                if len(valid_signers(r, keys)) >= max(1, int(required)):
                    revoked = True
    reachable = [n for n, a in answers.items() if a is not None]
    out = []
    for d in sorted(held, key=lambda x: (-len(held[x]), x)):
        rec = dict(records[d], sigs=list(sigs.get(d, {}).values()), digest=d)
        m = rec["manifest"]
        hash_ok = m.get("sha256") == sha and bool(ident(m))
        rings = m.get("rings") or {}
        ring_open = int(rings[str(ring)]) if str(ring) in rings else max(list(rings.values()) or [0])
        votes = [{"node": n, "sig_ok": n in reachable, "record": d if n in held[d] else ""} for n in answers]
        out.append({"sha256": sha, "name": name, "version": version, "nodes": [n["name"] for n in nodes],
                    "votes": votes, "record": d, "hash_ok": hash_ok, "signers": valid_signers(rec, keys),
                    "officers": sorted(keys), "required": int(required), "revoked": revoked,
                    "ring_open": max(0, ring_open), "now": int(now if now is not None else time.time()), "_record": rec})
    if not out:
        out.append({"sha256": sha, "name": name, "version": version, "nodes": [n["name"] for n in nodes],
                    "votes": [{"node": n, "sig_ok": answers[n] is not None, "record": ""} for n in answers],
                    "record": "", "hash_ok": False, "signers": [], "officers": sorted(keys), "required": int(required),
                    "revoked": revoked, "ring_open": 0, "now": int(now if now is not None else time.time()),
                    "_record": None})
    out[0]["_reachable"] = len(reachable)
    return out


def facts(deb, nodes, keys, required, ring, get=fetch, now=None):
    return candidates(deb, nodes, keys, required, ring, get, now)[0]


def decide(deb, nodes, keys, required, ring, get=fetch, now=None):
    """(allowed, reason, facts): allowed if the proven decision allows any record the nodes hold for this file"""
    import zdecide
    cands = candidates(deb, nodes, keys, required, ring, get, now)
    first = None
    for f in cands:
        ok, why = zdecide.install(f)
        if ok:
            return True, None, f
        first = first or (why, f)
    return False, first[0], first[1]


def conf():
    try:
        c = json.loads(CONF.read_text())
    except FileNotFoundError:
        return {"mode": "off"}
    except (OSError, ValueError):
        return {"mode": "enforce", "broken": True}     # a configuration that cannot be read never loosens the check
    c.setdefault("mode", "enforce")
    c.setdefault("required", 2)
    c.setdefault("ring", 1)
    return c


def audit_nodes():
    try:
        return json.loads(AUDIT_CONF.read_text()).get("nodes", [])
    except (OSError, ValueError):
        return []

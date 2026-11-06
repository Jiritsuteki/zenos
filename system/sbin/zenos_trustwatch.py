#!/usr/bin/env python3
"""ZENOS trust agent (root service): watches every route by which this PC decides to trust a server, and fixes it.

A "route" is a program and the root certificates it trusts. ZENOS has several: the system store (/etc/ssl/certs,
used by the browser, apt, curl and Python), the root list compiled into Node (messenger, storage, any Node program),
and any bundle a program brings with it (Python certifi, Java cacerts, NSS databases).

Every 15 minutes the agent takes inventory of all trust stores on the disk and rates each route:
  red    a store trusts a root ZENOS distrusts, or a store changed outside the package system
  amber  a store trusts a root that vouches for a compromised CA key, and programs using that store are not
         covered by the ZENOS refusal list; a root was added; new distrust from Mozilla affects a local root
Every 6 hours (and right after an anomaly) it reads Mozilla's OneCRL, the list Firefox uses to distrust CA
certificates. The list is accepted only if its content signature verifies up to Mozilla's pinned signing root.
New entries go into /var/lib/zenos/distrust.learned.json, which the ZENOS browser and every Node program enforce at
once (zdistrust.py / zdistrust.js). Then the agent goes for the fix: it refreshes the package lists and, if Debian or
ZENOS has published an update for a TLS / trust package, installs it at once (unattended-upgrade, same origins and
rules as the daily run) instead of waiting for the next day.

Output: /run/zenos/trust.json (routes, stores, alerts; read by the security monitor), /var/log/zenos/trust.jsonl.
"""
import base64, hashlib, json, os, re, shutil, ssl, subprocess, sys, time, urllib.request

# the ZENOS library is ../lib/zenos beside this program (/usr/lib/zenos, root-owned)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
import zdistrust

_T = os.environ.get("ZENOS_TRUST_DIR")           # tests: keep every file the agent writes in one folder
OUT = _T + "/trust.json" if _T else "/run/zenos/trust.json"
STATE = _T + "/trust-state.json" if _T else "/var/lib/zenos/trust-state.json"
LEARNED = os.environ.get("ZENOS_DISTRUST_LEARNED") or "/var/lib/zenos/distrust.learned.json"
LOG = _T + "/trust.jsonl" if _T else "/var/log/zenos/trust.jsonl"
DRY = "--dry-fix" in sys.argv                      # look for fixes (simulation) but install nothing
REPEAT = 86400                                     # the same alert is raised again after a day at most
FIX_GAP = 3600                                     # go for a fix at most once an hour
INV_EVERY, FEED_EVERY = 900, 6 * 3600
SYSTEM_STORE = "/etc/ssl/certs/ca-certificates.crt"
LOCAL_ROOTS = "/usr/local/share/ca-certificates"
ONECRL = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0"
ONECRL_SIGNER = "onecrl.content-signature.mozilla.org"
# Mozilla's content-signing root (root-ca-production-amo), the same pin Firefox uses (security.content.signature.root_hash)
MOZ_ROOT = "C8A80E9AFAEF4E219B6FB5D7A71D0F101223BAC5001AC28F9B0D43DC59A106DB"
TRUST_PKGS = ["ca-certificates", "openssl", "libssl3t64", "libgnutls30t64", "libnss3", "nodejs", "libnode115",
              "libsoup-3.0-0", "libwebkit2gtk-4.1-0", "glib-networking", "python3-certifi", "p11-kit-modules",
              "ca-certificates-java", "curl", "libcurl4t64", "libcurl3t64-gnutls"]
STORE_NAMES = ["cacert.pem", "ca-certificates.crt", "ca-bundle.crt", "ca-bundle.pem", "tls-ca-bundle.pem",
               "roots.pem", "cacerts", "cert9.db"]
SEARCH = ["/etc", "/usr", "/opt", "/srv", "/var/lib"]
PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def sh(*a, timeout=120, env=None):
    try:
        return subprocess.run(a, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout,
                              env=env).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def log(kind, **kw):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write(json.dumps(dict(kw, t=int(time.time()), kind=kind)) + "\n")


def load(p, default):
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(p, obj, mode=0o644):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.chmod(tmp, mode)
    os.replace(tmp, p)


# ---------------------------------------------------------------- inventory

def certs_of(ders):
    from cryptography import x509
    out = []
    for der in ders:
        try:
            c = x509.load_der_x509_certificate(der)
            out.append({"der": der, "obj": c, "subject": c.subject.rfc4514_string()[:120],
                        "spki": zdistrust.spki_sha256(der), "sha256": hashlib.sha256(der).hexdigest().upper()})
        except Exception:
            continue
    return out


def java_store(b):
    """trusted certificates of a Java cacerts file (JKS, or PKCS12 as in JDK 9+), read without Java"""
    import struct
    if b[:4] == b"\xfe\xed\xfe\xed":                       # JKS
        try:
            ver, n = struct.unpack(">II", b[4:12])
            i, out = 12, []
            for _ in range(n):
                tag, = struct.unpack(">I", b[i:i + 4]); i += 4
                l, = struct.unpack(">H", b[i:i + 2]); i += 2 + l + 8          # alias, date
                if tag == 1:                                                  # private key entry: skip
                    l, = struct.unpack(">I", b[i:i + 4]); i += 4 + l
                    k, = struct.unpack(">I", b[i:i + 4]); i += 4
                    for _ in range(k):
                        l, = struct.unpack(">H", b[i:i + 2]); i += 2 + l
                        l, = struct.unpack(">I", b[i:i + 4]); i += 4 + l
                elif tag == 2:                                                # trusted certificate
                    if ver == 2:
                        l, = struct.unpack(">H", b[i:i + 2]); i += 2 + l
                    l, = struct.unpack(">I", b[i:i + 4]); out.append(b[i + 4:i + 4 + l]); i += 4 + l
                else:
                    return out
            return out
        except struct.error:
            return None
    from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
    for pw in (None, b"changeit"):          # "changeit": Java's public default store password, not a secret
        try:
            p = pkcs12.load_pkcs12(b, pw)
            return [c.certificate.public_bytes(Encoding.DER) for c in p.additional_certs] + \
                   ([p.cert.certificate.public_bytes(Encoding.DER)] if p.cert else [])
        except Exception:
            continue
    return None


def describe(path):
    """(label, users, unused) for a trust store file found on the disk"""
    m = re.match(r"/var/lib/docker/overlay2/([0-9a-f]+)/diff(/.*)", path)
    if m:
        layer, inner = m.groups()
        img = docker_layers().get(layer, "image layer " + layer[:12])
        running, stopped = [], []
        for c in docker_containers():
            if layer not in c["layers"]:
                continue
            if any(inner == d or inner.startswith(d.rstrip("/") + "/") for d in c["mounts"]):
                continue                       # a bind mount replaces this file inside that container
            (running if c["running"] else stopped).append(c["name"])
        users = ["running container " + n for n in running] + ["stopped container " + n for n in stopped]
        # the file is a live route only while a running container sees it
        return ("Container image %s: %s" % (img, inner),
                users or ["no container uses it (image only, or replaced by a mount)"], not running)
    owner = dpkg_owner(path)
    label = path + (" (package %s)" % owner if owner else "")
    if path.endswith("/certifi/cacert.pem"):
        try:
            if "/etc/ssl/certs/ca-certificates.crt" in open(os.path.join(os.path.dirname(path), "core.py")).read():
                return label, ["nobody: this certifi is patched to use the system trust store"], True
        except OSError:
            pass
    if path.endswith("/lib/security/cacerts"):
        return label, ["Java programs of " + path.rsplit("/lib/security/", 1)[0]], False
    return label, ["programs that use " + path], False


_layers = {}
_containers = []


def docker_containers():
    """[{name, running, layers, mounts}] for every container, from docker inspect"""
    if not _containers and shutil.which("docker"):
        ids = sh("docker", "ps", "-aq", timeout=30).split()
        if ids:
            out = sh("docker", "inspect", "--format",
                     "{{.Name}}|{{.State.Running}}|{{.GraphDriver.Data.UpperDir}}:{{.GraphDriver.Data.LowerDir}}|"
                     "{{range .Mounts}}{{.Destination}},{{end}}", *ids, timeout=60)
            for l in out.splitlines():
                f = l.split("|")
                if len(f) == 4:
                    _containers.append({"name": f[0].lstrip("/"), "running": f[1] == "true",
                                        "layers": set(re.findall(r"/var/lib/docker/overlay2/([0-9a-f]+)/diff", f[2])),
                                        "mounts": [d for d in f[3].split(",") if d]})
    return _containers


def docker_layers():
    if not _layers and shutil.which("docker"):
        ids = sh("docker", "image", "ls", "-q", timeout=30).split()
        if ids:
            out = sh("docker", "image", "inspect", "--format",
                     "{{json .RepoTags}} {{.GraphDriver.Data.UpperDir}}:{{.GraphDriver.Data.LowerDir}}", *ids, timeout=60)
            for l in out.splitlines():
                tags, _, dirs = l.partition(" ")
                try:
                    name = (json.loads(tags) or ["(untagged)"])[0]
                except ValueError:
                    name = "?"
                for d in re.findall(r"/var/lib/docker/overlay2/([0-9a-f]+)/diff", dirs):
                    _layers.setdefault(d, name)
    return _layers


def read_store(path):
    """the roots in a trust store file, or None if this kind of store cannot be read here"""
    base = os.path.basename(path)
    if base == "cert9.db":
        if not shutil.which("certutil"):
            return None
        d = os.path.dirname(path)
        ders = []
        for l in sh("certutil", "-L", "-d", "sql:" + d).splitlines()[4:]:
            nick = l[:60].strip()
            if nick and ",C" in l.replace(" ", ""):
                ders += [ssl.PEM_cert_to_DER_cert(m.decode()) for m in
                         PEM_RE.findall(sh("certutil", "-L", "-d", "sql:" + d, "-n", nick, "-a").encode())]
        return ders
    try:
        raw = open(path, "rb").read()
    except OSError:
        return None
    if base == "cacerts":
        return java_store(raw)
    return [ssl.PEM_cert_to_DER_cert(m.decode()) for m in PEM_RE.findall(raw)]


def root_only(path):
    """a file only root can change: it and every folder above it owned by root and not writable by others. This
    service runs as root, so it never starts a program that someone else could have put or changed there."""
    try:
        p = os.path.realpath(path)
        while True:
            st = os.lstat(p)
            if st.st_uid != 0 or st.st_mode & 0o022:
                return False
            if p == "/":
                return True
            p = os.path.dirname(p)
    except OSError:
        return False


def node_binaries():
    found = set()
    for n in ("node", "nodejs"):
        p = shutil.which(n)
        if p:
            found.add(os.path.realpath(p))
    for l in sh("find", "/usr/share/zenos", "/opt", "/usr/lib", "-xdev", "-type", "f", "-name", "node",
                "-perm", "-u+x", timeout=60).splitlines():
        try:
            if open(l, "rb").read(4) == b"\x7fELF":
                found.add(os.path.realpath(l))
        except OSError:
            pass
    skipped = sorted(b for b in found if not root_only(b))
    if skipped:
        log("node-skipped", reason="not root-owned, not run", binaries=skipped[:10])
    return sorted(b for b in found if root_only(b))


def node_store(binary):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}         # nothing from the environment (NODE_OPTIONS, NODE_PATH)
    out = sh(binary, "-e", "const t=require('tls');console.log(JSON.stringify({v:process.version,"
             "sys:String(process.config.variables.openssl_use_def_ca_store),r:t.rootCertificates}))", timeout=30, env=env)
    try:
        d = json.loads(out)
    except ValueError:
        return None
    return d["v"], d["sys"] == "true", [ssl.PEM_cert_to_DER_cert(p) for p in d["r"]]


def store_files():
    args = ["find"] + SEARCH + ["-xdev", "("]
    for i, n in enumerate(STORE_NAMES):
        args += (["-o"] if i else []) + ["-name", n]
    args += [")", "-type", "f"]
    files = {os.path.realpath(p) for p in sh(*args, timeout=300).splitlines() if p}
    files.add(os.path.realpath(SYSTEM_STORE))
    return sorted(f for f in files if not f.startswith("/var/lib/zenos/"))


def compromised_pems():
    """the compromised CA certificates shipped in distrust.json, to see which local roots vouch for them"""
    from cryptography import x509
    out = []
    d = load(os.path.join(os.path.dirname(zdistrust.__file__), "distrust.json"), {})
    for e in d.get("entries", []):
        for k in e.get("keys", []):
            for c in k.get("certificates", []):
                if c.get("pem"):
                    try:
                        out.append((k["name"], x509.load_pem_x509_certificate(c["pem"].encode())))
                    except Exception:
                        pass
    return out


def vouches(root, bad):
    for name, c in bad:
        if c.issuer != root["obj"].subject:
            continue
        try:
            c.verify_directly_issued_by(root["obj"])
            return name
        except Exception:
            continue
    return None


def dpkg_owner(path):
    out = sh("dpkg-query", "-S", path, timeout=20)
    return out.split(":")[0] if out and not out.startswith("dpkg-query") else None


def inventory(prev):
    _containers.clear(); _layers.clear()          # containers come and go between rounds
    bad = compromised_pems()
    learned = load(LEARNED, {})
    onecrl_issuers = {k.split(":")[0] for k in learned.get("issuer_serial", {})}
    key_issuers = set(learned.get("key_issuers", []))
    stores = []
    system_spki = {c["spki"] for c in certs_of(read_store(SYSTEM_STORE) or [])}

    def rate(sid, label, users, ders, protected, path=None):
        roots = certs_of(ders)
        h = hashlib.sha256(b"".join(sorted(r["sha256"].encode() for r in roots))).hexdigest()
        s = {"id": sid, "label": label, "path": path, "users": users, "protected": protected, "roots": len(roots),
             "hash": h, "distrusted": [], "vouching": [], "not_in_system": [], "onecrl_issuers": 0,
             "key_compromise_issuers": []}
        for r in roots:
            w = zdistrust.why(r["der"])
            if w:
                s["distrusted"].append({"root": r["subject"], "why": w})
            v = vouches(r, bad)
            if v:
                s["vouching"].append({"root": r["subject"], "for": v})
            if r["spki"] not in system_spki:
                s["not_in_system"].append(r["subject"])
            iss = base64.b64encode(r["obj"].subject.public_bytes()).decode()
            if iss in onecrl_issuers:
                s["onecrl_issuers"] += 1
            if iss in key_issuers:
                s["key_compromise_issuers"].append(r["subject"])
        s["_spkis"] = sorted({r["spki"] for r in roots})
        stores.append(s)

    for path in store_files():
        ders = read_store(path)
        if ders is None:
            stores.append({"id": path, "label": path, "path": path, "users": ["programs that read " + path],
                           "protected": False, "unreadable": True, "roots": None})
            continue
        if path == os.path.realpath(SYSTEM_STORE):
            rate(path, "System trust store", ["ZENOS Browser (WebKit/GnuTLS)", "apt", "curl", "Python programs",
                                              "Node programs (default)"], ders, False, path)
        else:
            label, users, unused = describe(path)
            rate(path, label, users, ders, unused, path)
            stores[-1]["unused"] = unused
    for b in node_binaries():
        r = node_store(b)
        if r:
            v, uses_sys, ders = r
            rate("node:" + b, "Node %s built-in root list (%s)" % (v, b),
                 ["ZENOS Messages", "ZENOS storage", "any Node program that passes tls.rootCertificates"
                  + ("" if uses_sys else " (this Node uses it by default)")], ders, True)
    try:
        local = sorted(f for f in os.listdir(LOCAL_ROOTS) if f.endswith(".crt"))
    except OSError:
        local = []

    alerts = []
    pstores = {s["id"]: s for s in prev.get("stores", [])}
    dpkg_t = os.path.getmtime("/var/lib/dpkg/status") if os.path.exists("/var/lib/dpkg/status") else 0
    for s in stores:
        if s.get("unreadable"):
            if s["id"] not in pstores:
                alerts.append(("amber", "Trust store ZENOS cannot read", "%s holds roots ZENOS cannot inspect." % s["id"]))
            continue
        name = s["label"]
        for d in s["distrusted"]:
            alerts.append(("red", "Distrusted root in a trust store", "%s trusts %s: %s" % (name, d["root"], d["why"])))
        if s["vouching"] and not s["protected"]:
            alerts.append(("amber", "Route open to a compromised CA key",
                           "%s trusts %s, which cross-signed %s. Programs using it without ZENOS refusal accept it."
                           % (name, s["vouching"][0]["root"], s["vouching"][0]["for"])))
        if s["key_compromise_issuers"] and not s["protected"]:
            alerts.append(("amber", "Root with a key-compromise distrust",
                           "%s trusts %s, under which Mozilla distrusts a CA key." % (name, s["key_compromise_issuers"][0])))
        p = pstores.get(s["id"])
        if p and p.get("hash") and p["hash"] != s["hash"]:
            added = sorted(set(s["_spkis"]) - set(p.get("_spkis", [])))
            outside = dpkg_t <= prev.get("t", 0) and s["path"] and dpkg_owner(s["path"])
            if outside:
                alerts.append(("red", "Trust store changed outside the package system",
                               "%s changed (%d root(s) added) and no package update explains it." % (name, len(added))))
            elif added:
                alerts.append(("amber", "Roots added to a trust store", "%s now trusts %d more root(s)." % (name, len(added))))
            log("store-changed", store=s["id"], added=len(added), outside_packages=bool(outside))
    if local != prev.get("local_roots", local):
        alerts.append(("amber", "Locally added root certificates changed",
                       "%s now holds: %s" % (LOCAL_ROOTS, ", ".join(local) or "nothing")))
    return stores, local, alerts


# ---------------------------------------------------------------- Mozilla OneCRL (signed)

def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fetch(url, limit=8 << 20):
    req = urllib.request.Request(url, headers={"User-Agent": "ZENOS-trustwatch/1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(limit)


def verify_changeset(d, chain_pem):
    """Mozilla Remote Settings content signature: P-384 ECDSA over the canonical records, chained to the pinned root"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.x509.oid import ExtensionOID
    certs = x509.load_pem_x509_certificates(chain_pem)
    root = hashlib.sha256(certs[-1].public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    if root != MOZ_ROOT:
        raise ValueError("signing chain does not end at Mozilla's root")
    for c, i in zip(certs, certs[1:]):
        c.verify_directly_issued_by(i)
    now = time.time()
    for c in certs:
        if not (c.not_valid_before_utc.timestamp() <= now <= c.not_valid_after_utc.timestamp()):
            raise ValueError("signing certificate outside its validity")
    san = certs[0].extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    if ONECRL_SIGNER not in san.get_values_for_type(x509.DNSName):
        raise ValueError("signed by the wrong signer")
    raw = base64.urlsafe_b64decode(d["metadata"]["signature"]["signature"] + "==")
    sig = encode_dss_signature(int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big"))
    recs = sorted((r for r in d["changes"] if not r.get("deleted")), key=lambda r: r["id"])
    payload = canonical({"data": recs, "last_modified": str(d["timestamp"])})
    certs[0].public_key().verify(sig, b"Content-Signature:\x00" + payload.encode(), ec.ECDSA(hashes.SHA384()))
    return recs


def sync_onecrl():
    d = json.loads(fetch(ONECRL))
    x5u = d["metadata"]["signature"]["x5u"]
    if not x5u.startswith("https://content-signature-2.cdn.mozilla.net/"):
        raise ValueError("unexpected signing chain location")
    recs = verify_changeset(d, fetch(x5u, 1 << 20))
    old = load(LEARNED, {})
    spki, isn, key_issuers, labels = {}, {}, set(), {}
    for r in recs:
        if r.get("enabled") is False:
            continue
        det = r.get("details") or {}
        label = "Mozilla OneCRL: " + (det.get("name") or det.get("why") or det.get("bug") or r["id"])[:120]
        if r.get("pubKeyHash"):
            spki[base64.b64decode(r["pubKeyHash"]).hex().upper()] = label
            if r.get("subject"):
                key_issuers.add(r["subject"])
        elif r.get("issuerName") and r.get("serialNumber"):
            isn[r["issuerName"] + ":" + r["serialNumber"]] = label
        labels[r["id"]] = label
    new_spki = sorted(set(spki) - set(old.get("spki", {})))
    new_isn = sorted(set(isn) - set(old.get("issuer_serial", {})))
    first = not old
    save(LEARNED, {"about": "Learned by zenos_trustwatch from Mozilla OneCRL (content signature verified to the pinned "
                            "Mozilla root). Enforced by zdistrust.py / zdistrust.js.",
                   "source": ONECRL, "timestamp": d["timestamp"], "fetched": int(time.time()),
                   "spki": spki, "issuer_serial": isn, "key_issuers": sorted(key_issuers)})
    log("onecrl", records=len(recs), keys=len(spki), certificates=len(isn), new_keys=len(new_spki),
        new_certificates=len(new_isn), first=first)
    return {"records": len(recs), "keys": len(spki), "certificates": len(isn), "timestamp": d["timestamp"],
            "new_keys": [] if first else [spki[h] for h in new_spki],
            "new_certificates": 0 if first else len(new_isn)}


# ---------------------------------------------------------------- the fix

def installed(pkgs):
    out = sh("dpkg-query", "-W", "-f", "${Package} ${Status}\\n", *pkgs, timeout=30)
    return [l.split()[0] for l in out.splitlines() if l.endswith("installed") and " not-installed" not in l]


def pending_trust_updates():
    pk = installed(TRUST_PKGS)
    if not pk:
        return []
    out = sh("apt-get", "-s", "-o", "Debug::NoLocking=1", "install", "--only-upgrade", *pk, timeout=120)
    return [l.split()[1] for l in out.splitlines() if l.startswith("Inst ")]


def get_fix(reason):
    """go and fetch the fix: refresh the package lists, install any published update for a trust package"""
    if not DRY:
        sh("apt-get", "update", "-q", timeout=600)
    pend = pending_trust_updates()
    res = {"t": int(time.time()), "reason": reason, "found": pend, "installed": [], "still_pending": pend, "dry": DRY}
    if pend and not DRY and shutil.which("unattended-upgrade"):
        sh("unattended-upgrade", timeout=1800)
        left = pending_trust_updates()
        res["installed"] = sorted(set(pend) - set(left))
        res["still_pending"] = left
    log("fix", **res)
    return res


# ---------------------------------------------------------------- main loop

def publish(st, stores, local, feed, fix, now):
    risk = "red" if any(s.get("distrusted") for s in stores) else \
        "amber" if any((s.get("vouching") or s.get("key_compromise_issuers")) and not s.get("protected")
                       for s in stores) else "green"
    st.update(t=int(now), stores=stores, local_roots=local, feed=feed, fix=fix, risk=risk)
    save(STATE, st, 0o600)
    pub = {k: v for k, v in st.items() if k != "seen"}
    pub["stores"] = [{k: v for k, v in s.items() if not k.startswith("_")} for s in stores]
    save(OUT, pub)


def main():
    once = "--once" in sys.argv
    st = load(STATE, {})
    st.setdefault("alerts", [])
    next_feed = 0 if "--no-feed" not in sys.argv else float("inf")
    while True:
        now = time.time()
        new_alerts, reasons = [], []
        feed = st.get("feed")
        if now >= next_feed:
            try:
                feed = sync_onecrl()
                feed["ok"], feed["checked"] = True, int(now)
                if feed["new_keys"]:
                    new_alerts.append(("red", "Mozilla distrusted a CA key",
                                       "%d key(s): %s. ZENOS refuses them now." % (len(feed["new_keys"]),
                                                                                   "; ".join(feed["new_keys"][:2]))))
                    reasons.append("Mozilla distrusted %d CA key(s)" % len(feed["new_keys"]))
                elif feed["new_certificates"]:
                    reasons.append("Mozilla distrusted %d CA certificate(s)" % feed["new_certificates"])
            except Exception as e:
                feed = dict(st.get("feed") or {}, ok=False, error=str(e)[:160], checked=int(now))
                log("onecrl-failed", error=str(e)[:300])
                if now - (st.get("feed") or {}).get("last_ok", now) > 2 * 86400:
                    new_alerts.append(("amber", "Trust list not updated", "Mozilla's distrust list could not be read "
                                                                          "for 2 days: " + str(e)[:80]))
            if feed.get("ok"):
                feed["last_ok"] = int(now)
            next_feed = now + FEED_EVERY
        stores, local, inv_alerts = inventory(st)
        new_alerts += inv_alerts
        if any(a[0] == "red" for a in inv_alerts):
            reasons.append("a trust store trusts a distrusted root")
        elif any("Route open" in a[1] for a in inv_alerts):
            reasons.append("a trust store trusts a root that cross-signed a compromised CA key")
        fix = st.get("fix")
        since = now - (fix or {}).get("t", 0)
        publish(st, stores, local, feed, fix, now)       # show the routes now; fetching a fix can take a while
        if (reasons and since > FIX_GAP) or since > 86400:
            fix = get_fix("; ".join(reasons) or "daily check")
            if fix["installed"]:
                new_alerts.append(("amber", "Trust fix installed", "Installed: " + ", ".join(fix["installed"][:5])))
                stores, local, _ = inventory({"stores": [], "local_roots": local})
            elif fix["still_pending"]:
                new_alerts.append(("amber", "Trust fix waiting", "Published but not installed yet: "
                                   + ", ".join(fix["still_pending"][:5])))
            elif reasons:
                new_alerts.append(("amber", "No fix published yet",
                                   "%s. No package fix published yet. The ZENOS browser and Node programs refuse it "
                                   "meanwhile; the stores named in the other alerts are not covered." % reasons[0]))
        seen = st.setdefault("seen", {})
        for sev, title, text in new_alerts:
            k = hashlib.sha256((title + text).encode()).hexdigest()[:16]
            if now - seen.get(k, 0) < REPEAT:
                continue
            seen[k] = int(now)
            st["alerts"].append({"id": "%d-trust-%d" % (int(now * 1000), len(st["alerts"])), "t": int(now),
                                 "sev": sev, "title": title, "text": text[:200]})
            log("alert", sev=sev, title=title, text=text)
        st["alerts"] = st["alerts"][-30:]
        publish(st, stores, local, feed, fix, now)
        if once:
            return
        time.sleep(INV_EVERY)


if __name__ == "__main__":
    main()

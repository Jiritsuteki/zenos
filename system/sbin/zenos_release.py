#!/usr/bin/env python3
"""ZENOS releases: describe a package file, have release officers sign it, put it in the release ledger.

No single machine or person can release on its own: a record counts on the PCs only with the signatures of at least
`required` officers (each signs on their own machine, with a key kept offline or on a hardware key), and only once
a majority of the audit nodes hold it. The publisher only carries signed records to the audit nodes; it holds no
officer key, and neither does any central service.

  zenos_release.py keygen --out OFFICER.key                 a new officer key (prints the public key for the PCs)
  zenos_release.py manifest DEB --origin zenos|debian|nodesource [--rings 0=0,1=+1d,2=+3d] [--apt-check]
                   [--buildinfo FILE] [--rebuilt NAME=SHA256 ...] --out RECORD.json
  zenos_release.py sign RECORD.json --key OFFICER.key --by NAME
  zenos_release.py verify RECORD.json --keys DIR --required N
  zenos_release.py revoke SHA256 --reason TEXT --out RECORD.json      (then sign it like a release)
  zenos_release.py model FOLDER --name N --version V --publisher P --source URL --licence L --max-level 0..5
                   [--rings 0=0,1=+1d] --out RECORD.json
      an AI model kept on the PCs: every file of the folder (weights, tokenizer, settings, adapters) with its
      SHA-256 (zmodel.py); sign and publish it like a package, then `zenos_model.py install` on the PCs
  zenos_release.py model-api --kind anthropic|openai|openai-compatible --model M [--url URL] [--version V]
                   --publisher P --max-level 0..5 --out RECORD.json
      an AI model called through an API: the identity calls are pinned to (provider, address, model, version)
  zenos_release.py publish RECORD.json --ledger FILE --conf PUBLISHER.json
      PUBLISHER.json: {"machine": "zenos-release", "nodes": [...audit nodes...], "ledgers": {"releases": FILE}}
      (shipped with the audit shipping, signed with the publisher's own identity key: ZENOS_AUDIT_KEY)
"""
import base64, json, os, sys, time
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import zsupply                                                   # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey   # noqa: E402
from cryptography.hazmat.primitives import serialization          # noqa: E402


def rings_arg(s, now=None):
    now = int(now or time.time())
    out = {}
    for part in (s or "0=0").split(","):
        k, _, v = part.partition("=")
        if v.startswith("+"):
            n, unit = int(v[1:-1]), v[-1]
            v = now + n * {"h": 3600, "d": 86400, "m": 60}[unit]
        out[str(int(k))] = int(v)
    return out


def load_key(p):
    return Ed25519PrivateKey.from_private_bytes(Path(p).read_bytes())


def main():
    a = sys.argv[1:]
    opt = lambda k, d=None: a[a.index(k) + 1] if k in a else d
    if not a:
        sys.exit(__doc__)
    cmd = a[0]
    if cmd == "keygen":
        k = Ed25519PrivateKey.generate()
        out = Path(opt("--out"))
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        out.with_suffix(".pub").write_bytes(pub)
        return print("public key (goes to /etc/zenos/release-keys/<name>.pub on the PCs):", base64.b64encode(pub).decode())
    if cmd == "manifest":
        rebuilt = []
        if "--rebuilt" in a:
            for x in a[a.index("--rebuilt") + 1:]:
                if x.startswith("--"):
                    break
                who, _, sha = x.partition("=")
                rebuilt.append({"builder": who, "sha256": sha})
        bi = opt("--buildinfo")
        m = zsupply.manifest(a[1], origin=opt("--origin", "zenos"), rings=rings_arg(opt("--rings")),
                             buildinfo=zsupply.sha256_file(bi) if bi else None, rebuilt=rebuilt,
                             apt_check="--apt-check" in a)
        bad = [r for r in rebuilt if r["sha256"] != m["sha256"]]
        if bad:
            sys.exit("A rebuild does not match this file; it is not released: %s" % bad)
        rec = {"manifest": m}
        rec["digest"] = zsupply.record_digest(rec)
        Path(opt("--out")).write_text(json.dumps(rec, indent=1))
        return print(f"{m['name']} {m['version']} {m['sha256'][:16]} digest {rec['digest'][:16]}: {len(m['files'])} files")
    if cmd == "model":
        import zmodel
        m = zmodel.manifest(a[1], opt("--name"), opt("--version"), opt("--publisher", ""), opt("--source", ""),
                            opt("--licence", ""), int(opt("--max-level", 0)), rings=rings_arg(opt("--rings")))
        if not zsupply.NAME.match(str(m["name"] or "")) or not zsupply.NAME.match(str(m["version"] or "")):
            sys.exit("--name and --version: letters, digits, . _ - only")
        rec = {"manifest": m}
        rec["digest"] = zsupply.record_digest(rec)
        Path(opt("--out")).write_text(json.dumps(rec, indent=1))
        return print(f"model {m['name']} {m['version']} {m['sha256'][:16]}: {len(m['files'])} files, up to L{m['max_level']}")
    if cmd == "model-api":
        import zmodel
        m = zmodel.api_manifest({"kind": opt("--kind"), "model": opt("--model"), "url": opt("--url"),
                                 "version": opt("--version")}, opt("--publisher", ""), int(opt("--max-level", 0)),
                                rings=rings_arg(opt("--rings")))
        rec = {"manifest": m}
        rec["digest"] = zsupply.record_digest(rec)
        Path(opt("--out")).write_text(json.dumps(rec, indent=1))
        return print(f"API model {m['provider']} {m['host']} {m['model']} {m['version']} {m['sha256'][:16]}")
    if cmd == "revoke":
        rec = {"revoke": {"sha256": a[1], "reason": opt("--reason", ""), "t": int(time.time())}}
        rec["digest"] = zsupply.record_digest(rec)
        Path(opt("--out")).write_text(json.dumps(rec, indent=1))
        return print("revocation", rec["digest"][:16])
    if cmd == "sign":
        p = Path(a[1])
        rec = zsupply.sign(json.loads(p.read_text()), load_key(opt("--key")), opt("--by"))
        p.write_text(json.dumps(rec, indent=1))
        return print(f"signed by {opt('--by')}: {len(rec['sigs'])} signature(s)")
    if cmd == "verify":
        rec = json.loads(Path(a[1]).read_text())
        s = zsupply.valid_signers(rec, zsupply.officers(opt("--keys")))
        need = int(opt("--required", 2))
        print(json.dumps({"digest": zsupply.record_digest(rec), "signers": s, "required": need}))
        sys.exit(0 if len(s) >= need else 1)
    if cmd == "publish":
        rec = json.loads(Path(a[1]).read_text())
        if not rec.get("sigs"):
            sys.exit("Not signed by any officer.")
        import zledger
        ev = "release" if "manifest" in rec else "revoke"
        zledger.append(opt("--ledger"), ev, rec["sigs"][0]["by"], "zenos-release", record=rec)
        if opt("--conf"):
            os.environ["ZENOS_AUDIT_CONF"] = opt("--conf")
            import zenos_auditship as S
            c = S.conf()
            state = {}
            S.ship_once(c, S.device_key(), state)
            print(json.dumps(state))
        return print(f"{ev} {rec['digest'][:16]} in the ledger")
    sys.exit(__doc__)


if __name__ == "__main__":
    main()

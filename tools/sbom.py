#!/usr/bin/env python3
"""ZENOS's own software bill of materials, in SPDX 2.3 (JSON) and CycloneDX 1.6 (JSON).

  tools/sbom.py --version 0.2.0 --out build/ [--debs build/zenos_0.2.0_amd64.deb ...]
                [--debian-packages build/iso/....packages] [--name zenos-0.2.0-preview-amd64]

What it lists:
  - the ZENOS packages themselves (the .deb files given, with their SHA-256);
  - the Node.js packages they ship, from the lock files (messenger, storage, the Office apps' bundles; development
    tools left out), with the lock file's integrity hash;
  - binaries ZENOS downloads at build time with a pinned checksum (the LiveKit call server);
  - the Debian packages in the installer image, from live-build's package list, when given.

Each component carries a package URL (purl), so a ministry or company can load the file into its own inventory
and match it against vulnerability information (CISA KEV, NVD, JVN, OSV) with its own tools. The output is
deterministic for the same inputs (sorted, timestamps from SOURCE_DATE_EPOCH when set).
"""
import argparse, base64, hashlib, json, os, re, subprocess, sys, time, uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NPM_TREES = {"messenger": "ZENOS Messages", "storage": "ZENOS storage", "apps/docs": "ZENOS Docs",
             "apps/sheets": "ZENOS Sheets", "apps/slides": "ZENOS Slides"}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def deb_fields(p):
    out = subprocess.run(["dpkg-deb", "-f", str(p), "Package", "Version", "Architecture"], capture_output=True,
                         text=True, check=True).stdout
    return dict(l.split(": ", 1) for l in out.splitlines() if ": " in l)


def npm_components(tree):
    lock = REPO / tree / "package-lock.json"
    if not lock.exists():
        return []
    d = json.loads(lock.read_text())
    out = []
    for path, p in (d.get("packages") or {}).items():
        if not path or p.get("dev") or p.get("link") or "version" not in p:
            continue
        name = p.get("name") or path.split("node_modules/")[-1]
        c = {"type": "npm", "name": name, "version": p["version"], "licence": p.get("license") or "NOASSERTION",
             "purl": f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{p['version']}",
             "used_by": NPM_TREES[tree]}
        integ = p.get("integrity") or ""
        if integ.startswith("sha512-"):
            c["sha512"] = base64.b64decode(integ[7:]).hex()
        out.append(c)
    return out


def pinned_components():
    src = (REPO / "packaging" / "build-deb.sh").read_text()
    ver = re.search(r"^LK_VER=(\S+)", src, re.M).group(1)
    sha = re.search(r"^LK_SHA=([0-9a-f]{64})", src, re.M).group(1)
    return [{"type": "generic", "name": "livekit-server", "version": ver, "licence": "Apache-2.0",
             "purl": f"pkg:github/livekit/livekit@v{ver}", "sha256": sha, "used_by": "ZENOS Messages calls"}]


def debian_components(listing):
    """live-build's .packages file: 'name<TAB>version' per line (name may carry ':arch')"""
    out = []
    for l in Path(listing).read_text().splitlines():
        f = l.split()
        if len(f) < 2:
            continue
        name, arch = (f[0].split(":", 1) + ["amd64"])[:2]
        out.append({"type": "deb", "name": name, "version": f[1], "licence": "NOASSERTION",
                    "purl": f"pkg:deb/debian/{name}@{f[1]}?arch={arch}&distro=trixie", "used_by": "installer image"})
    return out


def build(version, debs, debian_listing=None, name=None):
    comps = []
    for d in debs:
        f = deb_fields(d)
        comps.append({"type": "deb", "name": f["Package"], "version": f["Version"], "licence": "Apache-2.0",
                      "purl": f"pkg:deb/zenos/{f['Package']}@{f['Version']}?arch={f.get('Architecture', 'amd64')}",
                      "sha256": sha256(d), "used_by": "ZENOS", "own": True})
    for t in NPM_TREES:
        comps += npm_components(t)
    comps += pinned_components()
    if debian_listing:
        comps += debian_components(debian_listing)
    merged = {}
    for c in sorted(comps, key=lambda c: (c["purl"], c["used_by"])):
        if c["purl"] in merged:                     # one package used by several parts: one entry naming them all
            m = merged[c["purl"]]
            if c["used_by"] not in m["used_by"].split(", "):
                m["used_by"] += ", " + c["used_by"]
        else:
            merged[c["purl"]] = dict(c)
    return {"name": name or f"zenos-{version}", "version": version, "components": list(merged.values())}


def when():
    t = int(os.environ.get("SOURCE_DATE_EPOCH") or time.time())
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def spdx(b):
    ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://zenos-os.org/sbom/" + b["name"])
    root = {"SPDXID": "SPDXRef-ZENOS", "name": "ZENOS", "versionInfo": b["version"],
            "downloadLocation": "https://github.com/zenos-org/zenos/releases", "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Apache-2.0", "copyrightText": "NOASSERTION", "supplier": "Organization: The ZENOS Authors",
            "primaryPackagePurpose": "OPERATING-SYSTEM"}
    pkgs, rels = [root], [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": "SPDXRef-ZENOS"}]
    for i, c in enumerate(b["components"]):
        sid = f"SPDXRef-{i}-{re.sub(r'[^A-Za-z0-9.-]', '-', c['name'])[:60]}"
        p = {"SPDXID": sid, "name": c["name"], "versionInfo": c["version"], "downloadLocation": "NOASSERTION",
             "licenseConcluded": "NOASSERTION", "licenseDeclared": c["licence"] if re.fullmatch(r"[A-Za-z0-9.+-]+(?: (?:OR|AND) [A-Za-z0-9.+-]+)*", str(c["licence"])) else "NOASSERTION",
             "copyrightText": "NOASSERTION", "supplier": "Organization: The ZENOS Authors" if c.get("own") else "NOASSERTION",
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c["purl"]}],
             "comment": "used by: " + c["used_by"]}
        sums = [{"algorithm": a.upper(), "checksumValue": c[a]} for a in ("sha256", "sha512") if c.get(a)]
        if sums:
            p["checksums"] = sums
        pkgs.append(p)
        rels.append({"spdxElementId": "SPDXRef-ZENOS", "relationshipType": "CONTAINS", "relatedSpdxElement": sid})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": b["name"],
            "documentNamespace": f"https://zenos-os.org/spdx/{b['name']}-{ns}",
            "creationInfo": {"created": when(), "creators": ["Organization: The ZENOS Authors", "Tool: zenos-sbom"]},
            "packages": pkgs, "relationships": rels}


def cyclonedx(b):
    comps = []
    for c in b["components"]:
        x = {"type": "application" if c.get("own") else "library", "bom-ref": c["purl"], "name": c["name"],
             "version": c["version"], "purl": c["purl"], "properties": [{"name": "zenos:used-by", "value": c["used_by"]}]}
        if c["licence"] != "NOASSERTION":
            x["licenses"] = [{"expression": c["licence"]}]
        hs = [{"alg": a.replace("sha", "SHA-"), "content": c[a]} for a in ("sha256", "sha512") if c.get(a)]
        if hs:
            x["hashes"] = hs
        comps.append(x)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "https://zenos-os.org/cdx/" + b["name"])),
            "version": 1, "metadata": {"timestamp": when(), "tools": {"components": [{"type": "application", "name": "zenos-sbom"}]},
                                       "component": {"type": "operating-system", "name": "ZENOS", "version": b["version"],
                                                     "bom-ref": "zenos@" + b["version"]}},
            "components": comps}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", default=".")
    ap.add_argument("--debs", nargs="*", default=[])
    ap.add_argument("--debian-packages")
    ap.add_argument("--name")
    ap.add_argument("--npm-inventory", help="write only the shipped Node.js packages (for zenos-vulnwatch) to this file")
    a = ap.parse_args()
    if a.npm_inventory:
        comps = [{"name": c["name"], "version": c["version"], "used_by": c["used_by"]}
                 for c in build(a.version, []).get("components") if c["type"] == "npm"]
        Path(a.npm_inventory).write_text(json.dumps({"version": a.version, "components": comps}, indent=0) + "\n")
        print(a.npm_inventory, len(comps), "packages")
        return
    b = build(a.version, a.debs, a.debian_packages, a.name)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for ext, doc in ((".spdx.json", spdx(b)), (".cdx.json", cyclonedx(b))):
        p = out / (b["name"] + ext)
        p.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
        print(p, sha256(p), f"{len(b['components'])} components")


if __name__ == "__main__":
    main()

"""Vulnerability information from outside, as data, matched against the PC's own parts.

Sources (only these official places; their hosts are added to the system accounts' allowed destinations):
  kev       CISA Known Exploited Vulnerabilities catalogue (JSON)       which vulnerabilities are being exploited
  debian    Debian security tracker (JSON)                              which Debian source package is affected,
                                                                        fixed in which version, reachable remotely
  nvd       NIST NVD API 2.0, one query per vulnerability that matters  CVSS score and attack vector
  jvn       JVN iPedia (MyJVN API, XML)                                 Japanese advisories: CVE and CVSS
  spdx      SPDX inventories published by national CERTs (now NCSC-NL's PHP list)   product names per CVE
  zerowire  Cloudflare Zero Wire                                        CVE identifiers only; off until a
                                                                        machine-readable feed is confirmed
  osv       OSV, as bulk downloads (the whole npm and Debian lists)     the Node.js packages ZENOS ships
            The lists are downloaded whole, never queried: OSV's query service would learn which packages and
            versions this PC runs; a download tells it only that someone fetched the list.
Settings: /etc/zenos/vuln.json {"sources": {"kev": true, ...}, "urls": {...}, "every": 21600}

Data only. From every source ZENOS keeps identifiers (CVE-yyyy-n), package and product names, versions, scores
and dates that match strict patterns, and drops everything else: descriptions, advice, and the prompts some
sources write for AI agents. Nothing a source writes is passed to an AI agent or decides anything; what is done
is decided by zenos-decide "vuln" (formal/ZenosFormal/Vuln.lean) from those facts alone.
"""
import json, re, subprocess, time, urllib.request
from pathlib import Path

CONF = Path("/etc/zenos/vuln.json")
URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "debian": "https://security-tracker.debian.org/tracker/data/json",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
    "jvn": "https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&rangeDatePublished=m&rangeDateFirstPublished=m",
    "spdx": "https://api.github.com/repos/NCSC-NL/php2shell/contents/software/spdx",
    "zerowire": None,
    "osv": "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
}
DEFAULT_ON = {"kev": True, "debian": True, "nvd": True, "jvn": True, "spdx": True, "zerowire": False, "osv": True}
NPM_INVENTORY = Path("/usr/share/zenos/npm-inventory.json")

CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CVE_IN = re.compile(r"CVE-\d{4}-\d{4,7}")
NAME = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,99}$")
VERSION = re.compile(r"^[A-Za-z0-9.+~:_-]{1,80}$")
PRODUCT = re.compile(r"^[A-Za-z0-9 ._+/()-]{1,80}$")
RELEASE = "trixie"
# What is counted as affected (and turns the System Monitor amber) is what someone can act on: a vulnerability
# known to be exploited (KEV), or one Debian has fixed while the PC still runs an older version. Debian's tracker
# also lists thousands of open issues with no fix in the archive, most not yet triaged ("not yet assigned"), judged
# not worth a fix in a stable release ("unimportant", "no DSA"), or past support ("end-of-life"). Those are kept
# as "open" (counted apart, shown on request), unless they are known to be exploited.
MINOR = {"unimportant", "end-of-life"}


def conf():
    try:
        c = json.loads(CONF.read_text())
    except (OSError, ValueError):
        c = {}
    on = dict(DEFAULT_ON, **(c.get("sources") or {}))
    urls = dict(URLS, **(c.get("urls") or {}))
    return {"on": {k: bool(v) and bool(urls.get(k)) for k, v in on.items()}, "urls": urls,
            "every": int(c.get("every", 21600))}


def hosts(c=None):
    """the hosts the enabled sources live on (for the network sentinel's list of allowed destinations)"""
    from urllib.parse import urlparse
    c = c or conf()
    out = {urlparse(u.replace("{ecosystem}", "x")).hostname for k, u in c["urls"].items() if c["on"].get(k) and u}
    if c["on"].get("spdx"):
        out.add("raw.githubusercontent.com")
    return {h for h in out if h}


def fetch_to(url, path, timeout=120, limit=600 * 1024 * 1024):
    """a large download straight to a file (OSV's lists), never whole in memory"""
    req = urllib.request.Request(url, headers={"User-Agent": "zenos-vulnwatch"})
    n = 0
    with urllib.request.urlopen(req, timeout=timeout) as r, open(path, "wb") as f:
        for b in iter(lambda: r.read(1 << 20), b""):
            n += len(b)
            if n > limit:
                raise ValueError("download too large")
            f.write(b)
    return path


def fetch(url, timeout=60, limit=200 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": "zenos-vulnwatch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("answer too large")
    return data


# ---------------------------------------------------------------- parsers: bytes in, plain facts out
def _cve(s):
    s = str(s or "").strip().upper()
    return s if CVE.match(s) else None


def _name(s):
    s = str(s or "").strip().lower()
    return s if NAME.match(s) else None


def _version(s):
    s = str(s or "").strip()
    return s if VERSION.match(s) else None


def _product(s):
    s = str(s or "").strip()
    return s if PRODUCT.match(s) else None


def parse_kev(data):
    """{cve: {"kev": True, "products": [...], "added": date}}"""
    out = {}
    for v in (json.loads(data).get("vulnerabilities") or []):
        c = _cve(v.get("cveID"))
        if not c:
            continue
        prods = [p for p in (_product(v.get("vendorProject")), _product(v.get("product"))) if p]
        added = str(v.get("dateAdded", ""))[:10]
        out[c] = {"kev": True, "products": prods, "added": added if re.match(r"^\d{4}-\d{2}-\d{2}$", added) else None}
    return out


def parse_debian(data, release=RELEASE):
    """{source package: {cve: {"status": "fixed"|"open"|"not-affected", "fixed": version|None, "remote": bool|None}}}"""
    out = {}
    for pkg, cves in (json.loads(data) or {}).items():
        p = _name(pkg)
        if not p or not isinstance(cves, dict):
            continue
        for cid, info in cves.items():
            c = _cve(cid)
            if not c or not isinstance(info, dict):
                continue
            r = (info.get("releases") or {}).get(release)
            if not isinstance(r, dict):
                continue
            st, fixed = r.get("status"), _version(r.get("fixed_version"))
            if st == "resolved":
                status = "not-affected" if fixed == "0" else "fixed"
            elif st == "open":
                status = "open"
            else:
                continue                                        # "undetermined": nothing to act on yet
            scope = info.get("scope")
            urg = str(r.get("urgency") or "")
            out.setdefault(p, {})[c] = {"status": status, "fixed": None if fixed == "0" else fixed,
                                        "remote": True if scope == "remote" else (False if scope == "local" else None),
                                        "minor": urg in MINOR or bool(r.get("nodsa"))}
    return out


def parse_nvd(data):
    """{cve: {"score": tenths, "remote": bool}}"""
    out = {}
    for v in (json.loads(data).get("vulnerabilities") or []):
        cve = v.get("cve") or {}
        c = _cve(cve.get("id"))
        if not c:
            continue
        m = cve.get("metrics") or {}
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if m.get(k):
                d = (m[k][0] or {}).get("cvssData") or {}
                try:
                    score = int(round(float(d.get("baseScore")) * 10))
                except (TypeError, ValueError):
                    continue
                out[c] = {"score": max(0, min(100, score)), "remote": d.get("attackVector") == "NETWORK"}
                break
    return out


def parse_jvn(data):
    """{cve: {"score": tenths}} from MyJVN's overview list (XML; only CVE ids and CVSS scores are read)"""
    import xml.etree.ElementTree as ET
    out = {}
    root = ET.fromstring(data)
    for item in root.iter():
        if not item.tag.endswith("item"):
            continue
        cves, score = set(), None
        for e in item.iter():
            if e.tag.endswith("references") and e.get("source") == "CVE":
                c = _cve(e.get("id") or e.text)
                if c:
                    cves.add(c)
            if e.tag.endswith("cvss") and e.get("score"):
                try:
                    score = max(score or 0, int(round(float(e.get("score")) * 10)))
                except ValueError:
                    pass
        for c in cves:
            if score is not None:
                out[c] = {"score": max(0, min(100, score))}
    return out


def parse_spdx(data):
    """{cve: {"products": [...]}} from an SPDX JSON inventory: products named there, with the CVEs the document names"""
    d = json.loads(data)
    prods = []
    for p in d.get("packages") or []:
        n = _product(p.get("name"))
        if n:
            prods.append(n)
    cves = set()
    for c in CVE_IN.findall(json.dumps(d.get("annotations") or []) + json.dumps(d.get("comment") or "")
                            + str(d.get("name") or "")):
        if _cve(c):
            cves.add(c)
    return {c: {"products": prods} for c in cves}


def parse_feed(data):
    """an RSS or Atom feed (Zero Wire): the CVE identifiers in item titles and links, nothing else"""
    import xml.etree.ElementTree as ET
    out = {}
    for item in ET.fromstring(data).iter():
        if item.tag.split("}")[-1] not in ("item", "entry"):
            continue
        txt = " ".join((e.text or "") + " " + (e.get("href") or "") for e in item
                       if e.tag.split("}")[-1] in ("title", "link"))
        for c in CVE_IN.findall(txt):
            out[c] = {"listed_by": "zerowire"}
    return out


def _semver(v):
    """a comparable key for npm versions (1.2.3, 1.2.3-rc.1); None when the version is not one"""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", str(v or ""))
    if not m:
        return None
    pre = m.group(4)
    pk = (1,) if pre is None else (0,) + tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split("."))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) + pk


def parse_osv_zip(path, wanted):
    """{(package, version): [{"cve", "fixed", "open"}]} for the npm packages in `wanted` ({name: {versions}}), from
    OSV's npm list. Only package names, version ranges and CVE aliases are read; malicious-package entries (MAL-)
    are matched too, since a package known to be malware is the worst case."""
    import zipfile
    out = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if not info.filename.endswith(".json") or info.file_size > 4 * 1024 * 1024:
                continue
            try:
                v = json.loads(z.read(info))
            except ValueError:
                continue
            ids = [x for x in [v.get("id")] + list(v.get("aliases") or []) if isinstance(x, str)]
            cves = [c for c in (_cve(x) for x in ids) if c]
            mal = any(str(x).startswith("MAL-") for x in ids)
            if not cves and not mal:
                continue
            key = cves[0] if cves else str(v.get("id"))[:40]
            for a in v.get("affected") or []:
                pkg = (a.get("package") or {})
                name = str(pkg.get("name") or "")
                if pkg.get("ecosystem") != "npm" or name not in wanted:
                    continue
                for ver in wanted[name]:
                    hit, fixed = _in_ranges(ver, a)
                    if hit:
                        out.setdefault((name, ver), []).append({"cve": key, "fixed": fixed, "malicious": mal})
    return out


def _in_ranges(ver, a):
    """(affected?, a fixed version) for one npm version against one OSV "affected" entry"""
    if ver in (a.get("versions") or []):
        return True, None
    k = _semver(ver)
    if k is None:
        return False, None
    for r in a.get("ranges") or []:
        if r.get("type") != "SEMVER":
            continue
        intro, fixed, last = None, None, None
        for e in r.get("events") or []:
            if "introduced" in e:
                intro = (0,) if e["introduced"] == "0" else _semver(e["introduced"])
            if "fixed" in e:
                fixed = e["fixed"]
            if "last_affected" in e:
                last = _semver(e["last_affected"])
        if intro is None:
            continue
        fk = _semver(fixed) if fixed else None
        if k >= intro and (fk is None or k < fk) and (last is None or k <= last):
            return True, fixed if fk else None
    return False, None


def npm_inventory(path=None):
    """{name: {versions}} of the Node.js packages ZENOS ships (written at build time from the lock files)"""
    try:
        d = json.loads(Path(path or NPM_INVENTORY).read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    for c in d.get("components") or []:
        n, v = str(c.get("name", "")), str(c.get("version", ""))
        if n and VERSION.match(v):
            out.setdefault(n, set()).add(v)
    return out


def match_npm(hits, kev, scores, mitigations=None, signers=None, required=2, decide=None):
    """findings for the shipped Node.js packages, from parse_osv_zip's result"""
    import zdecide
    decide = decide or zdecide.ask
    out = []
    for (name, ver), vulns in hits.items():
        for h in vulns:
            c = h["cve"]
            sc = scores.get(c) or {}
            facts = {"op": "vuln", "listed": True, "fixed_installed": False, "mitigated": c in (mitigations or {}),
                     "kev": c in kev, "score": int(sc.get("score") or (100 if h["malicious"] else 0)),
                     "remote": bool(sc.get("remote")), "signatures": int((signers or {}).get(c, 0)),
                     "required": int(required)}
            r = decide(facts)
            out.append({"cve": c, "package": "npm:" + name, "installed": ver, "fixed": h["fixed"],
                        "fix_available": bool(h["fixed"]), "kev": c in kev, "score": facts["score"],
                        "remote": facts["remote"], "status": r["status"], "priority": int(r["priority"]),
                        "may_mitigate": bool(r["may_mitigate"]),
                        "minor": not (c in kev or h["fixed"] or h["malicious"]), "binaries": []})
    return out


# ---------------------------------------------------------------- the PC's parts
def installed():
    """{source package: (source version, [binary packages])} as dpkg has them"""
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f", "${source:Package}\t${source:Version}\t${Package}\t${db:Status-Status}\n"],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    inv = {}
    for l in out.splitlines():
        f = l.split("\t")
        if len(f) == 4 and f[3] == "installed":
            s = inv.setdefault(f[0], [f[1], []])
            s[1].append(f[2])
    return {k: (v[0], v[1]) for k, v in inv.items()}


def version_ge(a, b):
    try:
        return subprocess.run(["dpkg", "--compare-versions", a, "ge", b], timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ---------------------------------------------------------------- matching and deciding
def match(debian, kev, scores, inv, mitigations=None, signers=None, required=2, ge=version_ge, decide=None):
    """findings for the parts on this PC, most urgent first. `mitigations`: {cve: mitigation id in force};
    `signers`: {mitigation id: number of officers' valid signatures} for mitigations offered but not applied."""
    import zdecide
    decide = decide or zdecide.ask
    mitigations, signers = mitigations or {}, signers or {}
    out = []
    for src, cves in debian.items():
        if src not in inv:
            continue
        ver, bins = inv[src]
        if not debian_build(ver):
            continue                    # the same name, built elsewhere (NodeSource's nodejs): Debian's entry is not about it
        for c, d in cves.items():
            if d["status"] == "not-affected":
                continue
            fixed_installed = bool(d["fixed"]) and ge(ver, d["fixed"])
            sc = scores.get(c) or {}
            remote = d["remote"] if d["remote"] is not None else bool(sc.get("remote"))
            facts = {"op": "vuln", "listed": True, "fixed_installed": fixed_installed, "mitigated": c in mitigations,
                     "kev": c in kev, "score": int(sc.get("score") or 0), "remote": bool(remote),
                     "signatures": int(signers.get(c, 0)), "required": int(required)}
            r = decide(facts)
            out.append({"cve": c, "package": src, "installed": ver, "fixed": d["fixed"],
                        "fix_available": bool(d["fixed"]) and not fixed_installed, "kev": c in kev,
                        "score": facts["score"], "remote": facts["remote"], "status": r["status"],
                        "priority": int(r["priority"]), "may_mitigate": bool(r["may_mitigate"]),
                        "minor": c not in kev and (d["status"] == "open" or bool(d.get("minor"))),
                        "binaries": sorted(bins)[:20]})
    out.sort(key=lambda f: (-f["priority"], f["cve"], f["package"]))
    return out


def debian_build(version):
    """a version Debian's own archive builds (other builders mark theirs: NodeSource's "nodesource1", ZENOS's own)"""
    return not any(x in version for x in ("nodesource", "zenos"))


def summary(findings):
    s = {"affected": 0, "fixed": 0, "mitigated": 0, "kev_affected": 0, "minor": 0}
    for f in findings:
        if f["status"] == "affected" and f.get("minor"):
            s["minor"] += 1
        elif f["status"] in s:
            s[f["status"]] += 1
        if f["status"] == "affected" and f["kev"]:
            s["kev_affected"] += 1
    return s

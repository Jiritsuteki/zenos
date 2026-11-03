#!/usr/bin/env python3
"""Find public Word, Excel and PowerPoint files on government and municipal pages, download them and add them to
corpus.json (URL, the page it was published on, SHA-256, size, date). Run it rarely and by hand; the tests use
corpus.json and fetch.py, never this crawler.

  crawl.py SEEDS.txt OUT_DIR [--per-host 40] [--total 600] [--depth 2] [--only pptx,ppt]

SEEDS.txt: one page URL per line (a page that lists forms). Only links on the same host as the seed are followed,
only hosts ending in .go.jp or .lg.jp (or listed in SEEDS.txt itself) are visited, at most one request every
second per host, files above 20 MB are skipped, and a file whose content is already in the corpus is not added again.
"""
import hashlib, html, json, re, sys, time, urllib.parse, urllib.request
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXT = ("doc", "docx", "xls", "xlsx", "ppt", "pptx")
UA = {"User-Agent": "ZENOS-compat-tests/0.1 (+https://zenos-os.org; hello@zenos-os.org)"}
MAX = 20 * 1024 * 1024
HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.I)


def arg(name, d):
    a = sys.argv
    return int(a[a.index(name) + 1]) if name in a else d


def get(url, last, limit=MAX):
    host = urllib.parse.urlsplit(url).hostname
    wait = 1.0 - (time.time() - last[host])
    if wait > 0:
        time.sleep(wait)
    last[host] = time.time()
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=45) as r:
        n = int(r.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("too large")
        b = r.read(limit + 1)
        if len(b) > limit:
            raise ValueError("too large")
        return b, r.headers.get_content_type()


def ext_of(url):
    p = urllib.parse.urlsplit(url).path.lower()
    e = p.rsplit(".", 1)[-1] if "." in p.rsplit("/", 1)[-1] else ""
    return e if e in EXT else None


def main():
    seeds = [l.strip() for l in Path(sys.argv[1]).read_text().splitlines() if l.strip() and not l.startswith("#")]
    out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
    per_host, total, depth = arg("--per-host", 40), arg("--total", 600), arg("--depth", 2)
    only = set(sys.argv[sys.argv.index("--only") + 1].split(",")) if "--only" in sys.argv else set(EXT)
    cpath = HERE / "corpus.json"
    corpus = json.loads(cpath.read_text())
    have = {m["sha256"] for m in corpus}
    seen_url = {m["url"] for m in corpus}
    count = Counter(urllib.parse.urlsplit(m["url"]).hostname for m in corpus
                    if "--only" not in sys.argv or m["file"].rsplit(".", 1)[-1] in set(sys.argv[sys.argv.index("--only") + 1].split(",")))
    allowed = {urllib.parse.urlsplit(s).hostname for s in seeds}
    last = defaultdict(float)
    added = 0
    for seed in seeds:
        host = urllib.parse.urlsplit(seed).hostname
        if not (host.endswith(".go.jp") or host.endswith(".lg.jp") or host in allowed):
            continue
        queue, visited, pages = [(seed, 0)], set(), 0
        while queue and count[host] < per_host and added < total and pages < 150:
            page, d = queue.pop(0)
            if page in visited:
                continue
            visited.add(page)
            try:
                body, ctype = get(page, last, 4 * 1024 * 1024)
            except Exception as e:
                print("page unavailable:", page, e, flush=True); continue
            pages += 1
            if ctype not in ("text/html", "application/xhtml+xml"):
                continue
            text = body.decode("utf-8", "replace")
            for href in HREF.findall(text):
                u = urllib.parse.urljoin(page, html.unescape(href.strip()))
                if urllib.parse.urlsplit(u).hostname != host or not u.startswith("http"):
                    continue
                e = ext_of(u)
                if e and e not in only:
                    continue
                if e:
                    if u in seen_url or count[host] >= per_host or added >= total:
                        continue
                    seen_url.add(u)
                    try:
                        b, _ = get(u, last)
                    except Exception as ex:
                        print("file unavailable:", u, ex, flush=True); continue
                    h = hashlib.sha256(b).hexdigest()
                    if h in have or len(b) < 512:
                        continue
                    have.add(h)
                    name = h[:12] + "." + e
                    (out / name).write_bytes(b)
                    corpus.append({"file": name, "url": u, "page": page, "sha256": h, "bytes": len(b),
                                   "fetched": time.strftime("%Y-%m-%d")})
                    count[host] += 1; added += 1
                    print("added", name, u, flush=True)
                elif d < depth and u.rstrip("/").lower().endswith((".html", ".htm", "/")) and u not in visited:
                    queue.append((u, d + 1))
        cpath.write_text(json.dumps(corpus, ensure_ascii=False, indent=1) + "\n")
    print(f"added {added}; corpus now {len(corpus)}:",
          dict(Counter(m['file'].rsplit('.', 1)[1] for m in corpus)), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Office compatibility check: open each public file and save it again with an engine, then compare the saved file
with the original. Nothing here is a model or a guess: counts of what is in the files, text, cell values and
formulas, and pictures of the pages.

  compat.py CORPUS_DIR OUT_DIR [--engines zenos,zapps,libreoffice] [--limit N] [--jobs N] [--gate BASELINE.json]

Engines:
  zenos        the ZENOS office engine (system/lib/zoffice.py): LibreOffice in the ZENOS sandbox, no network, the file
               only in memory, locked-down profile (no macros, no autosave, no update check)
  zapps        the ZENOS apps' own open/save code before the engine (apps/docs, apps/sheets, apps/slides), run by
               engines/zapps.bundle.mjs
  libreoffice  LibreOffice as installed (soffice --headless --convert-to), the same file type in and out

Measures, original against saved:
  text         how much of the text survives (character pairs in common, 0..1)
  features     each kind of element counted in both files: tables, pictures, vertical text, ruby, distributed
               alignment, headers and footers (Word); merged cells, column widths, borders, print areas, page
               breaks, conditional formats, input rules, charts, formulas, macros (Excel); slides, pictures,
               charts, tables (PowerPoint)
  cells        Excel: values and formulas of every non-empty cell, the same
  pages        both files drawn by LibreOffice into page images: page counts and how much of the ink of each lands
               where the other has ink, within one pixel at 30 dpi (0..1).
               The drawing is LibreOffice's, not Microsoft Office's: Microsoft Office itself is not used here.
Results: OUT_DIR/results.json and OUT_DIR/results.md.
"""
import json, os, re, shutil, subprocess, sys, tempfile, zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "system" / "lib"))
ZAPPS = HERE / "engines" / "zapps.bundle.mjs"

FEATURES = {
    "docx": {"tables": [r"<w:tbl>"], "pictures": [r"<w:drawing>", r"<v:imagedata"],
             "vertical text": [r"<w:textDirection w:val=\"(tbRl|tbRlV|btLr|tbLrV)\""], "ruby": [r"<w:ruby>"],
             "distributed": [r"<w:jc w:val=\"distribute\""],
             "headers/footers": ["@parts:word/(header|footer)\\d*\\.xml"]},
    "xlsx": {"merged cells": [r"<mergeCell "], "column widths": [r"<col "], "borders": ["@borders"],
             "print areas": [r"_xlnm\.Print_Area"], "page breaks": [r"<brk "],
             "conditional formats": [r"<conditionalFormatting"], "input rules": [r"<dataValidation "],
             "charts": ["@parts:xl/charts/chart\\d+\\.xml"], "formulas": [r"<f[ >]"],
             "macros": ["@parts:xl/vbaProject\\.bin"], "pictures": ["@parts:xl/media/"]},
    "pptx": {"slides": ["@parts:ppt/slides/slide\\d+\\.xml"], "pictures": [r"<p:pic>"],
             "charts": ["@parts:ppt/charts/chart\\d+\\.xml"], "tables": [r"<a:tbl>"]},
}
TEXT_PARTS = {"docx": r"word/(document|header\d*|footer\d*)\.xml", "xlsx": r"xl/(sharedStrings|worksheets/sheet\d+)\.xml",
              "pptx": r"ppt/slides/slide\d+\.xml"}
TEXT_TAGS = {"docx": r"<w:t[^>]*>([^<]*)</w:t>", "xlsx": r"<(?:t|v)[^>]*>([^<]*)</(?:t|v)>", "pptx": r"<a:t>([^<]*)</a:t>"}


LEGACY = ("doc", "xls", "ppt")          # the older binary formats: still most of what public offices publish


def kind(p):
    e = p.suffix.lower().lstrip(".")
    return {"docm": "docx", "xlsm": "xlsx", "pptm": "pptx"}.get(e, e)


def parts(path):
    try:
        with zipfile.ZipFile(path) as z:
            return {n: z.read(n) for n in z.namelist()}
    except (zipfile.BadZipFile, OSError):
        return None


def count(pp, k):
    out = {}
    xml = {n: v.decode("utf-8", "replace") for n, v in pp.items() if n.endswith(".xml") or n.endswith(".rels")}
    for name, pats in FEATURES[k].items():
        n = 0
        for pat in pats:
            if pat.startswith("@parts:"):
                n += sum(1 for p in pp if re.match(pat[7:], p))
            elif pat == "@borders":
                st = xml.get("xl/styles.xml", "")
                n += len(re.findall(r"<(left|right|top|bottom) style=", st))
            else:
                n += sum(len(re.findall(pat, v)) for v in xml.values())
        out[name] = n
    return out


def text(pp, k):
    s = []
    for n in sorted(pp):
        if re.fullmatch(TEXT_PARTS[k], n):
            s += re.findall(TEXT_TAGS[k], pp[n].decode("utf-8", "replace"))
    return re.sub(r"\s+", "", "".join(s))


def text_kept(a, b):
    if not a:
        return None
    ca, cb = Counter(a[i:i + 2] for i in range(len(a) - 1)), Counter(b[i:i + 2] for i in range(len(b) - 1))
    if not ca:
        return 1.0 if a in b else 0.0
    return round(sum((ca & cb).values()) / sum(ca.values()), 3)


def xlsx_structure(path, bounds=None):
    """what a person sees in a workbook, counted cell by cell (style tables are written differently by every
    program, so their entries are not counted)"""
    import openpyxl
    wb = openpyxl.load_workbook(path)
    bounds = bounds or {ws.title: (ws.max_column, ws.max_row) for ws in wb.worksheets}
    out = {"_bounds": bounds, "_cells": {}, "merged cells": 0, "borders": 0, "column widths": 0, "print areas": 0, "page breaks": 0,
           "conditional formats": 0, "input rules": 0, "formulas": 0, "number formats": 0, "fonts": 0, "fills": 0}
    for ws in wb.worksheets:
        bc, br = bounds.get(ws.title, (ws.max_column, ws.max_row))
        out["merged cells"] += len(ws.merged_cells.ranges)
        # column by column inside the used area: programs merge neighbouring columns of the same width into one entry
        widths = []
        for d in ws.column_dimensions.values():
            if d.width and d.min and d.max:
                widths.append((d.min, min(d.max, bc), round(d.width, 1)))
        out["_widths"] = out.get("_widths", {})
        for lo, hi, w in widths:
            for i in range(lo, hi + 1):
                out["_widths"][(ws.title, i)] = w
        out["print areas"] += 1 if ws.print_area else 0
        out["page breaks"] += len(ws.row_breaks.brk) + len(ws.col_breaks.brk)
        # rules count by the cells they cover: programs merge identical rules into one range on saving
        # only cells inside the sheet's used area: rules copied far below it (row 65,000 and beyond, left by old
        # conversions) cannot be seen and are dropped by some programs
        out["conditional formats"] += sum(_cells_in(cf.sqref, bc, br) * len(cf.rules) for cf in ws.conditional_formatting)
        out["input rules"] += sum(_cells_in(d.sqref, bc, br) for d in ws.data_validations.dataValidation)
        for row in ws.iter_rows(max_row=br, max_col=bc):
            for c in row:
                key = (ws.title, c.coordinate)
                b = c.border
                if any(getattr(b, k) is not None and getattr(b, k).style for k in ("left", "right", "top", "bottom")):
                    out["_cells"].setdefault("borders", set()).add(key)
                if c.data_type == "f":
                    out["formulas"] += 1
                if c.value is not None and c.number_format not in ("General",):
                    out["_cells"].setdefault("number formats", set()).add(key)
                if c.value is not None and c.font is not None and (c.font.b or c.font.i or (c.font.sz and c.font.sz != 11)):
                    out["_cells"].setdefault("fonts", set()).add(key)
                if c.fill is not None and c.fill.fill_type and not _white(c.fill):
                    out["_cells"].setdefault("fills", set()).add(key)
    return out


def _cells_in(sqref, max_col=16384, max_row=1048576):
    from openpyxl.utils.cell import range_boundaries
    n = 0
    for r in str(sqref).split():
        try:
            c1, r1, c2, r2 = range_boundaries(r)
        except Exception:
            continue
        c2, r2 = min(c2, max_col), min(r2, max_row)
        if c2 >= c1 and r2 >= r1:
            n += (c2 - c1 + 1) * (r2 - r1 + 1)
    return n


def _white(fill):
    """a white fill looks like no fill: programs drop it on saving"""
    try:
        c = fill.fgColor
        if c.type == "theme" and c.theme == 0 and not c.tint:
            return True
        if c.type == "rgb" and str(c.rgb).upper() in ("FFFFFFFF", "00FFFFFF"):
            return True
        if c.type == "indexed" and c.indexed in (1, 9):          # white in the old Excel palette
            return True
    except Exception:
        pass
    return False


def header_footer_text(pp):
    """the text of the headers and footers Word shows: a section's default ones, its first-page ones only when the
    section has a title page, the even-page ones only when the document uses them. Digits are left out (page
    numbers are field results, written again by every program)."""
    doc = pp.get("word/document.xml", b"").decode("utf-8", "replace")
    rels = pp.get("word/_rels/document.xml.rels", b"").decode("utf-8", "replace")
    settings = pp.get("word/settings.xml", b"").decode("utf-8", "replace")
    target = dict(re.findall(r'Id="([^"]+)"[^>]*Target="([^"]+)"', rels))
    target.update({k: v for v, k in re.findall(r'Target="([^"]+)"[^>]*Id="([^"]+)"', rels)})
    even = "<w:evenAndOddHeaders" in settings
    shown = []
    for sect in re.findall(r"<w:sectPr\b.*?</w:sectPr>", doc, re.S):
        title = "<w:titlePg" in sect and 'w:titlePg w:val="0"' not in sect and 'w:titlePg w:val="false"' not in sect
        for kind, typ, rid in re.findall(r'<w:(header|footer)Reference w:type="(\w+)" r:id="([^"]+)"', sect):
            if typ == "default" or (typ == "first" and title) or (typ == "even" and even):
                shown.append("word/" + target.get(rid, "").lstrip("/").replace("word/", ""))
    s = []
    for n in shown:
        if n in pp:
            s += re.findall(r"<w:t[^>]*>([^<]*)</w:t>", pp[n].decode("utf-8", "replace"))
    return re.sub(r"[\s0-9０-９]+", "", "".join(s))


def cells(orig, saved):
    try:
        import openpyxl
        wa, wb = openpyxl.load_workbook(orig), openpyxl.load_workbook(saved)
    except Exception:
        return None
    total = same = 0
    for i, sa in enumerate(wa.worksheets):
        sb = wb.worksheets[i] if i < len(wb.worksheets) else None
        for row in sa.iter_rows():
            for c in row:
                if c.value is None:
                    continue
                total += 1
                v = sb[c.coordinate].value if sb is not None else None
                if str(v).lstrip("=") == str(c.value).lstrip("=") or (isinstance(v, (int, float)) and isinstance(c.value, (int, float)) and abs(v - c.value) < 1e-9):
                    same += 1
    return {"cells": total, "same": same, "kept": round(same / total, 3) if total else None}


PROFILE = None


def soffice(args, timeout=180):
    global PROFILE
    exe = shutil.which("soffice") or shutil.which("libreoffice")
    prof = PROFILE = PROFILE or tempfile.mkdtemp(prefix="lo-")         # one profile: starting is much faster
    p = subprocess.Popen([exe, f"-env:UserInstallation=file://{prof}", "--headless", "--norestore"] + args,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, 9)            # soffice.bin too: a hung one would hold the profile and block every later file
        p.communicate()
        raise
    return subprocess.CompletedProcess(p.args, p.returncode, out, err)


def to_pdf(src, outdir):
    try:
        soffice(["--convert-to", "pdf", "--outdir", str(outdir), str(src)])
    except subprocess.TimeoutExpired:
        return None
    p = Path(outdir) / (Path(src).stem + ".pdf")
    return p if p.exists() else None


def pages(pdf, outdir, tag):
    subprocess.run(["pdftoppm", "-r", "30", "-gray", "-png", str(pdf), str(Path(outdir) / tag)], capture_output=True, timeout=300)
    return sorted(Path(outdir).glob(tag + "-*.png"))


def page_similarity(a, b):
    """how much of the ink of each page lands where the other page has ink, allowing one pixel at 30 dpi
    (under a millimetre): (ink of A near ink of B + ink of B near ink of A) / (ink of A + ink of B), 0..1.
    A page missing on one side counts 0."""
    from PIL import Image, ImageFilter
    import numpy as np
    n = max(len(a), len(b))
    if n == 0:
        return None
    s = 0.0
    for i in range(min(len(a), len(b))):
        ia, ib = Image.open(a[i]).convert("L"), Image.open(b[i]).convert("L")
        ib = ib.resize(ia.size)
        ka, kb = np.asarray(ia) < 200, np.asarray(ib) < 200          # the ink, not the white paper
        da = np.asarray(ia.filter(ImageFilter.MinFilter(3))) < 200    # ink grown by one pixel
        db = np.asarray(ib.filter(ImageFilter.MinFilter(3))) < 200
        tot = ka.sum() + kb.sum()
        s += 1.0 if tot == 0 else float((ka & db).sum() + (kb & da).sum()) / float(tot)
    return round(s / n, 3)


def run_engine(engine, src, out):
    if engine == "zenos":
        import zoffice
        k = kind(src) if kind(src) in ("doc", "xls", "ppt") else src.suffix.lower().lstrip(".")
        dst = {"docm": "docx", "xlsm": "xlsx", "pptm": "pptx"}.get(k, k)
        try:
            out.write_bytes(zoffice.convert(src.read_bytes(), src.suffix.lower().lstrip("."), dst))
            return True, ""
        except zoffice.Failed as e:
            return False, str(e)
    if engine == "zapps":
        r = subprocess.run(["node", str(ZAPPS), str(src), str(out)], capture_output=True, text=True, timeout=180)
        return out.exists() and r.returncode == 0, r.stderr[-300:]
    if engine == "libreoffice":
        d = out.parent / ("lo-" + out.stem)
        d.mkdir(exist_ok=True)
        ext = src.suffix.lower().lstrip(".")
        flt = {"doc": "doc:MS Word 97", "xls": "xls:MS Excel 97", "ppt": "ppt:MS PowerPoint 97"}.get(ext, ext)
        r = soffice(["--convert-to", flt, "--outdir", str(d), str(src)])
        got = d / src.name
        if got.exists():
            shutil.move(str(got), out)
        return out.exists(), r.stderr[-300:]
    raise ValueError(engine)


def check(src, engine, work):
    k = kind(src)
    res = {"file": src.name, "kind": k, "engine": engine}
    out = work / f"{engine}-{src.name}"
    if engine == "zapps" and k in ("doc", "xls"):
        out = out.with_suffix(".docx" if k == "doc" else ".xlsx")      # the apps save in the newer format
    try:
        ok, err = run_engine(engine, src, out)
    except subprocess.TimeoutExpired:
        ok, err = False, "timeout"
    res["saved"] = ok
    if not ok:
        res["error"] = err
        return res
    if k in LEGACY:                   # no XML to count: compare the pages only
        pa = pb = None
    else:
        pa, pb = parts(src), parts(out)
    if k in LEGACY:
        pass
    elif pa is None or pb is None:
        res["error"] = "not a zip package"
        return res
    if pa is not None:
        fa, fb = count(pa, k), count(pb, k)
        if k == "xlsx":
            try:
                xa = xlsx_structure(src)
                xb = xlsx_structure(out, xa["_bounds"])
                for n in ("merged cells", "column widths", "print areas", "page breaks", "conditional formats",
                          "input rules", "formulas"):
                    fa[n], fb[n] = xa[n], xb[n]
                # cell by cell: of the original's cells with a border (fill, font, number format), how many still have one
                for n in ("borders", "number formats", "fonts", "fills"):
                    ca, cb = xa["_cells"].get(n, set()), xb["_cells"].get(n, set())
                    fa[n], fb[n] = len(ca), len(ca & cb)
                wa, wb_ = xa.get("_widths", {}), xb.get("_widths", {})
                fa["column widths"] = len(wa)
                fb["column widths"] = sum(1 for k, w in wa.items() if k in wb_ and abs(wb_[k] - w) <= 0.15)
            except Exception:
                pass
        res["features"] = {n: [fa[n], fb[n]] for n in fa}
        if k == "docx":
            ha, hb = header_footer_text(pa), header_footer_text(pb)
            # headers and footers as Word shows them: the same text kept counts as kept, however many parts the
            # saving program writes it into
            res["features"]["headers/footers"] = [1, 1 if (text_kept(ha, hb) or 0) >= 0.95 else 0] if ha else [0, 0]
        res["text"] = text_kept(text(pa, k), text(pb, k))
    if k == "xlsx":
        res["cells"] = cells(src, out)
        if res["cells"] and res["cells"].get("kept") is not None:
            res["text"] = res["cells"]["kept"]       # a workbook's text is its cells; the XML order differs by program
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        a, b = to_pdf(src, t / "a"), to_pdf(out, t / "b")
        if a and b:
            ia, ib = pages(a, t, "a"), pages(b, t, "b")
            res["pages"] = [len(ia), len(ib)]
            res["look"] = page_similarity(ia, ib)
    return res


def summary(results):
    lines = ["| engine | kind | files | saved | text kept | look alike | same page count |", "|---|---|---|---|---|---|---|"]
    feats = {}
    for (e, k) in sorted({(r["engine"], r["kind"]) for r in results}):
        rs = [r for r in results if r["engine"] == e and r["kind"] == k]
        sv = [r for r in rs if r.get("saved")]
        avg = lambda xs: round(sum(xs) / len(xs), 3) if xs else None
        tk = avg([r["text"] for r in sv if r.get("text") is not None])
        lk = avg([r["look"] for r in sv if r.get("look") is not None])
        pc = sum(1 for r in sv if r.get("pages") and r["pages"][0] == r["pages"][1])
        lines.append(f"| {e} | {k} | {len(rs)} | {len(sv)} | {tk} | {lk} | {pc}/{len(sv)} |")
        for r in sv:
            for n, (a, b) in (r.get("features") or {}).items():
                if a:
                    f = feats.setdefault((e, k, n), [0, 0])
                    f[0] += 1
                    f[1] += 1 if b >= a else 0
    lines += ["", "Files where an element was present, and how many kept all of it:", "",
              "| engine | kind | element | files with it | kept all |", "|---|---|---|---|---|"]
    for (e, k, n), (a, b) in sorted(feats.items()):
        lines.append(f"| {e} | {k} | {n} | {a} | {b} |")
    return "\n".join(lines) + "\n"


def _fresh_profile():
    global PROFILE
    PROFILE = None                      # each worker its own LibreOffice profile for drawing pages


def _one(arg):
    f, e, w = arg
    d = Path(w) / f"{os.getpid()}"
    d.mkdir(exist_ok=True)
    try:
        return check(Path(f), e, d)
    except Exception as ex:
        return {"file": Path(f).name, "kind": kind(Path(f)), "engine": e, "saved": False, "error": repr(ex)[:300]}


def gate(results, baseline_path):
    """refuse a change that makes any file worse than the recorded baseline: a file that saved no longer saves, an
    element that was kept is no longer kept, the cells or text kept drop, or the pages look less alike (by more than
    0.02, the noise of drawing). Only files present in both are compared."""
    base = {(r["file"], r["engine"]): r for r in json.loads(Path(baseline_path).read_text())}
    worse = []
    for r in results:
        b = base.get((r["file"], r["engine"]))
        if not b:
            continue
        if b.get("saved") and not r.get("saved"):
            worse.append(f"{r['file']}: no longer saved ({r.get('error', '')[:80]})")
            continue
        for n, (x, y) in (b.get("features") or {}).items():
            if x and y >= x:
                y2 = (r.get("features") or {}).get(n, [x, 0])[1]
                if y2 < x:
                    worse.append(f"{r['file']}: {n} no longer kept ({y2} of {x})")
        for m in ("text", "look"):
            if b.get(m) is not None and r.get(m) is not None and r[m] < b[m] - (0.02 if m == "look" else 0.005):
                worse.append(f"{r['file']}: {m} {b[m]} -> {r[m]}")
    return worse


def main():
    a = sys.argv[1:]
    corpus, out = Path(a[0]), Path(a[1])
    engines = (a[a.index("--engines") + 1] if "--engines" in a else "zenos").split(",")
    limit = int(a[a.index("--limit") + 1]) if "--limit" in a else None
    out.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in corpus.iterdir() if kind(p) in FEATURES or kind(p) in LEGACY)[:limit]
    results = []
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 1
    work = [(f, e) for f in files for e in engines]
    with tempfile.TemporaryDirectory() as w:
        if jobs > 1:
            from multiprocessing import Pool
            with Pool(jobs, initializer=_fresh_profile) as pool:
                for r in pool.imap(_one, [(str(f), e, w) for f, e in work]):
                    results.append(r)
                    print(json.dumps(r, ensure_ascii=False), flush=True)
        else:
            for f, e in work:
                r = check(f, e, Path(w))
                results.append(r)
                print(json.dumps(r, ensure_ascii=False), flush=True)
    (out / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=1))
    (out / "results.md").write_text(summary(results))
    print(summary(results))
    if "--gate" in a and not Path(a[a.index("--gate") + 1]).exists():
        print("No baseline yet: this run's results.json becomes the baseline once reviewed.")
    elif "--gate" in a:
        worse = gate(results, a[a.index("--gate") + 1])
        (out / "worse.txt").write_text("\n".join(worse) + "\n")
        if worse:
            print(f"{len(worse)} results are worse than the baseline:")
            print("\n".join(worse[:60]))
            sys.exit(1)
        print("No result is worse than the baseline.")


if __name__ == "__main__":
    main()

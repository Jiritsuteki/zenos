#!/usr/bin/env python3
"""ZENOS: AI models kept on the PC (root). A model goes in only as a release, and is checked before every load.

  zenos_model.py install FOLDER RECORD.json     put a released model in place: the record must carry enough
                                                 officers' signatures and the ledger must hold it (zmodel.check)
  zenos_model.py check NAME [--level N]         may this model be loaded for data of level N? (exit 0 yes, 1 no)
  zenos_model.py list                           the models on this PC and what the offline check says

People do not put models in /var/lib/zenos/models themselves (only root writes there, and zenos-supplywatch moves
anything that is not a released model to quarantine). A program that loads a model asks `check` first and loads
nothing when it says no. The record comes from the release officers (zenos_release.py model, sign, publish).
"""
import json, os, shutil, sys, tempfile
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "zenos"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib"))
import zmodel, zsupply                                           # noqa: E402
try:
    import zledger                                               # noqa: E402
except Exception:
    zledger = None

LEDGER = os.environ.get("ZENOS_SUPPLYWATCH_LEDGER", "/var/log/zenos/access-ledger.jsonl")


def record(event, **kw):
    if zledger is not None:
        try:
            zledger.append(LEDGER, event, "root", "zenos-model", **kw)
        except Exception:
            pass


def install(src, rec_path, dest=None, c=None, get=zsupply.fetch):
    """copy a released model into place; returns the folder. Refuses anything the checks do not allow."""
    dest = Path(dest or zmodel.MODELS)
    rec = json.loads(Path(rec_path).read_text())
    m = rec.get("manifest") or {}
    if m.get("kind") != zmodel.KIND or not zsupply.NAME.match(str(m.get("name", ""))) or \
            not zsupply.NAME.match(str(m.get("version", ""))):
        raise zmodel.Refused("not a model release record")
    c = c if c is not None else zsupply.conf()
    keys = zsupply.officers() if c.get("keys") is None else c["keys"]
    need = max(1, int(c.get("required", 2)))
    if len(zsupply.valid_signers(rec, keys)) < need:
        raise zmodel.Refused(f"the record is signed by fewer than {need} release officers")
    if zmodel.files_of(src) != m.get("files"):
        raise zmodel.Refused("the files are not the ones in the record")
    dest.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".incoming-", dir=dest))      # dot folder: the watcher leaves it alone
    try:
        target = stage / "m"
        shutil.copytree(src, target, symlinks=True)
        (target / zmodel.RECORD).write_text(json.dumps(rec, indent=1))
        ok, why = zmodel.check(target, 0, dict(c, mode="enforce"), get)
        if not ok:
            raise zmodel.Refused(f"the release ledger does not allow it ({why})")
        final = dest / f"{m['name']}-{m['version']}"
        if final.exists():
            raise zmodel.Refused(f"{final.name} is already installed")
        os.replace(target, final)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    record("model-installed", name=m["name"], version=m["version"], sha256=m["sha256"])
    return final


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    try:
        if a[0] == "install" and len(a) >= 3:
            print("installed:", install(a[1], a[2]))
            return 0
        if a[0] == "check" and len(a) >= 2:
            lvl = int(a[a.index("--level") + 1]) if "--level" in a else 0
            ok, why = zmodel.check(zmodel.MODELS / a[1], lvl)
            record("model-check", name=a[1], level=lvl, allow=ok, reason=why)
            print("allowed" if ok else f"refused: {why}")
            return 0 if ok else 1
        if a[0] == "list":
            for folder in zmodel.models():
                if folder.name.startswith("."):
                    continue
                f = zmodel.offline_check(folder)
                print(f"{folder.name:40} {'ok' if not f else f[0]['kind'] + ': ' + f[0]['detail']}")
            return 0
    except (zmodel.Refused, OSError, ValueError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())

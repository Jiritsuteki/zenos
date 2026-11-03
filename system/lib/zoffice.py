"""The office engine under ZENOS's rules: Word, Excel and PowerPoint files are read, written and drawn by LibreOffice
(MPL-2.0), the same engine Collabora Online and LibreOfficeKit use, and ZENOS decides everything around it.

Every call runs LibreOffice in the sandbox (zsandbox.py: bubblewrap, an empty root, /usr /etc /opt read-only, no
network, no home folder, the seccomp filter). The file comes in on stdin and the result goes out on stdout: inside
the sandbox it lives in /tmp, a tmpfs, so a sealed file opened here is never written in plain text to the disk.
Each call gets a fresh profile, locked down: macros never run, no update check, no autosave or recovery copies,
no backup copies, no lock files.

  convert(data, "docx", "docx")   open and save again (what the compatibility check measures)
  convert(data, "doc", "docx")    an old format to the new one
  convert(data, "xlsx", "pdf")    pages, for viewing and for the print path (which keeps its own limits and banner)
"""
import os, shlex, subprocess
from pathlib import Path

try:
    from . import zsandbox
except ImportError:
    import zsandbox

FILTERS = {
    "docx": "docx:MS Word 2007 XML", "doc": "doc:MS Word 97", "odt": "odt",
    "xlsx": "xlsx:Calc MS Excel 2007 XML", "xls": "xls:MS Excel 97", "ods": "ods",
    "pptx": "pptx:Impress MS PowerPoint 2007 XML", "ppt": "ppt:MS PowerPoint 97", "odp": "odp",
    "pdf": "pdf",
}
KINDS = {"doc", "docx", "docm", "odt", "rtf", "xls", "xlsx", "xlsm", "ods", "csv", "ppt", "pptx", "pptm", "odp"}

# Keys from LibreOffice's own configuration schemas (officecfg), finalized so the document cannot change them.
# DisableActiveContent is not set: it also drops charts and other embedded objects (measured: every chart of a
# PowerPoint file lost). Links and DDE to the outside cannot reach anything anyway: the sandbox has no network and
# no files but the document.
LOCKDOWN = """<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="DisableMacrosExecution" oor:op="fuse" oor:finalized="true"><value>true</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="MacroSecurityLevel" oor:op="fuse" oor:finalized="true"><value>3</value></prop></item>
<item oor:path="/org.openoffice.Office.Jobs/Jobs/org.openoffice.Office.Jobs:Job['UpdateCheck']/Arguments"><prop oor:name="AutoCheckEnabled" oor:op="fuse" oor:finalized="true"><value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.Recovery/AutoSave"><prop oor:name="Enabled" oor:op="fuse" oor:finalized="true"><value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.Recovery/RecoveryInfo"><prop oor:name="Enabled" oor:op="fuse" oor:finalized="true"><value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Save/Document"><prop oor:name="CreateBackup" oor:op="fuse" oor:finalized="true"><value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Misc"><prop oor:name="UseLocking" oor:op="fuse" oor:finalized="true"><value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Misc"><prop oor:name="CrashReport" oor:op="fuse" oor:finalized="true"><value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.ExtensionManager/ExtensionSecurity"><prop oor:name="DisableExtensionInstallation" oor:op="fuse" oor:finalized="true"><value>true</value></prop></item>
</oor:items>
"""


class Failed(Exception):
    pass


def soffice():
    for p in ("/usr/lib/libreoffice/program/soffice", "/opt/libreoffice/program/soffice", "/usr/bin/soffice"):
        if os.path.exists(p):
            return p
    raise Failed("LibreOffice is not installed")


_TEMPLATE = None


def _template():
    """A locked-down profile made once per user (it holds no document data), copied into each sandbox: a fresh
    profile costs LibreOffice about 20 seconds at every start."""
    global _TEMPLATE
    if _TEMPLATE and os.path.isdir(_TEMPLATE):
        return _TEMPLATE
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or "/tmp") / f"zoffice-profile-{os.getuid()}"
    if not (base / "user" / "registrymodifications.xcu").exists():
        import io, tarfile
        script = f"""set -e
umask 077
mkdir -p /tmp/p/user
cat > /tmp/p/user/registrymodifications.xcu <<'XCU'
{LOCKDOWN}XCU
printf 'x' > /tmp/x.txt
{shlex.quote(soffice())} -env:UserInstallation=file:///tmp/p --headless --norestore --nologo --nodefault \
  --convert-to pdf --outdir /tmp /tmp/x.txt >/dev/null 2>&1 || true
cat > /tmp/p/user/registrymodifications.xcu <<'XCU'
{LOCKDOWN}XCU
cd /tmp/p && tar cf - .
"""
        r = zsandbox.run(["/bin/sh", "-c", script], timeout=300, text=False)
        if r.returncode != 0:
            raise Failed("could not prepare the office profile")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(r.stdout)) as t:
            t.extractall(base, filter="data")
    _TEMPLATE = str(base)
    return _TEMPLATE


def convert(data, src, dst, timeout=180):
    """data: the file's bytes; src: its kind (docx, xls, ...); dst: the kind to produce. Returns the new file's bytes."""
    src, dst = src.lower().lstrip("."), dst.lower().lstrip(".")
    if src not in KINDS or dst not in FILTERS:
        raise ValueError("unsupported kind")
    if src in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp") and not data.startswith(b"PK\x03\x04"):
        raise Failed("not a %s file" % src)      # a file that claims a package format must be one
    filt = FILTERS[dst]
    script = f"""set -e
umask 077
mkdir -p /tmp/o
cp -r /work/in/profile /tmp/p
cat > /tmp/p/user/registrymodifications.xcu <<'XCU'
{LOCKDOWN}XCU
cat > /tmp/in.{src}
{shlex.quote(soffice())} -env:UserInstallation=file:///tmp/p --headless --norestore --nologo --nodefault \
  --convert-to {shlex.quote(filt)} --outdir /tmp/o /tmp/in.{src} >/dev/null 2>&1 || true
f=$(ls /tmp/o/in.* 2>/dev/null | head -1); [ -n "$f" ] || exit 3
cat "$f"
"""
    if os.environ.get("ZENOS_IN_SANDBOX") == "1":
        # already inside the office window's sandbox (no network, tmpfs /tmp): bubblewrap cannot nest, so run here
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            local = script.replace("/tmp/", t + "/").replace("/work/in/profile", shlex.quote(_template()))
            r = subprocess.run(["/bin/sh", "-c", local], input=data, capture_output=True, timeout=timeout)
    else:
        r = zsandbox.run(["/bin/sh", "-c", script], inputs={"profile": _template()}, stdin=data, timeout=timeout, text=False)
    if r.returncode != 0 or not r.stdout:
        raise Failed("LibreOffice could not open or save this file")
    return r.stdout

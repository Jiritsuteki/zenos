#!/bin/bash
# Build the ZENOS Debian package (amd64) from this repository.
#   packaging/build-deb.sh            -> build/zenos_<version>_amd64.deb
# Needs: dpkg-deb, nodejs + npm (to build the office apps and install the messenger's runtime modules).
set -euo pipefail
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
VER="${VER:-0.1.0~preview$(date +%Y%m%d)}"
OUT="${OUT:-$SRC/build}"
# reproducible: the same source gives the same bytes (packaging/repro-check.sh builds twice and compares)
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$SRC" log -1 --format=%ct 2>/dev/null || date +%s)}"
export TZ=UTC LC_ALL=C.UTF-8
umask 022
B="$OUT/work"; P="$OUT/pkg"
mkdir -p "$OUT"
exec 9>"$OUT/.build.lock"
flock -n 9 || { echo "another build is running in $OUT" >&2; exit 1; }   # two builds would delete each other's files
rm -rf "$B" "$P"; mkdir -p "$B" "$P"
Z="$P/usr/share/zenos"

echo "== core"
mkdir -p "$Z/apps"
cp -a "$SRC/core/bin" "$SRC/core/shell" "$SRC/core/icons" "$SRC/core/templates" "$Z/"
# boot screen and login screen in the ZENOS look
mkdir -p "$P/usr/share/plymouth/themes" "$P/usr/share/sddm/themes"
cp -a "$SRC/desktop/plymouth/zenos" "$P/usr/share/plymouth/themes/"
cp -a "$SRC/desktop/sddm/zenos" "$P/usr/share/sddm/themes/"
cp "$SRC"/core/wallpaper.* "$Z/"
chmod 755 "$Z"/bin/*.sh "$Z"/bin/*.py

echo "== apps"
for a in images video pdf; do cp -a "$SRC/apps/$a" "$Z/apps/"; done
for a in docs sheets slides; do
  cp -a "$SRC/apps/$a" "$B/$a"
  ( cd "$B/$a" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent )
  mkdir -p "$Z/apps/$a"
  cp -a "$B/$a/dist" "$Z/apps/$a/"
done
cp -a "$SRC/apps/common" "$Z/apps/"          # the local server the three office apps share
cp -a "$SRC/apps/office" "$Z/apps/"          # ZENOS Office: the LibreOffice engine in a ZENOS window (docs/OFFICE_ENGINE.md)
chmod 755 "$Z/apps/office/zenos-office" "$Z/apps/office/zenos_office.py"
mkdir -p "$P/etc/fonts/conf.d"
install -m 644 "$SRC/system/fontconfig/60-zenos-office.conf" "$P/etc/fonts/conf.d/60-zenos-office.conf"

echo "== messenger (AGPL-3.0)"
cp -a "$SRC/messenger" "$B/msg"
( cd "$B/msg" && npm ci --omit=dev --no-audit --no-fund --loglevel=error
  # native modules for other platforms are not needed in an amd64 package
  find node_modules/@signalapp/libsignal-client/prebuilds -mindepth 1 -maxdepth 1 ! -name linux-x64 -exec rm -rf {} +
  find node_modules/@napi-rs -mindepth 1 -maxdepth 1 \( -name '*darwin*' -o -name '*win32*' -o -name '*arm*' -o -name '*musl*' -o -name '*android*' -o -name '*freebsd*' -o -name '*riscv*' -o -name '*ppc*' -o -name '*s390*' \) -exec rm -rf {} + 2>/dev/null || true )
cp -a "$B/msg" "$Z/msg"
chmod 755 "$Z"/msg/*.sh

echo "== storage layer (encrypted, erasure-coded shards on certified storage nodes)"
cp -a "$SRC/storage" "$B/storage"
( cd "$B/storage" && rm -rf node_modules test && npm ci --omit=dev --no-audit --no-fund --loglevel=error )
cp -a "$B/storage" "$Z/storage"
chmod 755 "$Z/storage/bin/zenos-store.js"

echo "== system services"
mkdir -p "$P/usr/lib/zenos" "$P/usr/sbin" "$P/lib/systemd/system" "$P/usr/lib/systemd/user"
cp -a "$SRC"/system/lib/. "$P/usr/lib/zenos/"
cp -a "$SRC"/system/sbin/. "$P/usr/sbin/"
chmod 755 "$P"/usr/sbin/*
chmod 644 "$P/usr/sbin/zenos-netsense.bt"
mkdir -p "$P/usr/bin"
ln -sf ../sbin/zenos_conductor.py "$P/usr/bin/zenos-conductor"     # the conductor runs as the person
ln -sf ../share/zenos/apps/office/zenos-office "$P/usr/bin/zenos-office"
cp "$SRC"/system/systemd/*.service "$SRC"/system/systemd/*.timer "$P/lib/systemd/system/"
# fewer ways into the kernel: sysctl settings and modules that are never loaded (docs/THREAT_MODEL.md)
mkdir -p "$P/usr/lib/sysctl.d" "$P/usr/lib/modprobe.d"
install -m 644 "$SRC/system/sysctl.d/60-zenos-hardening.conf" "$P/usr/lib/sysctl.d/60-zenos-hardening.conf"
install -m 644 "$SRC/system/modprobe.d/zenos-blacklist.conf" "$P/usr/lib/modprobe.d/zenos-blacklist.conf"
mkdir -p "$P/etc/default/grub.d"
install -m 644 "$SRC/system/grub.d/zenos-hardening.cfg" "$P/etc/default/grub.d/zenos-hardening.cfg"

echo "== the Node.js packages shipped, for zenos-vulnwatch to match against OSV"
python3 "$SRC/tools/sbom.py" --version "$VER" --npm-inventory "$Z/npm-inventory.json" >/dev/null

echo "== decision program (formal/: Lean 4; the build checks every proof)"
LAKE="${LAKE:-$(command -v lake || echo /opt/lean/lean-4.34.1-linux/bin/lake)}"
[ -x "$LAKE" ] || { echo "Lean 4 (lake) is needed to build zenos-decide: docs/FORMAL_VERIFICATION.md" >&2; exit 1; }
rm -rf "$B/formal"; mkdir -p "$B/formal"
( cd "$SRC/formal" && tar cf - --exclude=.lake . ) | ( cd "$B/formal" && tar xf - )
( cd "$B/formal" && PATH="$(dirname "$LAKE"):$PATH" "$LAKE" build )
install -m 755 "$B/formal/.lake/build/bin/zenos-decide" "$P/usr/lib/zenos/zenos-decide"
cp "$SRC"/system/systemd-user/*.service "$P/usr/lib/systemd/user/"
mkdir -p "$P/usr/lib/tmpfiles.d" && install -m 644 "$SRC/system/tmpfiles.d/zenos.conf" "$P/usr/lib/tmpfiles.d/zenos.conf"
mkdir -p "$P/etc/zenos"
# security fixes install themselves (packaging/debian/apt/52zenos-auto-update)
mkdir -p "$P/etc/apt/apt.conf.d"
install -m 644 "$SRC/packaging/debian/apt/52zenos-auto-update" "$P/etc/apt/apt.conf.d/52zenos-auto-update"
install -m 644 "$SRC/packaging/debian/apt/53zenos-supply" "$P/etc/apt/apt.conf.d/53zenos-supply"
# Node.js 24 LTS from NodeSource; Debian 13's Node 20 is past end of life (packaging/debian/apt/zenos-nodesource.*)
mkdir -p "$P/etc/apt/sources.list.d" "$P/etc/apt/preferences.d" "$P/usr/share/keyrings"
install -m 644 "$SRC/packaging/debian/apt/zenos-nodesource.sources" "$P/etc/apt/sources.list.d/zenos-nodesource.sources"
install -m 644 "$SRC/packaging/debian/apt/zenos-nodesource.pref" "$P/etc/apt/preferences.d/zenos-nodesource"
install -m 644 "$SRC/packaging/debian/apt/nodesource-archive-keyring.gpg" "$P/usr/share/keyrings/zenos-nodesource.gpg"
# every Node program refuses distrusted CA certificates and keys (system/lib/zdistrust.js)
mkdir -p "$P/etc/profile.d" "$P/usr/lib/environment.d" "$P/usr/lib/systemd/system.conf.d"
install -m 644 "$SRC/packaging/debian/node/zenos-node.sh" "$P/etc/profile.d/zenos-node.sh"
install -m 644 "$SRC/packaging/debian/node/60-zenos-node.conf" "$P/usr/lib/environment.d/60-zenos-node.conf"
install -m 644 "$SRC/packaging/debian/node/60-zenos-node-system.conf" "$P/usr/lib/systemd/system.conf.d/60-zenos-node.conf"
cat > "$P/etc/zenos/zenos.conf" <<'EOF'
# ZENOS machine settings (KEY=value)
# The desktop user whose files the root services protect. Empty: the first user who has ZENOS data.
#ZENOS_USER=
# Where the ZENOS programs are installed.
ZENOS_ROOT=/usr/share/zenos
EOF

echo "== LiveKit call server (Apache-2.0): pinned release, checksum verified"
LK_VER=1.13.10
LK_SHA=c25a3e45fb922e9a93c6443d10c0ed041ba64342097e38632331736630283165
curl -fsSL -o "$B/livekit.tgz" "https://github.com/livekit/livekit/releases/download/v$LK_VER/livekit_${LK_VER}_linux_amd64.tar.gz"
echo "$LK_SHA  $B/livekit.tgz" | sha256sum -c --quiet -
mkdir -p "$P/usr/lib/zenos/livekit"
tar -xzf "$B/livekit.tgz" -C "$P/usr/lib/zenos/livekit" livekit-server LICENSE
chmod 755 "$P/usr/lib/zenos/livekit/livekit-server"

echo "== desktop"
mkdir -p "$P/usr/share/applications" "$P/etc/xdg/autostart" "$P/usr/share/plasma/plasmoids" "$P/usr/share/plasma/desktoptheme"
cp "$SRC"/desktop/applications/*.desktop "$P/usr/share/applications/"
cp "$SRC"/desktop/autostart/zenos-*.desktop "$P/etc/xdg/autostart/"
cp -a "$SRC"/desktop/plasmoids/jp.zenos.* "$P/usr/share/plasma/plasmoids/"
cp -a "$SRC/third_party/kde-plasma-theme/zenos" "$P/usr/share/plasma/desktoptheme/"
mkdir -p "$P/etc/skel/.local/share/plasma/plasmoids"
cp -a "$SRC/desktop/skel/.config" "$P/etc/skel/"
cp -a "$SRC"/third_party/kde-plasmoids/* "$P/etc/skel/.local/share/plasma/plasmoids/"
mkdir -p "$P/usr/share/plasma/shells/org.kde.plasma.desktop/contents/updates"
cp -a "$SRC"/desktop/plasma-updates/*.js "$P/usr/share/plasma/shells/org.kde.plasma.desktop/contents/updates/"

echo "== docs"
mkdir -p "$P/usr/share/doc/zenos"
cp "$SRC"/README.md "$SRC"/LICENSE "$SRC"/NOTICE "$SRC"/THIRD_PARTY_NOTICES.md "$SRC"/docs/THREAT_MODEL.md "$P/usr/share/doc/zenos/"
cp "$SRC/messenger/LICENSE" "$P/usr/share/doc/zenos/LICENSE.messenger-AGPL-3.0"

echo "== control"
find "$P" -name __pycache__ -prune -exec rm -rf {} +
# modes and times that do not depend on the build machine
find "$P" -type d -exec chmod 755 {} +
find "$P" -type f -perm /111 -exec chmod 755 {} +
find "$P" -type f ! -perm /111 -exec chmod 644 {} +
mkdir -p "$P/DEBIAN"
SIZE=$(find "$P" -type f -printf '%s\n' | awk '{s+=$1} END {print int(s/1024)+1}')
sed -e "s/@VERSION@/$VER/" -e "s/@SIZE@/$SIZE/" "$SRC/packaging/debian/control.in" > "$P/DEBIAN/control"
for s in postinst prerm postrm; do install -m 755 "$SRC/packaging/debian/$s" "$P/DEBIAN/$s"; done
printf '/etc/zenos/zenos.conf\n/etc/default/grub.d/zenos-hardening.cfg\n' > "$P/DEBIAN/conffiles"

find "$P" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group -Zxz --build "$P" "$OUT/zenos_${VER}_amd64.deb" >/dev/null
ls -la "$OUT/zenos_${VER}_amd64.deb"
# the build record: what it was built from and with (published next to the package)
LAKE="$LAKE" python3 - "$OUT/zenos_${VER}_amd64.deb" "$SRC" > "$OUT/zenos_${VER}_amd64.buildinfo.json" <<'PY'
import hashlib, json, os, subprocess, sys
deb, src = sys.argv[1], sys.argv[2]
def v(*a):
    try:
        return (subprocess.run(a, capture_output=True, text=True).stdout or "").strip().splitlines()[:1]
    except OSError:
        return []
print(json.dumps({"package": os.path.basename(deb), "sha256": hashlib.sha256(open(deb, "rb").read()).hexdigest(),
                  "source_commit": (v("git", "-C", src, "rev-parse", "HEAD") or [""])[0],
                  "source_dirty": bool(v("git", "-C", src, "status", "--porcelain")),
                  "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
                  "tools": {"dpkg": v("dpkg", "--version"), "node": v("node", "--version"), "npm": v("npm", "--version"),
                            "python": v("python3", "--version"), "lean": v(os.environ.get("LAKE", "lake"), "--version")}}, indent=1))
PY

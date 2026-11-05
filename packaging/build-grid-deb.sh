#!/bin/bash
# Build the ZENOS grid server package (amd64): storage node, grid bootstrap and audit node.
# These run on servers the PC users do not control, one set per party (ministry, agency, audit body).
#   packaging/build-grid-deb.sh       -> build/zenos-grid_<version>_amd64.deb
# Needs: dpkg-deb, nodejs + npm.
set -euo pipefail
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
VER="${VER:-0.1.0~preview$(date +%Y%m%d)}"
OUT="${OUT:-$SRC/build}"
B="$OUT/grid-work"; P="$OUT/grid-pkg"
mkdir -p "$OUT"
exec 9>"$OUT/.grid-build.lock"
flock -n 9 || { echo "another grid build is running in $OUT" >&2; exit 1; }
rm -rf "$B" "$P"; mkdir -p "$B" "$P"
G="$P/usr/share/zenos-grid"

echo "== storage layer"
cp -a "$SRC/storage" "$B/storage"
( cd "$B/storage" && rm -rf node_modules test && npm ci --omit=dev --no-audit --no-fund --loglevel=error )
mkdir -p "$G"
cp -a "$B/storage" "$G/storage"
chmod 755 "$G/storage/bin/zenos-store.js"

echo "== audit node"
mkdir -p "$G/audit"
install -m 755 "$SRC/system/sbin/zenos_auditnode.py" "$G/audit/"
install -m 644 "$SRC/system/lib/zledger.py" "$SRC/system/lib/zdecide.py" "$SRC/system/lib/zident.py" "$SRC/system/lib/znotify.py" "$G/audit/"
echo "== key service (beside the audit node; it shares the proven decision program)"
install -m 755 "$SRC/system/sbin/zenos_keysvc.py" "$G/audit/"
install -m 644 "$SRC/system/lib/zkeysvc.py" "$SRC/system/lib/zwebauthn.py" "$G/audit/"
echo "== ZENOS Data peers (key and storage peers for servers' records)"
install -m 755 "$SRC/system/sbin/zenos_datapeer.py" "$G/audit/"
install -m 644 "$SRC/system/lib/zdata.py" "$G/audit/"
# the proven chain check (formal/), built the same way as for the zenos package
LAKE="${LAKE:-$(command -v lake || echo /opt/lean/lean-4.34.1-linux/bin/lake)}"
[ -x "$LAKE" ] || { echo "Lean 4 (lake) is needed to build zenos-decide: docs/FORMAL_VERIFICATION.md" >&2; exit 1; }
rm -rf "$B/formal"; mkdir -p "$B/formal"
( cd "$SRC/formal" && tar cf - --exclude=.lake . ) | ( cd "$B/formal" && tar xf - )
( cd "$B/formal" && PATH="$(dirname "$LAKE"):$PATH" "$LAKE" build )
install -m 755 "$B/formal/.lake/build/bin/zenos-decide" "$G/audit/zenos-decide"

echo "== services (each starts only once its /etc/zenos/*.json exists)"
mkdir -p "$P/lib/systemd/system"
install -m 644 "$SRC"/packaging/grid/*.service "$P/lib/systemd/system/"

echo "== docs and examples"
D="$P/usr/share/doc/zenos-grid"
mkdir -p "$D/examples"
cp "$SRC/packaging/grid/README.md" "$SRC/LICENSE" "$SRC/NOTICE" "$D/"
cp "$SRC"/config/examples/storage-node.example.json "$SRC"/config/examples/grid-bootstrap.example.json \
   "$SRC"/config/examples/auditnode.example.json "$SRC"/config/examples/grid.example.json \
   "$SRC"/config/examples/keysvc-server.env.example "$SRC"/config/examples/datapeer.example.json \
   "$SRC"/config/examples/datapeer.env.example "$D/examples/"

echo "== control"
find "$P" -name __pycache__ -prune -exec rm -rf {} +
mkdir -p "$P/DEBIAN"
SIZE=$(du -sk "$P" | cut -f1)
cat > "$P/DEBIAN/control" <<EOF
Package: zenos-grid
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Installed-Size: $SIZE
Maintainer: The ZENOS Authors <zenos-authors@users.noreply.invalid>
Depends: nodejs (>= 20), python3 (>= 3.11), python3-cryptography
Description: ZENOS grid servers: storage node, bootstrap, audit node, key service, data peers (Developer Preview)
 Servers for a ZENOS grid, run by each party outside the PCs: a storage node keeps
 encrypted, erasure-coded shards and serves them only to certified PCs cleared for
 their level; the bootstrap is the closed network's own entry point; the audit node
 keeps a copy of every enrolled PC's ledger and compares it with the other parties'
 audit nodes, so a rewritten or forked history is caught; the key service holds the
 keys of sealed files and releases one file's key at a time to a healthy PC;
 the data peers keep server programs' records with no plaintext and no key at
 rest (ZENOS Data).
 .
 This is a proof of concept and not yet safe for real classified data.
EOF
cat > "$P/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    for u in zenos-storage-node zenos-grid-bootstrap zenos-auditnode zenos-keysvc zenos-datapeer; do
        systemctl enable "$u.service" >/dev/null 2>&1 || true   # inert until its config file exists
        systemctl try-restart "$u.service" || true
    done
fi
EOF
cat > "$P/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    for u in zenos-storage-node zenos-grid-bootstrap zenos-auditnode zenos-keysvc zenos-datapeer; do
        systemctl disable --now "$u.service" >/dev/null 2>&1 || true
    done
fi
EOF
chmod 755 "$P/DEBIAN/postinst" "$P/DEBIAN/prerm"

dpkg-deb --root-owner-group -Zxz --build "$P" "$OUT/zenos-grid_${VER}_amd64.deb" >/dev/null
ls -la "$OUT/zenos-grid_${VER}_amd64.deb"

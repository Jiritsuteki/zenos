#!/bin/bash
# Build a ZENOS live / installer ISO (Debian 13 "trixie" + KDE Plasma + ZENOS, Calamares installer).
#   sudo packaging/iso/build-iso.sh build/zenos_<version>_amd64.deb
# The image boots on ordinary PCs (BIOS and UEFI) as a live session; "Install ZENOS" puts it on the disk.
# Needs root and live-build.
set -euo pipefail
DEB="$(readlink -f "${1:?path to zenos_*.deb}")"
SRC="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
W="${WORK:-$SRC/build/iso}"
[ -d "$W/cache" ] && mv "$W/cache" "$W.cache"                 # keep downloaded packages between builds
rm -rf "$W"; mkdir -p "$W"; cd "$W"
[ -d "$W.cache" ] && mv "$W.cache" "$W/cache"

lb config \
  --mode debian --distribution trixie --architectures amd64 \
  --archive-areas "main non-free-firmware" \
  --debian-installer none \
  --binary-images iso-hybrid --bootloaders "grub-efi,syslinux" \
  --iso-application "ZENOS" --iso-volume "ZENOS" --iso-publisher "The ZENOS Authors" \
  --image-name zenos \
  --bootappend-live "boot=live components quiet splash username=zenos user-fullname=ZENOS hostname=zenos locales=en_US.UTF-8 lockdown=integrity" \
  --apt-recommends false \
  --memtest none

mkdir -p config/package-lists config/packages.chroot config/includes.chroot/etc/sddm.conf.d config/hooks/live config/bootloaders
cp "$DEB" config/packages.chroot/
# Node.js 24 LTS from NodeSource (the ZENOS package needs nodejs >= 24; Debian 13 has only the unsupported Node 20).
# The build host fetches the package through its own apt (which verifies NodeSource's signature) and the image takes it
# as a local package: the chroot cannot verify deb.nodesource.com's certificate during the build (two ISO builds
# failed on that). The installed system gets the archive for updates from the ZENOS package.
NODE_DIR="$(mktemp -d)"
( cd "$NODE_DIR" && apt-get download nodejs ) || cp /var/cache/apt/archives/nodejs_2[4-9]*nodesource*_amd64.deb "$NODE_DIR"/
NODE_DEB="$(ls "$NODE_DIR"/nodejs_*_amd64.deb | sort -V | tail -1)"
dpkg --compare-versions "$(dpkg-deb -f "$NODE_DEB" Version)" ge 24 || { echo "need nodejs >= 24 on the build host (NodeSource)" >&2; exit 1; }
cp "$NODE_DEB" config/packages.chroot/; rm -rf "$NODE_DIR"
# the archive itself comes with the ZENOS package (zenos-nodesource.sources, its key only for that archive): no second
# copy here, whose key live-build would put in apt's global trust, valid for every archive
cp "$SRC/packaging/iso/splash.svg" config/bootloaders/splash.svg      # ZENOS boot screen (BIOS and UEFI menus)
cat > config/package-lists/zenos.list.chroot <<'EOF'
# desktop
kde-plasma-desktop
plasma-workspace
kwin-x11
sddm
sddm-theme-breeze
plymouth
plymouth-label
xorg
plasma-nm
network-manager
plasma-pa
pipewire-pulse
wireplumber
kscreen
powerdevil
xdg-user-dirs
sudo
# input: Japanese / English
fcitx5
fcitx5-anthy
kde-config-fcitx5
im-config
# installer and live system (live-config creates the live user only through user-setup)
calamares
calamares-settings-debian
live-boot
live-config
live-config-systemd
user-setup
# the installer's password check needs the cracklib dictionary
cracklib-runtime
# the installer copies the image with unsquashfs and formats with these
squashfs-tools
dosfstools
btrfs-progs
xfsprogs
# hardware
firmware-linux-free
firmware-misc-nonfree
firmware-iwlwifi
firmware-realtek
EOF
# packages the installer puts on the target from the image itself (Debian's Calamares helpers install the boot
# loader and the encrypted-root unlock with apt from the image's own pool, offline). live-build resolves each list
# on its own, so the BIOS and UEFI boot loaders, which conflict, sit in separate lists.
cat > config/package-lists/zenos-bios.list.binary <<'EOF'
grub-pc
cryptsetup
cryptsetup-initramfs
keyutils
EOF
cat > config/package-lists/zenos-efi.list.binary <<'EOF'
grub-efi
grub-efi-amd64
grub-efi-amd64-signed
shim-signed
efibootmgr
EOF
cat > config/includes.chroot/etc/sddm.conf.d/zenos.conf <<'EOF'
[General]
DefaultSession=plasmax11.desktop
[Theme]
Current=zenos
EOF
# live session: log the live user straight into Plasma (X11). live-config's own sddm step names the Wayland session
# (plasma.desktop, in Plasma 6) or none at all, and its /etc/sddm.conf overrides the conf.d files. This runs at
# live boot only, so nothing of it reaches an installed system (Calamares copies the image, not the running system).
mkdir -p config/includes.chroot/usr/lib/live/config
cat > config/includes.chroot/usr/lib/live/config/0086-zenos-sddm <<'EOF'
#!/bin/sh
. /usr/lib/live/config.sh
for p in ${LIVE_CONFIG_CMDLINE}; do case "$p" in live-config.username=*|username=*) LIVE_USERNAME="${p#*username=}";; noautologin|live-config.noautologin) exit 0;; esac; done
[ -n "${LIVE_USERNAME}" ] || exit 0
printf '[Autologin]\nUser=%s\nSession=plasmax11.desktop\n' "${LIVE_USERNAME}" > /etc/sddm.conf
EOF
chmod 755 config/includes.chroot/usr/lib/live/config/0086-zenos-sddm
cat > config/hooks/live/0100-zenos.hook.chroot <<'EOF'
#!/bin/sh
set -e
# fcitx5 is the input method for every session
im-config -n fcitx5 || true
EOF
chmod +x config/hooks/live/*.hook.chroot

# installer: ZENOS branding and the Plasma X11 session for Calamares (Debian's settings package names Debian and Wayland)
mkdir -p config/includes.chroot/etc/calamares/branding config/includes.chroot/etc/calamares/modules
cp -r "$SRC/packaging/iso/calamares/branding/zenos" config/includes.chroot/etc/calamares/branding/
cp "$SRC"/packaging/iso/calamares/modules/*.conf config/includes.chroot/etc/calamares/modules/   # X11 session, disk encryption on by default
# prepare the target for Calamares' unmount, which gives up after 10 s ("Could not unmount the root of the
# target system"): write everything out and drop the cached inodes of the new system, so the unmount itself has
# little left to do (on a slow machine, evicting the inodes of a fresh install took about 40 s)
mkdir -p config/includes.chroot/usr/lib/calamares/modules/zenos-sync
printf -- '---\ntype:       "job"\nname:       "zenos-sync"\ninterface:  "process"\nchroot:     false\ncommand:    "sync; echo 3 > /proc/sys/vm/drop_caches; sync"\ntimeout:    1800\n' \
  > config/includes.chroot/usr/lib/calamares/modules/zenos-sync/module.desc
cat > config/hooks/live/0110-zenos-installer.hook.chroot <<'EOF'
#!/bin/sh
set -e
sed -i 's/^branding:.*/branding: zenos/' /etc/calamares/settings.conf
grep -q 'zenos-sync' /etc/calamares/settings.conf || sed -i 's/^\(  *\)- umount$/\1- zenos-sync\n&/' /etc/calamares/settings.conf
grep -q 'zenos-sync' /etc/calamares/settings.conf
# Debian's boot loader step installs grub and the encrypted-root unlock and rebuilds the initramfs twice; on slow
# PCs (and in a VM without hardware acceleration) that took longer than its 10-minute limit and the install failed
sed -i 's/^timeout:.*/timeout:    3600/' /usr/lib/calamares/modules/bootloader-config/module.desc
grep -q 'timeout:    3600' /usr/lib/calamares/modules/bootloader-config/module.desc
for f in /usr/share/applications/calamares-install-debian.desktop; do
  [ -f "$f" ] || continue
  sed -i -e 's/^Name\(\[[^]]*\]\)\?=.*/Name=Install ZENOS/' -e 's/^GenericName\(\[[^]]*\]\)\?=.*/GenericName=Install ZENOS on this PC/' \
         -e 's/^Comment\(\[[^]]*\]\)\?=.*/Comment=Install ZENOS on this PC/' -e 's|^Icon=.*|Icon=/etc/calamares/branding/zenos/logo.svg|' "$f"
  awk '!seen[$0]++ || !/^(Name|GenericName|Comment)=/' "$f" > "$f.n" && mv "$f.n" "$f"
done
EOF
chmod +x config/hooks/live/*.hook.chroot
# live session: the live user may open files up to L4 (a fresh install starts with no clearance). The
# "Install ZENOS" desktop icon comes from Debian's installer settings (renamed by the hook above).
cat > config/includes.chroot/usr/lib/live/config/0087-zenos-live <<'EOF'
#!/bin/sh
. /usr/lib/live/config.sh
for p in ${LIVE_CONFIG_CMDLINE}; do case "$p" in live-config.username=*|username=*) LIVE_USERNAME="${p#*username=}";; esac; done
[ -n "${LIVE_USERNAME}" ] || exit 0
[ -x /usr/sbin/zenos_keyd.py ] && /usr/sbin/zenos_keyd.py --clearance "${LIVE_USERNAME}" 4 >/dev/null 2>&1 || true
# no screen lock in the live session: nobody knows the live user's password, and an install takes a while
H="/home/${LIVE_USERNAME}"; mkdir -p "$H/.config"
printf '[Daemon]\nAutolock=false\nLockOnResume=false\n' > "$H/.config/kscreenlockerrc"
chown -R "${LIVE_USERNAME}:" "$H/.config"
EOF
chmod 755 config/includes.chroot/usr/lib/live/config/0087-zenos-live

# boot menu: start the live system by itself after 5 seconds (it waited for Enter forever)
mkdir -p config/hooks/normal
cat > config/hooks/normal/0900-zenos-boot-timeout.hook.binary <<'EOF'
#!/bin/sh
for f in isolinux/isolinux.cfg isolinux/live.cfg; do
  [ -f "$f" ] || continue
  if grep -q '^timeout' "$f"; then sed -i 's/^timeout .*/timeout 50/' "$f"; else sed -i '1i timeout 50' "$f"; fi
done
for f in boot/grub/config.cfg boot/grub/grub.cfg; do
  [ -f "$f" ] || continue
  if grep -q 'set timeout=' "$f"; then sed -i 's/set timeout=.*/set timeout=5/' "$f"; else echo 'set timeout=5' >> "$f"; fi
done
EOF
chmod +x config/hooks/normal/0900-zenos-boot-timeout.hook.binary

# the ZENOS boot screen (also asks the disk passphrase), in the image and so on the installed system
cat > config/hooks/live/0950-zenos-plymouth.hook.chroot <<'EOF'
#!/bin/sh
set -e
plymouth-set-default-theme zenos
# the live image has no /etc/default/grub (the installer writes it, with its own parameters); grub-mkconfig sources
# grub.d after it, so this appends the splash to whatever the installer put there
mkdir -p /etc/default/grub.d
printf 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT quiet splash loglevel=3"\n' > /etc/default/grub.d/zenos-splash.cfg
if [ -f /etc/default/grub ]; then
  sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash loglevel=3"/' /etc/default/grub
fi
EOF
chmod +x config/hooks/live/0950-zenos-plymouth.hook.chroot
# no XEmbed tray bridge: it parks legacy tray icons (fcitx5's) in a window at the top-left corner, which shows as a
# black square whenever the desktop runs without compositing (virtual machines, some GPUs). ZENOS apps use the
# notifier tray (SNI); fcitx5 shows there too.
cat > config/hooks/live/0960-zenos-no-xembed.hook.chroot <<'EOF'
#!/bin/sh
set -e
systemctl --global mask plasma-xembedsniproxy.service
if [ -f /etc/xdg/autostart/xembedsniproxy.desktop ]; then
  grep -q '^Hidden=true' /etc/xdg/autostart/xembedsniproxy.desktop || echo 'Hidden=true' >> /etc/xdg/autostart/xembedsniproxy.desktop
fi
EOF
chmod +x config/hooks/live/0960-zenos-no-xembed.hook.chroot
mkdir -p config/includes.chroot/etc/calamares/modules
printf -- '---\nplymouth_theme: zenos\n' > config/includes.chroot/etc/calamares/modules/plymouthcfg.conf

lb build 2>&1 | tee build.log
ls -la "$W"/*.iso

# Releasing ZENOS

A release is a Debian package, a signed apt repository that PCs update from, and an installer image.

## 1. Check

```
python3 -W error::ResourceWarning -m unittest discover -s tests
packaging/check-secrets.sh          # no private keys, API keys, call-server secrets or real phone numbers
(cd apps/docs && npm audit --omit=dev --audit-level=high)   # and sheets, slides
```

Read `docs/THREAT_MODEL.md` again: every claim in the README must still match a row there.

## 1b. The software bill of materials

After the packages and the image are built (steps 2 and 4), write ZENOS's SBOM and publish it with the release:

```
tools/sbom.py --version <VER> --out build/ --name zenos-<VER>-preview-amd64 \
  --debs build/zenos_<VER>_amd64.deb build/zenos-grid_<VER>_amd64.deb --debian-packages build/iso/<image>.packages
```

It writes `.spdx.json` (SPDX 2.3) and `.cdx.json` (CycloneDX 1.6). Attach both to the release and put their SHA-256
in the release notes.

## 2. Build the package

```
VER=0.1.0~preview20261019 packaging/build-deb.sh      # -> build/zenos_<VER>_amd64.deb
```

Install it on a clean Debian 13 machine (or a fresh test image) and log in once before tagging: the desktop,
the security folders, the stop and release, and a call must work there, not only on the development machine.

## 3. Sign and publish the update repository

The archive signing key never lives on a build or development machine. Keep it on a hardware token or an
air-gapped computer, with a second copy in a safe. `gpg` only has to reach it while signing.

```
packaging/apt/build-repo.sh /srv/zenos-apt <KEY-ID> build/zenos_<VER>_amd64.deb
```

This writes `pool/`, `dists/trixie/{Release,InRelease,Release.gpg}`, the public keyring
`zenos-archive-keyring.gpg` and a sample `zenos.sources`. Serve the directory as static files over HTTPS.
On each PC, install the keyring to `/usr/share/keyrings/` and the sources file to `/etc/apt/sources.list.d/`;
from then on `apt` refuses any package list that is not signed by that key (tested: a changed package list and a
list signed by another key are both refused).

A version number is published once. To fix a release, raise the version; `build-repo.sh` does not replace a
package file that is already in the pool.

## 4. Build the installer image

```
sudo packaging/iso/build-iso.sh build/zenos_<VER>_amd64.deb
```

Boot it in a virtual machine (live session, then a Calamares install) before publishing, and publish its SHA-256
next to it.

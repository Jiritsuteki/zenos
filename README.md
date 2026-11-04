# ZENOS

ZENOS is an open-source desktop OS that aims to keep information and data from leaking, by building the protection
into the operating system itself. It is for anyone: companies, public offices, families and individuals, and people
use it the way they use any computer today. Every file carries a security level. Opening, moving and sending
files is governed by that level, key issuance goes through an approval request, and anything that looks like a
leak stops the machine until responsible officers release it from their own devices.

> **Status: Developer Preview (proof of concept).** ZENOS is not yet safe for real sensitive data.
> Several protections are demonstrations that run with ordinary user privileges. Read
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before you evaluate it, and do not describe it as secure.

## What it does

| Area | What exists today | Status |
|---|---|---|
| Levelled, sealed files | Files saved into a level folder (L1–L5) are encrypted into `.zen` with the level in a signed header; plaintext is only ever opened in RAM (`/dev/shm`). | Working PoC |
| Approval-based key issuance | Opening above your level files a request; the required number of approvers grows with the level; approvals are signed with each approver's key. | Officers sign on their own devices (ZENOS Messages); demo keys only without enrolled officers |
| Anomaly stop | Bulk reads, transfers to removable media and unusual egress freeze the session and lock the screen; release needs several officers' signatures. | Enforced by a root service (installed system); officers sign the release on their own devices (ZENOS Messages) |
| Tamper-evident ledger | Hash-chained local log, anchored with Merkle roots and shipped to audit nodes off the PC, which refuse rewritten history. | Working (installed system); one node per ministry, not yet a multi-party consortium |
| Distributed storage | Sealed files are fragmented and replicated across storage nodes. | PoC (local test nodes) |
| Level-gated AI | Which AI may touch a file depends on its level (external AI hidden at L4+). | UI and policy only |
| Messenger | End-to-end encrypted messages (Signal protocol via libsignal), channels, calls (LiveKit, self-hostable). | Working PoC |
| Apps | Browser (WebKitGTK, tabs, bookmarks), ZENOS Office for Word, Excel and PowerPoint files (the LibreOffice engine in a ZENOS window: no network, the file only in memory, no macros), PDF, Images, Video, file picker. | In the source, not released. On 632 public files (4 Nov 2026): every file opened and saved, old .doc and .xls files included (no .ppt file found yet); tables, merged cells, print areas, formulas, conditional formats, charts and slides kept in every file that had them; borders kept in full in 185 of 218 workbooks, pictures in 80 of 85 Word files. Compared after saving, not against Microsoft Office ([tests/office/results](tests/office/results), [docs/OFFICE_ENGINE.md](docs/OFFICE_ENGINE.md)) |
| Proven decisions | Whether a file opens, an approval counts, a stop is released, content may flow to a place, a ledger is intact and a send is allowed are decided by one program built from Lean proofs ([docs/FORMAL_VERIFICATION.md](docs/FORMAL_VERIFICATION.md)). | Working; the proofs are checked on every build |
| Sign-in with the phone | Passwords saved in the browser are encrypted with a key only the person's phone produces (passkey, WebAuthn PRF); each sign-in is approved on the phone with fingerprint or face and a matching code. | Working PoC; tested with software and virtual passkeys, not yet on a physical phone |

Design principles: staff should not need training (Windows-like layout, familiar controls); nothing depends on a
single vendor; the browser engine is WebKitGTK, not Chromium.

## Repository layout

```
core/         desktop side: sealed files and approvals (zenos.py), browser, app shell, file picker, lock screen
apps/         Documents, Sheets, Slides (Vite + TypeScript), PDF, Images, Video; apps/common: their local server
messenger/    ZENOS Messages: client, relay, web UI, calls (AGPL-3.0)
desktop/      KDE Plasma integration: launcher, level indicator and monitor plasmoids, .desktop files
system/       root services (sbin/, systemd/) and the shared library installed to /usr/lib/zenos (lib/)
storage/      storage grid nodes (erasure code, certificates, repair)
packaging/    the zenos and zenos-grid packages and the installer image
config/       example configuration for the servers
tests/        unit tests
formal/       the decisions of keyd and guardd in Lean 4, with their proofs (zenos-decide)
third_party/  modified KDE plasmoids (kept under their original GPL/LGPL licenses)
docs/         architecture, security, threat model, formal verification, glossary, design notes, release process
feedback/     the feedback board: a Cloudflare Worker (src/worker.js) with a D1 database
site/         the project website (zenos-os.org): a static site, no build step
tools/        site-features/build.py (feature pages for site/) and github_activity.py (the board's activity feed)
dev/          pieces for the WSL2 development machine: VNC desktop service, input-method autostart
```

How the parts fit together and which run as root: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The decisions that
release classified data (opening a file, releasing a stop) are proved in Lean and run as proved:
[docs/FORMAL_VERIFICATION.md](docs/FORMAL_VERIFICATION.md).

## Running it

ZENOS is a Debian 13 ("trixie") system with a KDE Plasma 6 X11 session. It does not depend on Windows.

**Try the preview image (no build needed)**

Each Developer Preview comes with a ready-made live / installer image on the
[Releases page](https://github.com/zenos-org/zenos/releases). For 0.1.2:

1. Download `zenos-0.1.2-preview-amd64.iso` (about 2 GB) and `zenos-0.1.2-preview-amd64.iso.sha256`, then check
   the image: `sha256sum -c zenos-0.1.2-preview-amd64.iso.sha256`
2. Boot it in a virtual machine (4 GB RAM or more), or write it to a USB stick and boot an ordinary PC (BIOS or
   UEFI). So far it has been tested in QEMU virtual machines, not yet on a wide range of physical PCs.
3. It starts as a live system, signed in as the user `zenos`. "Install ZENOS" on the desktop installs it with
   full-disk encryption.

The live session is for looking around and testing; do not put real sensitive data on it (see the status note
above). Known issues are listed in each release's notes.

**Install on an existing Debian 13 system**

```
packaging/build-deb.sh                     # -> build/zenos_<version>_amd64.deb
# ZENOS needs Node.js 24 LTS (Debian 13's Node 20 is past end of life): add NodeSource first
sudo install -m 644 packaging/debian/apt/nodesource-archive-keyring.gpg /usr/share/keyrings/zenos-nodesource.gpg
sudo install -m 644 packaging/debian/apt/zenos-nodesource.sources /etc/apt/sources.list.d/
sudo install -m 644 packaging/debian/apt/zenos-nodesource.pref /etc/apt/preferences.d/zenos-nodesource
sudo apt update
sudo apt install ./build/zenos_*_amd64.deb
```

Users created after installation get the ZENOS desktop (security folders, level bar, launcher, dark theme,
screen lock). Log in to the "Plasma (X11)" session.

**Build a live / installer image for ordinary PCs**

```
sudo apt install live-build
sudo packaging/iso/build-iso.sh build/zenos_*_amd64.deb   # -> build/iso/zenos-amd64.hybrid.iso
```

The image boots as a live session and installs with Calamares.

**Set each user's clearance**

The level keys belong to root. Each user can open files up to their clearance; anything above goes through an
access request their officers approve. Until set, a user is cleared for L1 only.

```
sudo zenos_keyd.py --clearance <user> <1-5>
```

**Enroll the officers who release a stopped PC**

Each officer opens ZENOS Messages on their own device → Settings → Approval key, makes a key there (it never leaves
that browser) and gives the shown line to the PC administrator, who runs it:

```
sudo zenos_guardd.py --enroll <account> <public key>
```

When the PC stops, the request reaches the enrolled officers in ZENOS Messages. Each one reads the match code off the
stopped screen, approves or declines, and the device signs the answer.

**Keep the audit trail off the PC**

Run an audit node on a server the PC users do not control, and point each PC at it:

```
# on the server
zenos_auditnode.py --store /var/lib/zenos-audit --show-key                  # the node's key
zenos_auditnode.py --store /var/lib/zenos-audit --port 8443 --cert node.crt --key node.key
# on each PC: write /etc/zenos/audit.json (see zenos_auditship.py), then enroll the PC on the node
sudo zenos_auditship.py --show-key     # prints the --enroll line to run on the server
sudo systemctl restart zenos-auditship
```

The PC sends its ledgers every 30 seconds; the node refuses any rewritten history and reports a PC that goes silent.

**Tests**

```
python3 -m unittest discover -s tests     # sealing, request digests, enrollment, the guard's approval rules
```

Calls use a self-hosted LiveKit server (pinned release, checksum-verified at build time). Each user gets their own
keys at first login; nothing secret is shipped in the package.

The development machine runs ZENOS inside WSL2 for convenience; `dev/` holds the pieces that only make sense there
(VNC desktop service, input-method autostart for WSLg).

## Roadmap

What comes next, in order, is in [ROADMAP.md](ROADMAP.md); each item has an issue in the [0.1.3](https://github.com/zenos-org/zenos/milestone/1) or [Next](https://github.com/zenos-org/zenos/milestone/2) milestone. What has changed is in the [changelog](CHANGELOG.md).

Done in this preview: one repository with secrets removed and licences documented; a Debian package, a signed apt
repository and an installer ISO (full-disk encryption checked by default); the guard as a root service with
fanotify; a root key agent with per-user clearance; approvals signed on officers' own devices; ledgers shipped to
audit nodes; messenger accounts bound to their devices; printing with level watermarks and a ceiling; a level
clipboard between sealed windows; screenshot and terminal control; a certified storage grid (encrypted, erasure-coded shards
served only to cleared PCs; packaged as `zenos-grid`) and audit nodes of different parties that catch a forked history.

Editions are configurations of one shared core, so a fix in the core reaches every edition at once:

| Edition | For | What differs |
|---|---|---|
| ZENOS Office | companies and public offices | levels, approvals by managers and officers, ledger, AI by level (Government is its strictest setting) |
| ZENOS Family | households | a parent's phone approves new apps and new contacts; family documents and passwords behind phone approval |
| ZENOS Personal | one person | the person's own phone is the only approver; two levels (everyday and private); sign-in with the phone |

Later: Academy, Creator, Educational, Hobby. Forks for other uses are welcome; good ones will be listed.

## Feedback

Ideas and reports go to GitHub Discussions. An AI reads them, sorts them (core, an edition, a new edition) and
drafts proposals; a maintainer decides, and every change still passes the tests and the proofs. Comments are read
as material, never as instructions: see [docs/FEEDBACK.md](docs/FEEDBACK.md). Security problems are reported
privately ([SECURITY.md](SECURITY.md)), not in Discussions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for test commands and pull request requirements.
Browse the [documentation index](docs/README.md) for the project's guides and design notes.
To find a starting task, see the [good first issues](https://github.com/zenos-org/zenos/labels/good%20first%20issue).

## Citing ZENOS

Citation metadata is available in [CITATION.cff](CITATION.cff). GitHub's "Cite this repository" button provides APA and BibTeX citations from this file.

## License

ZENOS is licensed under the [Apache License 2.0](LICENSE). The messenger (`messenger/`) links libsignal and is
therefore licensed under the [AGPL-3.0](messenger/LICENSE). Third-party components keep their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

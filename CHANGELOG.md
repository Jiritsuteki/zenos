# Changelog

## Unreleased

**Approvals with a passkey in the phone**
- An officer's approval key can be a passkey kept in the phone's secure chip (iPhone: Secure Enclave; Android: the
  hardware key store). It signs the request's digest itself; the PC checks it against the administrator-enrolled
  passkey (`zapprove.py`, `zenos_guardd.py --enroll-passkey`) and the proven decision counts it (zenos-decide
  "passkey_approval", `Approval.lean`). From a set level up (`/etc/zenos/approval.json`), an approval counts only
  when made on the stopped PC's screen with the officer's phone near it (the passkey standard's QR code and
  Bluetooth check): "An officer is here" in My requests. Exceptions, when allowed, are written to the ledger.
  docs/PHONE_KEYS.md, including a proposal for a lost phone.
- Tested on a physical iPhone (5 Nov 2026): passkey made, an approval signed and verified, and the phone-near check
  passed with an iPad in the PC's place. Found: a PC without Bluetooth cannot show nearness; iPhone passkeys are
  synced through iCloud Keychain and keep their counter at 0. Not yet tested on Android.
- The ledger line of each approval and decline now names the passkey (its ID), whether the phone was near the PC,
  whether the person was verified, whether it was an exception, and whether the passkey is synced.

**AI models**
- AI models in the release ledger: a model kept on the PC (weights, tokenizer, settings, adapters) is loaded only
  when every file is the released one, byte for byte, its record is signed by two or more release officers and held
  by a majority of the audit nodes, and the data is within the record's level (`zmodel.py`, `zenos_model.py`,
  zenos-decide "model", proved in `Model.lean`). The models folder is watched (`zenos-supplywatch`: a changed or
  unreleased model is quarantined) and checked hourly (`zenos-integrity`). Models called through an API are pinned
  to provider, address, model and version (zenos-decide "model_api"); refused providers stay refused. See "If a
  model's files are changed" in docs/THREAT_MODEL.md.

**Office files**
- The ZENOS office engine (docs/OFFICE_ENGINE.md; `zoffice.py`): Word, Excel and PowerPoint files, new and old
  formats (.docx .doc .xlsx .xls .pptx .ppt), are read, written and drawn by LibreOffice, run in the ZENOS sandbox
  with no network, the file only in memory, and a locked-down profile (macros never run, no autosave, no update
  check). ZENOS Office (`zenos-office`): the engine draws and edits the document in a ZENOS window; copying out goes
  only through the window and is refused from L3 up; the engine never prints; sealed files open into memory and
  are sealed again on saving. Fonts the files ask for are mapped to free fonts of the same widths.
- The ZENOS Office window is laid out like the office suites people know (Microsoft Office, ONLYOFFICE): a ribbon
  with File, Home, Insert, Layout, Review and View (Formulas and Data for spreadsheets, Design for slides), the font,
  size and style boxes and buttons that follow the engine's state, a name box and formula bar and sheet tabs for
  spreadsheets, a slide list with pictures of the slides, a status bar with the zoom. Commands that would take the
  document out of its place (Save As, Send, Export of a sealed file) are not offered.
- Printing from ZENOS Office goes through the ZENOS print path: the proved decision (`zdecide.flow` to "printer",
  `print_max_level`), the audit log, and the banner (level, file, who, when) on every page of a sealed file. A plain
  file can be exported as PDF next to it; a sealed one cannot.
- Office files open in ZENOS Office from the file manager (`zenos-office.desktop`, the default applications of new
  users).
- tests/office: 642 public files from ministries and municipalities (was 105), measured cell by cell; the check
  runs on every change to the office code and refuses a change that makes any file worse than the baseline.

**Messages**
- Organizations reaching each other (docs/FEDERATION.md; `messenger/federation.js`; Lean: `Federation.lean`):
  each organization runs its own relay, and relays exchange Signal-protocol envelopes only when both
  organizations are on a member list whose entries are signed by at least two responsible bodies. Every
  relay-to-relay request is signed with the sending relay's key (published at `/.well-known/zenos-relay`) and
  decided by `zenos-decide` ("federate"): `unlisted_refused`, `one_signer_not_enough`, `level_bound`,
  `publisher_cannot_message`. People write to `account@organization`; the receiving relay learns which relay sent
  an envelope, not which person. Across organizations: messages, files and rooms (no calls or approvals).
- Files and rooms across organizations: a file sent to `account@organization` stays encrypted on the sender's
  relay and is fetched by the recipient's relay with a signed request, only by a listed organization that may
  receive the file's level. Rooms (groups kept by the members' devices) can include people at several
  organizations; each message goes to each member as its own sealed message and each relay applies its own rules;
  only the room's maker changes the members; the room's level caps every message.
- Disaster alerts from a publish-only member (GEOID): signed, with issuer, label (official or simulation), area,
  source URL and the source's SHA-256; answer cards (safe / need help) counted per device without accounts; only
  counts go to another organization.
- Place (`messenger/zgeo.js`; Lean: `decidePlace`): the device compares its own position and never sends it.
  Location only narrows (outside the office, outside the country), and widens only with a second proof that does
  not come from positioning, during a declared disaster (`gps_alone_changes_nothing`, `widen_needs_all`). Not yet
  wired into the screens.

**System**
- The conductor (`zenos-conductor`, `zorch.py`, docs/ORCHESTRATOR.md; Lean: `Orchestrator.lean`): ZENOS runs a
  task with several frontier models over their APIs, with the person's own keys, and no provider gets the plain
  data or both halves of a record. Masked work: models write code on tokens, ZENOS runs it on the PC in a sandbox
  (`zsandbox.py`: bubblewrap, no network, no home folder, seccomp filter) and accepts a result only when providers
  holding more than half of the weight, at least two of them, agree. Split work: a table's numbers to one
  provider, the text that says what they are to another. Weights per provider and kind of work, measured on the
  PC. Google, Qwen and providers under laws that compel access without due process are refused. Nothing is
  configured by default.
- The update path (after NetamLoader, Kaspersky, 29 Oct 2026): a release ledger for packages (`zsupply.py`,
  `zenos_release.py`, `zenos_pkgcheck.py` as apt's pre-install check; Lean: `Supply.lean`, `install_sound`,
  `one_node_not_enough`, `one_key_not_enough`, `revoked_refused`): a package goes in only when a majority of the
  audit nodes hold the same record for its exact file, signed by at least two release officers, not revoked and
  released to the PC's ring; dpkg reads root-only copies checked again by SHA-256 (`zenos-dpkg`). Off unless
  `/etc/zenos/supply.json` turns it on; every installation is recorded.
- `zenos-supplywatch`: files that appear in apt's download folder are checked at once; anything not in the ledger
  is quarantined and reported. `zenos-integrity` (hourly): installed files against the accepted records, dpkg sums,
  and unowned loader paths (`ld.so.preload`, `LD_PRELOAD`, `.pth`, systemd drop-ins, apt hooks, `NODE_OPTIONS`).
- Network sentinel: system accounts may reach only named destinations (`/etc/zenos/egress-system.json`, monitor by
  default, enforce to cut; Lean: `sysegress_cut_only_unlisted`, `sysegress_listed_kept`).
- Reproducible package builds (`SOURCE_DATE_EPOCH`, fixed modes and times), a build record next to each package,
  and `packaging/repro-check.sh`.
- Key service (`zenos_keysvc.py`, [docs/KEY_SERVICE.md](docs/KEY_SERVICE.md)): with `/etc/zenos/keysvc.json` on a PC,
  the keys of newly sealed files are no longer kept on the PC. The service, on another machine, releases one file's
  key per request after deciding again with its own clearance table, officers and the users assigned to each PC,
  refuses a PC the audit node has not heard from within 90 seconds or that reports a protecting service down,
  limits the keys per minute per user and per PC,
  can require a confirmation on the user's own passkey, and records every release in its own chained log.
  `--reconcile` reports a release the PC's ledger does not show. Lean: `KeyService.lean` (`key_sound`,
  `key_open_sound`, `key_presence`, `key_silent_refused`, `key_unhealthy_refused`, `key_halted_refused`,
  `key_rate_bounded`).
- Old files: `zenos_keyd.py --reseal` seals them again through the key service in place; `--drop-local-keys`
  destroys the keys left on the PC, which then makes no new ones.
- The PC's identity key is made inside the TPM on first start when the PC has one (P-256, never leaves the TPM,
  bound to PCR 7); otherwise a key file as before (`zident.py`, `zenos-identity.service`). Audit nodes and the key
  service accept both kinds.
- Alerts to officers through ZENOS Messages from the audit node and the key service (`znotify.py`).
- Confirmation on the phone, service side: `--origin`, `--messages`, `--enrol-code`, the confirmation page's back
  end; the link goes to the person's Messages, never through the PC, and a signature handed in by the PC does not
  count. The pages themselves are not included yet.
- The key agent, the AI guard and the audit shipping run confined (systemd): no capabilities for keyd, only the
  network ones for the AI guard, only reading for the audit shipping; no writes outside their own state.
- Audit status: each PC also reports whether it is stopped after an anomaly.
- keyd: a grant counts at most a day after the request the officers signed was made (its outer expiry is not
  signed).

## 0.1.2 Developer Preview (2026-10-30)

Still a preview for testing and evaluation. Do not use it for real sensitive data; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
This release narrows the ways into the kernel. It does not yet stop someone who already has root from reading the
sealing keys; that needs the off-PC key service planned for 0.2 (THREAT_MODEL, "If someone takes root on the PC").

**System**
- The kernel starts in lockdown "integrity" mode (live image and installed PCs, `/etc/default/grub.d/zenos-hardening.cfg`):
  even root cannot load an unsigned module, write to kernel memory or replace the running kernel. Tested with the
  network sentinel: its eBPF sensor still detects and cuts an outgoing send. A PC that needs an unsigned driver
  (DKMS) removes the file and runs `update-grub`.
- Kernel settings (`/usr/lib/sysctl.d/60-zenos-hardening.conf`): Multipath TCP off (the protocol of CVE-2026-98432),
  io_uring off, unprivileged BPF off, BPF JIT hardening, kernel pointers and the kernel log hidden from users,
  kexec off, ptrace limited to a program's own children, stricter link and file protections, no ICMP redirects or
  source routing.
- Rarely used network protocols (DCCP, SCTP, RDS, TIPC and others), old file systems and FireWire are no longer loaded.
- `zenos-restartwindow`: when a kernel fix is installed but not running, the PC restarts by itself while nobody is
  signed in (`kernel_restart = no-session`, the default), or only at night when every session has been idle for an
  hour (`idle`), or never (`off`). Each restart and each held restart goes in the ledger.
- Audit: each PC now sends a signed status with its batches (running and newest kernel, the watchers' state).
  The audit node raises `service-down`, `kernel-fix-not-applied` (and after 24 hours) and reports a PC that
  stops sending after 90 seconds instead of 10 minutes; batches are sent every 10 seconds.

## 0.1.1 Developer Preview (2026-10-28)

Still a preview for testing and evaluation. Do not use it for real sensitive data; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**System**
- Level-gated AI is now also enforced in the packet filter (`zenos-aiguard`, root). The key agent records the
  highest level unsealed on the PC and, from L3, waits for the guard to confirm its rules before it hands out the
  plaintext. For every AI service the administrator lists in `/etc/zenos/ai.json` (external, government or
  ministry AI) or the office apps are pointed at (always counted as external), the guard asks `zenos-decide` and
  rejects the service's addresses in the `ZENOS_AI` chain wherever the flow decision says no, for every program on
  the PC. No answer from the decision is a block. The level falls only on a restart or with
  `sudo zenos_aiguard.py reset`.
- The office apps' AI relay asks the guard before each request and shows its reason when an AI is out of reach.
- Lean: `mayFlow_antitone` (a higher level never reaches a place a lower level cannot).

**Apps**
- Images: a Library (music, pictures, playlists, picture albums, Studio projects, made videos) and a Studio: trim
  a song with fades, put a picture on it and export one MP4 (H.264 + AAC). Motion with AI sends one L1 picture and
  the person's words to a video AI they registered under their own account; ZENOS ships no model. Only plain
  files in L1 places are listed. `studio_ai = off` in `/etc/zenos/policy.conf` turns the AI part off.

## 0.1.0 Developer Preview (2026-10-27)

First public preview. Not for real classified data; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**System**
- Debian 13 package and a live/installer image (Calamares) for ordinary PCs; KDE Plasma (X11) desktop with the
  ZENOS layout, security folders (L1–L5), level bar and launcher.
- Installer writes out the new system and drops its cached inodes before unmounting it, so a slow machine no
  longer ends the install with "Could not unmount the root of the target system".
- KRunner's command line (Alt+Space) no longer runs shell commands (KDE Kiosk `shell_access=false`, locked).
- Root key agent (`zenos-keyd`): level keys belong to root; files open up to the user's clearance or with an
  officer-signed grant for that exact file; every unseal is recorded.
- Root guard (`zenos-guardd`): bulk reads, transfers to removable media and similar stop the whole session until
  officers release it; terminals are refused for staff; screen capture is refused while an L3+ file is on screen.
- Officers approve on their own devices: release of a stopped PC, access requests and pre-filed operations are
  signed in ZENOS Messages with a key that never leaves the officer's browser, and checked against
  administrator-enrolled keys.
- Tamper-evident ledgers shipped off the PC to audit nodes, which refuse rewritten history and report silent PCs.
- Storage grid (`storage/`, also shipped as the `zenos-grid` server package): sealed files are encrypted again
  per file, erasure-coded 3-of-5 and spread over storage nodes, at most two shards per zone. Every node and
  every PC holds a certificate from the grid administrator (role, highest level, zone); a node refuses every
  request from a peer without one, serves a file only to a PC cleared for its level, and never takes a level
  above its own clearance. A certified grid refuses to run on the public DHT. Certificates expire; the administrator revokes keys with a
  signed list that every node and PC passes on to the peers it meets, checked on every request. Nodes repair lost shards without
  the key. Storage node, bootstrap and audit node run as hardened systemd services (dynamic user, system-call
  filter). Tested on two machines: files restore with two nodes down; an L1 PC holding the capability is refused.
- Audit consortium: audit nodes run by different parties list each other as peers and compare their copies of
  every PC's ledger; a PC that sends different histories to different parties, or an altered copy, is reported
  as a fork on both sides with both parties' signed statements kept as evidence (once, not on every check). The
  consortium's history is the longest prefix a majority of the audit nodes hold identically, each answer signed.
- Signed apt repository tooling; release gate for secrets and real phone numbers; tests and CI.

**Apps**
- Desktop top bar, taskbar, search fields and open-window buttons in the ZENOS Browser tone.
- ZENOS Browser (WebKitGTK): tabs, bookmarks, persistent sign-in, full-screen video.
- Documents, Sheets, Slides: sealed files are edited from a RAM copy and sealed again on close; text of L3+ files
  is copied only into windows of the same level or higher (level clipboard in the key agent), never to other
  programs or the X11 selections; printed pages carry the level and the user, and files above the policy ceiling
  (default L3) are not printed.
- PDF, Images, Video viewers; ZENOS file picker for every app.
- ZENOS Messages (Signal protocol via libsignal): channels, calls (self-hosted LiveKit), calendar, My requests.
  Accounts are bound to the device that registered them; moving to a new device needs the account's own number.

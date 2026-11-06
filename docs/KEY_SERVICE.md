# The key service

Status: in 0.2.0 (the `zenos-grid` package), tested. Developer Preview: do not use it for real sensitive data.

## Why

Until 0.1.2 the keys that open sealed files are root-owned files on the PC. Whoever takes root on the PC, through a
kernel hole for instance, can read every file sealed there. The key service moves those keys off the PC.

## How it works

- `zenos_keysvc.py` runs on a machine the PC's users and administrator do not control, next to the audit node.
  It holds one master key per level. A file's key is derived from the master key of its level and the file's id
  (HKDF-SHA256); it is never stored, on the PC or on the service.
- Sealing: keyd asks the service for a new file key (the service checks the user's clearance as it holds it),
  encrypts the file, and tells the service the finished file's SHA-256. The file header carries `"fmt": "zks1"` and
  the file id.
- Opening: keyd first decides as before, then asks the service. The service decides again with its own facts
  (`decideKey`, proved in `formal/ZenosFormal/KeyService.lean`):
  - the PC is enrolled and signed the request with its identity key; the request is recent and new;
  - the file was sealed on this PC (as before, a sealed file opens only on the PC that sealed it), and the user is
    assigned to this PC on the service (`--assign`);
  - the audit node heard from the PC within 90 seconds, and its last signed status shows the key agent, guard,
    AI guard, network sentinel and firewall running and no stop (root on the PC can fake that status; what it
    cannot fake is the shipping having stopped);
  - fewer than 30 keys for this PC and user, and 60 for this PC, in the last minute (`--rate-max`,
    `--machine-rate-max`, `--rate-window`); counting and deciding are one step per PC;
  - from `--presence-from` up, the user confirmed this file on their own passkey (a signature over a challenge the
    service issued for this PC, user and file, used once);
  - the user's clearance as the service holds it, or a grant signed by officers enrolled on the service, naming the
    file by the SHA-256 the service recorded at sealing (named once, within 10 minutes, a digest no other file
    has). A grant counts at most a day after the request the officers signed was made, whatever its outer
    expiry says.
- The key travels to keyd wrapped for that request only (X25519, HKDF, AES-256-GCM); the answer is signed with the
  service's key, which the PC knows from `/etc/zenos/keysvc.json`. keyd drops the key after decrypting.
- Every issue, release and refusal goes into the service's own hash-chained log (`releases.jsonl`) at once.
  `--reconcile` (also every 5 minutes while serving) compares it with the PCs' ledgers held by the audit node and
  raises `release-not-in-pc-ledger` for a key released for a file the PC never recorded opening.

## What it does not do yet

- The presence level is off by default (`--presence-from 6`) until the confirmation pages ship. The service side
  is done: `--origin` (the address phones reach the service at), `--messages USER NAME.12` (the person's ZENOS
  Messages account), `--enrol-code USER [--send]` (a one-time address where the person's phone makes a passkey for
  the service), and `/c/<secret>` (the page that shows the file as the service recorded it and takes the passkey
  signature over that secret). When a file needs a confirmation, the service sends the link straight to the
  person's Messages; the PC only learns that it was sent. A signature handed in by the PC never counts: whoever
  controls the PC controls its WebAuthn client, which writes the origin and challenge the phone signs.
- On a PC without a TPM the identity key is a root-owned file. With it, root can ask for files that the users
  assigned to this PC are cleared for, within the rate limits and with every release recorded on the service. With
  a TPM the key cannot leave the PC, but root on that PC can still ask the TPM to use it.

## Moving old files

    sudo zenos_keyd.py --reseal-dry /home /srv/shared     the sealed files whose key is still on this PC
    sudo zenos_keyd.py --reseal /home /srv/shared         seal them again through the key service, in place
    sudo zenos_keyd.py --drop-local-keys --yes            destroy the keys left on this PC (only after a --reseal
                                                          run that left nothing)

Each file keeps its name, owner, mode, author and level. Paths are opened without following symbolic links, so a
user who swaps a folder for a link while it runs cannot redirect the writes. Files on USB sticks, backups or other
PCs that were not sealed again cannot be opened once the keys are destroyed. Grants for the old files name their old digest and no
longer apply. After `--drop-local-keys` the PC makes no new level key, even after a restart.

## The PC's identity

`zenos-identity.service` makes the identity once, on first start: inside the TPM when the PC has one (a P-256 key
that never leaves the TPM, usable only with the same PCR 7, the Secure Boot state), otherwise an Ed25519 key file.
`zenos_identity.py --show` prints the key to enroll on the audit nodes and the key service;
`zenos_identity.py --setup-tpm` moves an existing PC to the TPM (enroll the new key again).
Tested with a software TPM (swtpm), not yet on PC hardware. PCR 7 changes when the Secure Boot settings or the
firmware's list of revoked signatures (dbx) change: the key then stops working, the PC stops reporting, the officers
are alerted, and the administrator makes a new key (`--setup-tpm`) and enrolls it again.

## Alerts

`--notify-url` and `--notify-to` (the audit node: `"notify"` in its config) send alerts as ZENOS Messages from the
server's own Messages account to the named officers: a PC gone silent, a key refused to a silent, unhealthy or
stopped PC, a release the PC's ledger does not show, a rewritten ledger. Every alert is also in `alerts.jsonl`.

## Setting it up

On the service machine (behind TLS):

    zenos_keysvc.py --store /var/lib/zenos-keys --audit-store /var/lib/zenos-audit --port 8444 --cert C --key K
    zenos_keysvc.py --store /var/lib/zenos-keys --show-key
    zenos_keysvc.py --store /var/lib/zenos-keys --enroll MACHINE PUBKEY      (from `zenos_auditship.py --show-key`)
    zenos_keysvc.py --store /var/lib/zenos-keys --assign MACHINE USER
    zenos_keysvc.py --store /var/lib/zenos-keys --clearance USER N
    zenos_keysvc.py --store /var/lib/zenos-keys --approver NAME PUBKEY

On the PC, `/etc/zenos/keysvc.json`:

    {"url": "https://keys.example.go.jp:8444", "pub": "<the --show-key output>"}

With that file present, keyd seals every new file through the service and refuses to seal when the service cannot
be reached or the file cannot be used, rather than falling back to a key on the PC.

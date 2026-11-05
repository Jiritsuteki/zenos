# ZENOS grid servers

The `zenos-grid` package holds the servers a ZENOS grid needs outside the PCs. Each party
(a ministry, an agency, an independent audit board) runs its own set on machines the PC users do not
control. Only the key service holds keys that open files; it releases them one file at a time.

| Service | What it does | Config file |
|---|---|---|
| `zenos-grid-bootstrap` | the closed network's own entry point, so nothing touches the public internet | `/etc/zenos/grid-bootstrap.json` |
| `zenos-storage-node` | keeps encrypted, erasure-coded shards; serves them only to certified PCs cleared for the level | `/etc/zenos/storage-node.json` |
| `zenos-auditnode` | keeps a copy of every enrolled PC's ledger and compares it with the other parties' audit nodes | `/etc/zenos/auditnode.json` |
| `zenos-datapeer` | a key peer or a storage peer of ZENOS Data: server programs' records with no plaintext and no key at rest ([docs/DATA_STORE.md](../../docs/DATA_STORE.md)) | `/etc/zenos/datapeer.env` and `/etc/zenos/datapeer.json` |
| `zenos-keysvc` | holds the keys of sealed files and releases one file's key at a time to a healthy PC ([docs/KEY_SERVICE.md](../../docs/KEY_SERVICE.md)) | `/etc/zenos/keysvc-server.env` |

Each service starts only once its config file exists. Examples are in `/usr/share/doc/zenos-grid/examples`.

## The grid administrator

The administrator key signs every certificate. Create it on a machine that is not part of the grid
and keep it there:

```
node /usr/share/zenos-grid/storage/bin/zenos-store.js admin-init --out admin.json
```

The public key it prints goes into every node's and every PC's config (`admin`).

## A storage node

1. Write `/etc/zenos/storage-node.json` (see `storage-node.example.json`; one zone per site).
2. `sudo systemctl start zenos-storage-node` and read the node key: `journalctl -u zenos-storage-node | grep key`.
3. On the administrator's machine, certify it, with the highest level this site may hold:
   `zenos-store.js certify --admin-file admin.json --key <node key> --role node --clearance L4 --zone "Site A" --out cert.json`
4. Copy `cert.json` to `/etc/zenos/storage-node-cert.json` and `sudo systemctl restart zenos-storage-node`.

A node without a valid certificate starts but holds nothing. A node never takes a file above its own
clearance, whoever asks. Files are spread 3-of-5 with at most two shards per zone, so a whole site can
be lost and every file still restores.

## A ZENOS Data peer

1. Write `/etc/zenos/datapeer.env` (`ROLE=key` or `ROLE=store`, `PORT`) and `/etc/zenos/datapeer.json` (the
   enrolled servers with their public keys and purposes, the sign-in services, clearances, limits and the audit
   node; see `datapeer.example.json`), and put a TLS certificate in `/etc/zenos/datapeer.crt` and `.key`.
2. `sudo systemctl start zenos-datapeer`. For a key peer, give its public key to the servers' administrators:
   `sudo python3 /usr/share/zenos-grid/audit/zenos_datapeer.py --state /var/lib/private/zenos-data --pub`.
3. Run the key peers at different parties (k of n, n at least 3, k at least 2). A changed `datapeer.json` takes
   effect after `systemctl restart zenos-datapeer`.

## A ZENOS PC

1. Write `/etc/zenos/grid.json` on the PC (see `grid.example.json`).
2. As the desktop user: `zenos_p2p.py enroll` prints the PC's storage key.
3. The administrator certifies it with `--role client` and the user's clearance.
4. `zenos_p2p.py install-cert cert.json`. From then on sealed files are also stored on the grid.

A PC without a certificate gets nothing from the nodes, not even the list of other nodes. A PC
certified for L2 cannot read an L3 file's shards even if it holds the file's capability.

## Expiry and revocation

Certificates are valid for a year (`certify --days N` to change). To take a key out of the grid at once:

```
zenos-store.js revoke --admin-file admin.json --keys <key>[,<key>...] --previous revocations.json --out revocations.json
```

Give the new list to any one node or PC (`/etc/zenos/grid-revocations.json`, or `--revocations`); every node and
PC passes the newest list it holds to each peer it meets, and checks it on every request.

## Audit nodes: the consortium

Every PC ships its ledgers to every audit node it is enrolled on (`/etc/zenos/audit.json` on the PC).
Each audit node accepts only records that continue the history it already holds, and signs what it
holds. The audit nodes of the different parties list each other as `peers` and compare their copies
every `check_seconds`. The shorter copy must be a prefix of the longer one; if not, it is a fork: the PC
sent different histories to different parties, or one party's copy was changed. Both signed statements
are written to `forks.jsonl`, so neither party can later deny what it held.

```
zenos_auditnode.py --config /etc/zenos/auditnode.json --store /var/lib/zenos-audit --check-peers
```

prints the comparison with every peer now, and

```
zenos_auditnode.py --config /etc/zenos/auditnode.json --store /var/lib/zenos-audit --consortium-status MACHINE CHAIN
```

prints the history the consortium stands behind: the longest prefix a majority of the audit nodes hold
identically, and which members agree, are behind, dissent or cannot be reached.

The TLS certificate and key for the audit node stay in `/etc/zenos/auditnode.crt` and `.key`
(root only); systemd hands the service a copy.

## Not yet

- The administrator key on a hardware token.
- Issuing the per-file capability through the request-and-approval flow instead of keeping it in the
  PC's sealed index.

# ZENOS Data: a server's records with no plaintext and no key at rest

Status: in 0.2.0 (the `zenos-grid` package and `system/lib/zdata.py`). Developer Preview: tested, not audited.

## Why

Most leaks of personal data are not leaks from a PC. They are copies of a server's database: a backup taken, an
administrator account taken over, a cloud bucket left open. Calling an identity service's API at sign-in does not
change that, because the records the service then keeps are still plain rows in its own database. The way out is
to change how the data is kept: a server that never holds its records in plain text and never holds the key to
them.

ZENOS already keeps files that way on the PC (sealed, fragmented, the key released per opening). ZENOS Data does the
same for a server program's records.

## How it works

For each record the server program writes (`zdata.Store.put`):

1. The record is encrypted with its own random key (AES-256-GCM). Its id, table and level are bound to it, so a
   copy moved to another id, table or level does not decrypt.
2. The encrypted record is placed on several storage peers (`zenos_datapeer.py --role store`). They keep only
   ciphertext, accept writes only from enrolled servers, and give a record back only to the server that wrote it.
   One copy is enough to read; a changed copy fails to decrypt and the next one is used.
3. The record's key is split into n shares, any k of which make the key (Shamir's scheme over GF(2^8)). Each
   share is sealed to one key peer (`--role key`), with the record's id, table and level. The sealed shares travel
   with the record. The key peers store no shares, and the server stores no key.

To read a record (`zdata.Store.get`), the server signs a request that names the record, the person it is for and
the purpose, with a one-time key for the answer, and sends it to the key peers with that peer's sealed share.
Each key peer decides on its own facts, with the proven decision (zenos-decide "share",
`formal/ZenosFormal/DataStore.lean`):

- the server is enrolled with this peer, signed this request, the request is recent and not seen before;
- the audit node heard from the server recently (a server that stopped shipping its ledger gets nothing);
- the person is signed in: a token of the organization's sign-in service, whose public key the peer enrolled and
  checks itself. The server cannot vouch for a person on its own;
- the purpose is registered for this server and this table (`casework` yes, `marketing` no);
- the person's clearance, as this peer holds it, covers the record's level, or a grant on the peer names the record;
- not too many shares for this person, and for this server, within the minute.

Only then does the peer open its share, and only if the share was sealed for the same record, table and level the
request names (a server that names a lower level cannot open it). It seals the share to the request's one-time key.
Every answer, released or refused, goes into the peer's own hash-chained ledger. With k shares the server makes
the key in memory, decrypts, and drops the key.

### Finding records

A field can be indexed with a blind index (`Store.blind`): an HMAC of the value under a key per table. That key is
itself a ZENOS Data record, read through the key peers when the server starts and kept only in memory. The index
shows which records share a value, not the value. Ranges, sorting and full-text search over protected fields are
not possible this way; those fields are read and filtered after release. A field that does not identify anyone
(a status, a date bucket) can stay a plain column next to the record id.

## What it protects against

| Someone who | gets |
|---|---|
| copies the server's disk, its database or its backups | record ids, blind index values, nothing readable |
| copies every storage peer | ciphertext and sealed shares; no key peer's secret, so nothing readable |
| takes over one key peer (k ≥ 2) | that peer's shares: not enough for any key (`one_peer_not_enough`) |
| takes over the running server | only what the key peers release while they hold it: records within the clearance of persons actually signed in, for registered purposes, at the rate limits; every release is in k ledgers they do not control |
| asks for a record above a person's clearance | nothing from any peer (`above_clearance_no_record`) |

## What it does not do

- A server program that is taken over while people are signed in can read what those people may read, during that
  time. The ledgers show it; they do not prevent it.
- Key peers run by parties that collude up to the threshold can make any key. Put them with different
  organizations (an agency, an audit body, a second agency).
- The splitting (Shamir over GF(2^8)), AES-256-GCM, X25519 and Ed25519 are trusted, not proved. The decision is
  proved; the facts it is given are checked in Python.
- There is no query language: the server program asks for records by id or by blind index.
- Availability: with n key peers and threshold k, up to n − k key peers may be down. Storage peers: any one.

## Running it

Key and storage peers are in the `zenos-grid` package (`zenos-datapeer.service`, one role per machine). The peer's
settings (`/etc/zenos/datapeer.json`, example in `/usr/share/doc/zenos-grid/examples`) list the enrolled servers
and their purposes, the sign-in services, the clearances, grants, limits and the audit node. A server program uses
`zdata.py`:

```python
import zdata
db = zdata.Store("cases", server_key,
                 [zdata.http_peer("agency-a", "https://k1.example", K1_PUB),
                  zdata.http_peer("audit-body", "https://k2.example", K2_PUB),
                  zdata.http_peer("agency-b", "https://k3.example", K3_PUB)], 2,
                 [zdata.http_peer("s1", "https://s1.example"), zdata.http_peer("s2", "https://s2.example")])
rid = db.put("cases", {"name": "...", "case": "..."}, 3)
case = db.get(rid, person, token_from_sign_in, "casework")
```

Tests: `tests/test_data_store.py` (three key peers, threshold two, three storage peers; also over HTTP).

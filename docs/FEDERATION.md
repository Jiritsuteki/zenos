# ZENOS Messages across organizations

Status: in the source, not released. It extends ZENOS Messages (messenger/), it is not a separate product.

Built and tested (tests/messenger_federation.js, tests/messenger_federation_clients.js, tests/test_federation.py):

- relays of two organizations exchanging Signal-protocol envelopes through the signed member list (federation,
  section 2), with the proven decision `decideFederate`;
- `account@organization` addresses in the client: a message and its reply between two clients at two
  organizations, end to end;
- files across organizations: the file is encrypted on the sender's device (AES-256-GCM, the key only inside the
  sealed message), the ciphertext stays on the sender's relay with the level the sender gave it, and the
  recipient's relay fetches it with a signed request (`/fed/blob`, `/fed/blobs`); the sender's relay gives it only
  to a listed organization that may receive that level (decided by `decideFederate`, kind "message");
- rooms: groups that can include people at several organizations, kept by the members' devices rather than by a
  relay. The person who makes a room lists the members (`account` here, `account@organization` elsewhere); every
  message carries the room (id, name, level, members) and goes to each member as its own sealed message, so each
  relay applies its own rules to each member. Only the person who made the room changes who is in it; the room's
  level caps every message in it;
- disaster alerts from a publish-only member, answer cards and counts (section 4);
- the place decision `decidePlace` and the device-side geometry (section 7), not yet wired into the screens.

Not built yet: the Cloudflare backend for the relay (section 1), the Debian package for an own-server relay, the
phone without a ZENOS PC (section 5), area channels, archive copies (section 6).

## Goal

Every organization (a municipality, a ministry, a company) runs its own channel for ZENOS Messages and chooses where
it runs. Organizations that are on a shared, signed list reach each other directly. There is no central server
for messages: if one organization's channel stops, the others stay connected. Messages stay end-to-end encrypted
with the Signal protocol as today, and who talks to whom is kept to the organizations involved.

## What exists today (messenger/)

- `client.js`: one person's device. libsignal (Signal's own library: X3DH/PQXDH and the Double Ratchet), levels on
  every message, channels with threads and mentions, approvals, calls (LiveKit), Web Push to the person's phone.
- `relay.js`: the relay a ministry runs. It stores public key bundles and queues encrypted envelopes; random
  mailboxes so it does not learn who sent a message (stage 1); encrypted attachments (`/blobs`, the key never
  reaches it); 14-day retention; phone-number accounts; device binding; an audit log of metadata, never content.
- `relays.json`: the client can already point at a chosen relay.

The plan keeps the relay's HTTP API and the client's protocol, and changes where the relay runs and how relays reach
each other.

## 1. Each organization's channel, where it chooses

One relay core, two ways to run it, the same API:

| | Cloudflare (default) | Own server |
|---|---|---|
| Mailboxes, key bundles, channels | Durable Objects (one per mailbox; WebSocket with hibernation for new-message notices) | SQLite |
| Attachments | R2 (encrypted blobs, deleted after collection or retention) | S3-compatible storage on the organization's own hardware |
| Who to whom, when | visible to Cloudflare | stays inside the organization |
| Set up | one script with the organization's own Cloudflare account | a Debian package (`zenos-relay`) |

The organization's IT staff choose. Private companies will mostly take the default; governments and anyone who
handles sensitive metadata can keep everything on their own hardware. A relay can move from one to the other
without users noticing (export and import of mailboxes and channel state).

Cost on Cloudflare's published prices (Workers Paid, Durable Objects, R2, Realtime; 1 USD = 150 JPY assumed):
an organization of 3,000 staff sending 100 messages a day each, 10% with pictures, 60 voice minutes a month
relayed: about 6 USD a month including the 5 USD plan. On the free plan, about 300 to 500 such staff fit in the
daily request allowance. At a national scale of 100 million users (25 messages a day, 5 video minutes a month,
20% of calls relayed) the delivery itself would be about 245,000 USD a month; staffing, abuse handling and phone
verification are not in that figure. These are estimates from assumed usage, not measurements.

## 2. Organizations reaching each other (federation)

- Each relay has its own signing key, published under the organization's domain
  (`https://<domain>/.well-known/zenos-relay`), like DKIM for mail. Relays sign every request to each other.
- A message for someone in another organization goes from the sender's device to its own relay, and from there to
  the recipient's relay, which puts it in the recipient's mailbox. The content stays a Signal-protocol ciphertext
  end to end; key bundles of people in other organizations are fetched the same way.
- The list of member organizations is signed by several responsible bodies (for example a ministry, the prefecture
  and the joining municipality): an entry counts only with k of n signatures, and the list is kept in the audit
  nodes' ledgers, so it cannot be rewritten quietly. Adding a municipality is one signed entry; it then reaches
  every member without pairwise contracts.
- Whether a message may go to another organization is decided by a proven function (Lean, `decideFederate`): the
  recipient organization is on the list, the message's level is one that organization may receive, the sending
  relay's signature verifies. Planned theorems: `unlisted_refused`, `level_bound`, `one_signer_not_enough` (one
  stolen signing key does not add an organization; the same shape as `one_key_not_enough` for releases).
- Each relay records cross-organization deliveries (metadata only) in its own audit ledger.
- Groups across organizations are rooms kept by the members' devices (one sealed message per member, as Signal
  groups began); the design keeps the door open to MLS (RFC 9420) for large groups and to IETF MIMI for
  interoperability with other messengers.

## 3. Keeping who-to-whom small

- Random mailboxes and sender-hidden delivery (stage 1, already in `relay.js`) apply between relays too: the
  receiving relay learns which relay sent an envelope, not which person.
- Post-quantum key agreement (PQXDH, already in libsignal) on every new session, so ciphertext captured today is not
  readable later.
- Organizations that must not show metadata to anyone outside run their relay on their own hardware.

## 4. Disaster information from GEOID

GEOID (a separate project that gathers disaster information, with geofencing) joins the federation as a
publish-only member.

- Alerts are pushed, signed, to each organization's relay, with the fields of CAP (Common Alerting Protocol): kind,
  area (polygons or municipality codes), severity, issuer, time, expiry, source URL and SHA-256 of the source.
- Each device reads the alerts from its own organization's relay and decides on the device whether it is in the
  area; neither the relay nor GEOID is told who is where.
- Issuers are shown as they are: warnings from the Japan Meteorological Agency as such; GEOID's own computed
  output labelled as a simulation, not a forecast.
- Alert cards carry answer buttons (safe / need help). Answers stay in the organization's relay; only counts go on
  to the prefecture or ministry over the federation.
- Area channels (GeoID/2's geo-guard): only people verified inside an area can post, which keeps posts from outside
  a disaster area out of it.

## 5. The client on phones

- ZENOS Messages becomes a mobile-first web app (manifest and service worker exist today).
- Android and desktop Chrome/Edge: an "Install ZENOS Messages" button on the page uses the browser's install prompt
  (one confirmation).
- iPhone: pages cannot trigger "Add to Home Screen". Staff phones get the icon from the organization's device
  management (MDM web clip); residents see an illustrated guide (Share, then Add to Home Screen). Web Push works
  on iPhone once the app is on the Home Screen. A native iPhone app can wrap the same code later.
- Open engineering question: libsignal is a native library (Node/Android/iOS); today the crypto runs in `client.js`
  on the PC. For phones the Signal protocol must run on the phone: a WebAssembly build of libsignal is the
  candidate (Signal does not publish one as far as checked; a research port from Inria exists but predates the
  post-quantum key agreement). Today a phone works as the screen of the person's ZENOS PC, which does the
  encryption; this covers staff, not residents without a ZENOS PC. Keys on a web
  page are kept in the browser's storage, weaker than a phone's secure element; L3 and above stay on ZENOS devices
  until a native app exists.

## 6. Public records

Government messages may have to be kept as records. Delete-after-delivery on the relay stays; where an
organization must keep records, its own archive copy is encrypted to an organization key and kept on its side. The
retention rules are to be checked before this is built.

## 7. Place (geofencing)

A device's own position can be faked, so place is used to narrow what a person may do, and widens it only with a
second proof that does not come from positioning: a beacon or NFC tag in the building, the office network, a
check-in at a cordon. The device compares its position itself (`messenger/zgeo.js`) and never sends it; only the
person's answer (safe / need help) leaves the device, and it is counted without accounts.

Uses that narrow (a faked position gains nothing):

- L3 and above open only inside the office; outside, the subject line only.
- Outside the country, L3 and above close on the device (devices inspected at a border).
- A meeting-room channel is readable only in the room.
- A device that leaves the allowed areas locks.
- Impossible travel (two places too far apart for the time between) asks for sign-in again.

Uses that widen (with the second proof, while a disaster is declared):

- Emergency sharing: inside the disaster area, while the disaster is declared, information of people who need
  help is shared with the rescue teams; it closes when the disaster ends or the person leaves the area.
- Responders who check in at a cordon join the incident channel and leave it when they leave.
- A check-in at a shelter joins the shelter's channel; only head counts go up.

From GEOID's geo-guard (posting only from inside an area): a damage report carries a proof that it was taken there;
in public channels, posts from outside the area are labelled as such rather than blocked.

Proved (`decidePlace`): `abroad_closes`, `no_widen_without_emergency`, `widen_needs_all`, `zone_needs_proof`,
`gps_alone_changes_nothing`.

## Steps

1. Federation between two organizations: relay keys, signed member list, `decideFederate` with its proofs, audit.
   Built.
2. GEOID alerts into relays, answer cards and counts. Built (alerts are matched to the area on the device).
3. Place: `decidePlace` and the device geometry built; the screens next (Figma first).
4. Relay backends: Cloudflare (Durable Objects, R2) and an own-server package, the existing tests passing on both.
5. The Signal protocol in the phone's browser (a WebAssembly build of libsignal), the mobile web app, install
   button and iPhone guide.
6. Area channels with geo-guard.

## Weak spots

- Metadata on Cloudflare (who to whom, when) for organizations on the default; the own-server option is the answer.
- The list of member organizations is a shared point; k-of-n signing and the ledger keep any one body from changing
  it alone.
- Federation brings spam and impersonation risk; only listed organizations connect.
- Municipal networks that cannot reach the internet (three-tier separation, LGWAN) and ISMAP coverage of the
  services used are institutional questions to settle first.
- The national-scale figure is delivery cost only, from assumed usage.

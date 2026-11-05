# Formal verification of the ZENOS decisions

The decisions that decide whether classified data is released or leaves are written in Lean 4 (`formal/`) with
machine-checked proofs of what they guarantee. The services do not reimplement them: keyd, guardd, the apps, the
ledger check, the audit nodes, the pre-send check and the network sentinel run `zenos-decide`, the program built from
the same Lean definitions, and follow its answer (`system/lib/zdecide.py`). Anything unexpected from it (missing,
timeout, unreadable answer) is a refusal; for the network sentinel, a cut.

## What is proved

`formal/ZenosFormal/Proofs.lean`, checked by Lean's kernel on every build. `formal/ZenosFormal/Axioms.lean` fails the
build unless the theorems rest only on Lean's standard axioms (`propext`, `Quot.sound`): no `sorry`, no added axiom.

| Theorem | Statement |
|---|---|
| `open_sound` | keyd hands out a file's plaintext only if the PC is not stopped, the level is 1–5, and either the user's clearance covers the level or a grant does: for this user, this exact file (SHA-256), a level at least the file's, not expired, an access grant (not a release or plan), whose stored digest matches its signed contents, signed by at least the number of officers the level needs. |
| `grant_needs_officer` | Opening above one's clearance needs at least one enrolled officer, other than the user, whose signature verified. |
| `approvers_not_requester`, `approvers_nodup` | The requester's own approval never counts, and no officer counts twice. |
| `release_sound` | A stop is released only for a pending request signed by at least `required`, and at least one, distinct enrolled officers other than the stopped user. |
| `run_open_not_halted` | Over any sequence of anomalies, officers' answers, enforcement checks and open requests, every file keyd opened was opened while the PC was not stopped. |
| `run_release` | Over any such sequence, the PC goes from stopped to running only through a release check that held. |

### Where content may go (`Flow.lean`)

One decision for every place a copy of a file's content can reach: level folders (Save As), level windows (paste),
the system clipboard, the printer, external AI, the government's AI, the ministry's AI. The apps (zenos_app,
zenos-webview) and keyd's clipboard ask it; the launcher's AI table is checked against it by a test.

| Theorem | Statement |
|---|---|
| `no_write_down` | Content of a level reaches only folders and windows of that level or higher (public content excepted). |
| `flow_within_cap` | No place ever holds more than its ceiling: clipboard L2, printer L4, external AI L2, government AI L3, whatever the configuration says. |
| `mayFlow_antitone` | A higher level never reaches a place a lower level cannot. The AI guard relies on it: it goes by the highest level opened on the PC, so it may block more than a request needed, never less. |
| `l3_stays_inside` | L3 and above never reach the system clipboard or an AI outside the government. |
| `l4_ministry_ai_only` | L4 and above reach no AI but the ministry's own. |
| `l5_stays` | Specially Designated Secrets (L5) are never printed and leave the L5 places only for the ministry's AI. |
| `carry_monotone` | Moving a copy hop by hop never lowers its level. |

### The tamper-evident ledger (`Ledger.lean`)

| Theorem | Statement |
|---|---|
| `chainCheck_ok` | The check accepts exactly the chains whose links and hashes hold. |
| `accept_extends` | An audit node's copy stays an intact chain and only grows: a batch is accepted only if it continues it. |
| `history_unique` | For any hash function without collisions, two histories that pass the check and end at the same hash are the same history. The audit nodes hold that hash, so an altered past cannot be shown to them. |

### What leaves the PC (`Egress.lean`)

| Theorem | Statement |
|---|---|
| `send_sound` | Nothing unsealed or tampered passes the pre-send check, and nothing over the size line without an approved transfer. |
| `egress_cut_iff` | The network sentinel cuts a destination exactly when it is not approved, not already cut, and the bytes sent to it within the window reach the threshold. |
| `egress_cut_stays` | A cut destination stays cut. |
| `prune_prune` | Keeping only the recent part of the window loses nothing, as long as the clock does not go backwards. |

### Officers' signatures (`Protocol.lean`)

Signatures are modelled as unforgeable and the digest as collision-free (hypotheses of the theorems, the standard
assumptions about Ed25519 and SHA-256).

| Theorem | Statement |
|---|---|
| `approve_ne_decline` | An approval (32-byte digest) can never be read as a decline (`"decline:"` + digest) or the reverse. |
| `counted_was_signed_for` | A signature that counts for a request was made for exactly that request: same id, same stop. |
| `release_counts_only_this_stop` | A stop is released only with a signature, by an enrolled officer other than the stopped user, over the request that names this stop: approvals cannot be replayed from another request or another stop. |

Levels need 0, 1, 1, 2, 3 approvals (L1–L5, `required`, the same table as `zformat.REQUIRED`; a test checks they
agree). A release needs more officers than opening the file did (at least 2), capped by the enrolled officers other
than the stopped user; with none, it cannot be met and the PC stays stopped.

### Sign-in with the phone (`Cred.lean`)

| Theorem | Statement |
|---|---|
| `cred_sound` | A saved password is released only to the page whose origin, as the browser verified it, is the one it was saved for, over verified TLS, within the time limit, after a phone registered to this person signed this very request with the person verified on the phone (counter moving forward), and the person picked the code the browser showed. |
| `cred_once` | Every request is answered at most once: once answered, approved or not, it is refused. An answer cannot be replayed, and a wrong code cannot be retried on the same request. |
| `ask_bounded` | However many requests a program sends, and however fast, at most `max` prompts reach the phone within any window. |

The passkey checks (signature with the registered key, the signed challenge is this request's digest, client data
origin and relying party of the registered phone page, user-verified flag, counter) are made by `zwebauthn.py` and
passed to the decision as facts. The entry's key comes from the phone's passkey (WebAuthn PRF) and reaches the vault
service encrypted to that request's one-time key; the PC stores only ciphertext.

### The key service (`KeyService.lean`)

| Theorem | Statement |
|---|---|
| `key_sound` | The key service releases a file's key only to an enrolled PC, for a request signed with its identity key, recent and not seen before, for a user the service assigned to this PC, while the audit node has heard from the PC within the silence limit, its last signed status shows every protecting service running and no stop, fewer than the limits of keys went to this PC and user, and to this PC, within the rate window, and (from the presence level) the user confirmed it on their own passkey. |
| `key_open_sound` | A released key is one `decideOpen` allows with the clearance, officers and grant as the service holds them: what `open_sound` says carries over. |
| `key_presence` | From the presence level up, every released key came with a confirmation on a passkey registered to that user, over a challenge issued for this PC, user and file, with the person verified. |
| `key_silent_refused`, `key_unhealthy_refused`, `key_halted_refused` | A PC that went silent, whose protecting services are not all running, or that reported a stop gets no key, whoever asks. |
| `key_rate_bounded` | However many key requests a program on the PC sends for one user, and however fast, at most the limit of keys is released within any window (requests decided one at a time; the service serialises counting and deciding per PC). |

The service checks the PC's request signature, the time and nonce, the passkey assertion (`zwebauthn.py`), the
officers' signatures on a grant and reads the PC's health from the audit node's store; these are passed as facts. The
file key is derived on the service (HKDF-SHA256 from the level's master key and the file id) and reaches keyd wrapped
for that request only (X25519, HKDF, AES-256-GCM); the answer is signed with the service's key.

### What a PC lets in (`Supply.lean`)

| Theorem | Statement |
|---|---|
| `install_sound` | A package file is installed only when it matches the release record, more than half of the configured audit nodes answered with that same record under their own signatures, at least `required` (and at least one) distinct enrolled release officers signed it, no revocation is agreed, and the PC's ring is open. |
| `one_node_not_enough` | With two or more audit nodes configured, one node vouching never lets a package in. |
| `one_key_not_enough` | When two or more officers must sign, one release key never lets a package in. |
| `revoked_refused` | An agreed revocation keeps a package out. |
| `approval_sound` | An officer's passkey approval counts only when its signature verifies with the enrolled passkey, it was made for this request and ZENOS's page, the person was verified on the phone, the counter did not go back, and (when required) the phone was near the PC or an allowed exception was used (`Approval.lean`). |
| `far_refused` | When nearness is required and exceptions are off, a phone that was not near the PC never approves. |
| `model_sound` | An AI model kept on the PC is loaded only when its record is a model record, every file in its folder is in the record with the same SHA-256 and every listed file is there, the data is within the record's level, and the ledger holds the record as for a package (`Model.lean`). |
| `changed_file_refused` | A model folder with any file added, changed or missing is never loaded. |
| `model_one_key_not_enough`, `model_one_node_not_enough` | One officer's key, or one audit node, never lets a model in. |
| `model_level_bound` | A model never sees data above the level its record allows. |
| `kev_first` | A vulnerability known to be exploited (CISA KEV) is always handled before one that is not, whatever the scores (`Vuln.lean`). |
| `severity_before_reach` | Between two of the same KEV standing, the higher CVSS score comes first, even if the other is reachable from the network. |
| `mitigation_needs_signatures` | A mitigation is applied only to an affected part and only with at least the required number (at least one) of release officers' signatures. |
| `fixed_never_affected` | A part whose installed version has the fix is never reported affected. |
| `share_sound` | A ZENOS Data key peer releases its share of a record's key only when the server is enrolled and signed this request, recent and not seen before, the audit node heard from the server within the silence limit, the person is verified by the sign-in service, the purpose is registered, the person's clearance covers the record's level or a grant names the record, and both rate limits hold (`DataStore.lean`). |
| `above_clearance_no_record` | When no grant names the record and the person's clearance is below its level, every key peer refuses, so the key cannot be made with any threshold of at least one. |
| `one_peer_not_enough` | With a threshold of two or more, one key peer's share never makes a record's key, however that peer decides. |
| `share_silent_refused`, `share_unverified_refused` | A server the audit node no longer hears from, or a person not verified, gets no share. |
| `api_sound`, `api_other_version_refused`, `api_denied_refused` | A model called through an API is used only at the provider, address, model and version pinned in its record, and never at a provider ZENOS refuses. |
| `sysegress_cut_only_unlisted`, `sysegress_listed_kept` | The network sentinel cuts a system account's connection only in enforce mode and only to a destination that is not listed; listed destinations and people's own programs are never cut by this rule. |

The PC checks the node answers' signatures, the officers' signatures over the record digest and the file's SHA-256
(`zsupply.py`), and passes the results as facts.

### The conductor (`Orchestrator.lean`, docs/ORCHESTRATOR.md)

| Theorem | Statement |
|---|---|
| `route_sound` | A piece of a task is sent only to a provider the person allows. |
| `no_linked_pair` | Under an allowed route, no provider receives both what a record is about (a name, a label) and its value (a number, a diagnosis). |
| `one_provider_not_whole` | Under an allowed route, for every protected record and every provider, part of that record never reaches that provider. |
| `vote_sound`, `one_provider_never_decides` | A cross-checked result is accepted only when its backers hold more than half of the weight of all who answered and at least two distinct providers back it; however the weights are set, one provider never decides alone. |
| `masked_only_out`, `local_sends_nothing`, `split_needs_route`, `send_to_allowed` | A masked task sends nothing the masker flagged as real; a task kept on the PC sends nothing; a split piece goes out only on a route decideRoute allowed. |
| `taint_narrows`, `dest_from_person` | After outside content, the destinations open are a subset of those open before; every destination a step reaches was set by the person. |
| `confirm_irreversible` | An act that cannot be taken back runs only after confirmation. |
| `chart_split_allowed`, `chart_whole_refused`, `chart_unlisted_refused`, `heavy_alone_refused`, `heavy_with_second_accepted` | The examples, checked. |

The conductor finds the values to mask (`zorch.py`: the person's terms, patterns, the tables' names and cells) and
gives each piece its role; those are passed as facts.

### Organizations reaching each other, and place (`Federation.lean`, docs/FEDERATION.md)

| Theorem | Statement |
|---|---|
| `fed_sound` | A request from one organization's relay to another passes only when it is signed by the sending relay, fresh, both organizations are listed, and its level is within both entries. |
| `unlisted_refused`, `unlisted_sender_refused` | A request to or from an organization without a valid entry is refused. |
| `one_signer_not_enough` | An organization whose entries each carry at most one valid authority signature is not listed (the list needs at least two distinct authorities per entry). |
| `level_bound` | An allowed request never carries a level above what the receiving organization may receive. |
| `publisher_cannot_message` | A publish-only member (a disaster information service) never sends or receives messages or key bundles. |
| `abroad_closes` | Outside the country, levels from the set threshold up are refused. |
| `no_widen_without_emergency`, `widen_needs_all` | Place never allows more than the decision without place, except emergency sharing while a disaster is declared, inside the area by both the device and a second proof. |
| `zone_needs_proof` | Content that requires a zone opens only with a second proof of place that does not come from the device's positioning. |
| `gps_alone_changes_nothing` | Without that second proof, the device's location reading does not change the decision: faking it gains nothing. |
| `ex_ministry_to_city`, `ex_above_city_level`, `ex_rogue_refused`, `ex_geoid_alert`, `ex_geoid_no_message`, `ex_k1_refused` | The examples, checked. |

The relay checks each authority's Ed25519 signature on the entries, the sending relay's signature on the request
and its freshness (`messenger/federation.js`); the device measures its position (`messenger/zgeo.js`). Those are
passed as facts.

## What is trusted, not proved

- Cryptography: Ed25519 signature checks with the officers' enrolled keys, SHA-256 digests, AES-GCM; for sign-in,
  the passkey signature (ES256 / EdDSA), the PRF of the phone's authenticator, ECDH P-256 and HKDF. The services
  check these and pass the results (`sig_ok`, `digest_ok`) to the decision.
- The facts the services read from root-owned files: the clearance file, the enrolled officers, the stop state, the
  clock.
- The glue: `zdecide.py`, the parts of the services that gather facts and carry out the answer (write the request
  file, freeze or thaw processes, cut a destination), the folder-level and CIDR lookups, and the readers in
  `formal/Main.lean`.
- The network sensor (eBPF/bpftrace) that reports each outbound send.
- The sentinel's clock: `prune_prune` assumes the times it is given never go backwards. The sentinel currently
  stamps sends with wall-clock time, which can jump; a monotonic clock is tracked in
  [#58](https://github.com/zenos-org/zenos/issues/58).
- Lean's compiler and runtime, the Linux kernel, Python.
- What the proofs do not speak about: the firewall rules themselves, ledger shipping, the trust agent and the
  messenger are tested, not proved. The signature model in `Protocol.lean` is symbolic (unforgeability and
  collision resistance are assumed); a computational proof of the cryptography is out of scope.

## Building and checking

```
# once: install elan, Lean's toolchain manager (https://github.com/leanprover/elan)
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

git clone https://github.com/zenos-org/zenos && cd zenos
cd formal && lake build          # checks every proof and builds .lake/build/bin/zenos-decide
cd .. && python3 -m unittest tests/test_decide.py
```

elan picks the Lean version from `formal/lean-toolchain` by itself. If `lake build` finishes without an error,
every theorem in `formal/` has been checked by Lean's kernel on your machine, and `Axioms.lean` has confirmed
that none of them uses `sorry` or an added axiom.

A short reading order for a first look: `Flow.lean` (one decision, with the
[walkthrough](https://github.com/zenos-org/zenos/discussions/11)), then the theorems in `Proofs.lean` against the
tables above, then `Axioms.lean`, then "What is trusted, not proved" above, where the proofs stop.

`packaging/build-deb.sh` builds it the same way and installs the program as `/usr/lib/zenos/zenos-decide`.
Lean 4 v4.34.1 (`formal/lean-toolchain`); no other dependency.

## Reviewing the proofs

Review of the specifications is the most useful help for this part: whether each theorem states what it should,
and whether a gap between a theorem and what a service actually does is missing from the list above.

- Walkthroughs: [where file content may go (`Flow.lean`)](https://github.com/zenos-org/zenos/discussions/11),
  [how the ledger catches a rewritten history (`Ledger.lean`)](https://github.com/zenos-org/zenos/discussions/17) and
  [what may leave the PC (`Egress.lean`)](https://github.com/zenos-org/zenos/discussions/59).
- A theorem that says less than it should, or a missing assumption: open an
  [issue](https://github.com/zenos-org/zenos/issues) or reply in [Discussions](https://github.com/zenos-org/zenos/discussions).
- A way to get data out despite the decisions: please report it privately as described in
  [SECURITY.md](../SECURITY.md), not in public.

## Credit

The idea of proving these decisions in Lean came from [Nyxis](https://github.com/NyxFoundation/nyxis) by Nyx
Foundation, which proves the authorization of a web backend. It builds on earlier work, among it Amazon's
[Cedar](https://github.com/cedar-policy/cedar-spec) policy language, whose authorizer is formalized and verified in
Lean, and the [seL4](https://sel4.systems/) verified kernel. ZENOS uses none of their code; the proofs in `formal/`
were written for ZENOS.

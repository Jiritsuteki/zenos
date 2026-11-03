# ZENOS glossary

## Conductor

The conductor runs an AI task on the person's PC, coordinates calls to model providers, and keeps the task data and token table locally. It is in the source but not released; see [the conductor's parts](ORCHESTRATOR.md#the-parts) and the limitations in that document.

## Egress

Egress is what leaves the PC: the pre-send check evaluates files before sending, while the network sentinel checks outbound traffic against approved destinations and a byte threshold. See [what leaves the PC](FORMAL_VERIFICATION.md#what-leaves-the-pc-egresslean).

## Federation

Federation lets ZENOS Messages relays at different organizations exchange encrypted envelopes through a shared, signed member list. It is in the source but not released; see [organizations reaching each other](FEDERATION.md#2-organizations-reaching-each-other-federation).

## Key service

The key service moves the master keys used to derive sealed-file keys off the PC and checks requests using its own records of users, grants and PC health. It is in the repository but not released; see [how the key service works](KEY_SERVICE.md#how-it-works).

## Ledger

A ledger is a hash-chained audit history; audit nodes accept batches only when they extend the chain the node already holds. See [the tamper-evident ledger](FORMAL_VERIFICATION.md#the-tamper-evident-ledger-ledgerlean) and its deployment limitations in the [threat model](THREAT_MODEL.md#what-is-real-today-and-what-is-not).

## Officer

An officer is an enrolled approver whose verified signature can authorize a request, such as access above a user's clearance or release of a stopped PC. The requester cannot count as their own approver; see [officers' signatures](FORMAL_VERIFICATION.md#officers-signatures-protocollean).

## Sealed file

A sealed file is encrypted and fragmented with a signed header; the key agent seals and opens it according to the user's clearance or an officer-approved grant. See the file-sealing row and its limitations in [what is real today](THREAT_MODEL.md#what-is-real-today-and-what-is-not).

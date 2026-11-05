# Officers' approvals with a passkey in the phone

Status: in the source, not released. Tested with software passkeys (Chrome's virtual authenticator, a simulated
P-256 phone key); tests on physical phones are listed at the end as they are done.

## What changes

An officer approves a request (opening a file of L3 or above, letting a stopped PC go on, a pre-filed operation)
by signing it. Until now the signature came from an Ed25519 key made in the officer's browser (WebCrypto,
non-extractable): it cannot be read out, but it lives in the browser, not in the phone's secure chip.

The approval key can now be a passkey, which the phone keeps in its secure chip (iPhone: Secure Enclave; Android:
the hardware key store) and uses only after face, fingerprint or PIN:

- The passkey signs the request itself: the WebAuthn challenge is the request's digest (which PC, which file, who,
  when; `"decline:"` + digest to decline). A signature cannot be moved to another request.
- The PC checks it (`system/lib/zapprove.py`) with the passkey the administrator enrolled for that officer
  (`/etc/zenos/approvers/<name>.passkey.json`, `zenos_guardd.py --enroll-passkey NAME LINE`), and the proven
  decision (`formal/ZenosFormal/Approval.lean`, zenos-decide "passkey_approval") counts it only when the signature
  verifies, it was made for this request and for ZENOS's page, the person was verified on the phone, and the
  passkey's counter did not go backwards (a copied key).
- Moving off the browser key: the officer presses "Use a passkey" in ZENOS Messages → Settings → Approval key and
  gives the line it shows to the administrator. Once the passkey is enrolled, the old browser key no longer signs
  for that officer.

## The phone must be near the PC

The passkey standard lets a phone sign in on a PC: the PC's browser shows a QR code, the phone reads it, and the two
check over Bluetooth that they are close to each other before anything is signed. From another place it does not go
through.

ZENOS uses this for approvals that matter most. With `/etc/zenos/approval.json`:

    {"near_from_level": 3, "exceptions": false}

an approval of an L3 or higher request counts only when it was made on the PC's screen with the officer's phone
("An officer is here" in My requests on the stopped PC). The browser reports this as "cross-platform"; it is not
part of the signature, so it is as trustworthy as the PC itself. A browser key cannot show nearness, so it no longer
approves such requests. `"exceptions": true` lets an officer approve from afar (working from home, travelling) by
saying so; every such approval is written to the ledger as "approval-exception". Proved: when nearness is required
and exceptions are off, a phone that was not near never approves (`far_refused`).

## If the phone is lost (proposal, not built)

Following the direction set on 27 October 2026 (no spare keys to keep in a drawer; a copy kept on the PC in a
different form, opened with the face; the messenger's keys and the approval key thought of together):

1. At enrolment, the PC also makes a second credential for the same officer in its own TPM (a passkey of the PC,
   opened with face recognition on the PC's camera or the fingerprint reader), and keeps an encrypted copy of the
   officer's ZENOS Messages identity sealed to the same TPM. Neither leaves the PC.
2. When the phone is lost, the officer stands at their own PC and opens that copy with their face. This alone
   does not make the new phone an approver: another officer approves the re-enrolment on the same PC (the near
   rule above), the administrator enrols the new phone's passkey, and the lost phone's passkey is removed
   (`/etc/zenos/approvers/<name>.passkey.json` replaced). All of it is written to the ledger.
3. The messenger identity is restored on the new phone from the PC's copy as a new device; the lost phone's device
   is unlinked at the relay.

Open questions: face recognition on PCs without an infrared camera is weak against photos (fingerprint is the
safer default there); a PC that is itself lost or stolen takes its copy with it, which the TPM's seal and the
officers' approval have to cover.

## Tests on physical phones

| Phone | OS | Browser | Make a passkey | Approve on the phone | Approve on a PC with the phone near |
|---|---|---|---|---|---|
| (waiting) | | | | | |

The test page is `tests/manual/passkey-test.html`; it is served for testing at a preview address of the website
project (not zenos-os.org), and it sends nothing anywhere.

import ZenosFormal.Decide

/-!
# An officer's approval made with a passkey

An officer approves (opening a file of L3 or above, letting a stopped PC go on) by signing the request with a
passkey kept in their phone's secure chip (iPhone: Secure Enclave; Android: the hardware key store). The signature
is over the request's digest (which PC, which file, who, when). What the PC checks about one approval:

* the signature verifies with the passkey enrolled for that officer (`sigOk`);
* it was made for this request (`challengeOk`: the passkey signed this request's digest, `webauthn.get`);
* it was made for ZENOS's site and page (`originOk`), with the person verified on the phone (`userVerified`:
  face, fingerprint or PIN);
* the passkey's counter moved forward or is not used (`counterOk`: a copied key shows up here);
* and, when the policy asks for it (`nearRequired`), the phone was near the PC: the approval was made on the PC's
  screen with the phone that read its QR code, which the passkey standard confirms over Bluetooth (`near`). An
  exception (working from home, travelling) counts only if the policy allows exceptions and the officer used one,
  and using it is written to the ledger.

An approval that passes counts as one approval with a verified signature in the approval rules (`Decide.lean`).

Proved:
* `approval_sound`: an approval that counts passed every check above.
* `far_refused`: when nearness is required and exceptions are not allowed, an approval from a phone that was not
  near the PC never counts.
* `unverified_refused`: an approval without the person verified on the phone never counts.
-/

namespace Zenos

structure PasskeyApproval where
  sigOk : Bool
  challengeOk : Bool
  originOk : Bool
  userVerified : Bool
  counterOk : Bool
  near : Bool
  nearRequired : Bool
  exceptionAllowed : Bool
  exceptionUsed : Bool
  deriving Repr, Inhabited, DecidableEq

def nearEnough (a : PasskeyApproval) : Bool :=
  a.near || !a.nearRequired || (a.exceptionAllowed && a.exceptionUsed)

def decidePasskeyApproval (a : PasskeyApproval) : Option String :=
  if !a.sigOk then some "signature"
  else if !a.challengeOk then some "not-for-this-request"
  else if !a.originOk then some "wrong-page"
  else if !a.userVerified then some "person-not-verified"
  else if !a.counterOk then some "cloned-passkey"
  else if !nearEnough a then some "phone-not-near"
  else none

theorem approval_sound {a : PasskeyApproval} (h : decidePasskeyApproval a = none) :
    a.sigOk = true ∧ a.challengeOk = true ∧ a.originOk = true ∧ a.userVerified = true ∧ a.counterOk = true ∧
    (a.near = true ∨ a.nearRequired = false ∨ (a.exceptionAllowed = true ∧ a.exceptionUsed = true)) := by
  unfold decidePasskeyApproval at h
  split at h; · cases h
  rename_i h1
  split at h; · cases h
  rename_i h2
  split at h; · cases h
  rename_i h3
  split at h; · cases h
  rename_i h4
  split at h; · cases h
  rename_i h5
  split at h; · cases h
  rename_i h6
  simp only [Bool.not_eq_true, Bool.not_eq_false'] at h1 h2 h3 h4 h5
  simp only [nearEnough] at h6
  refine ⟨h1, h2, h3, h4, h5, ?_⟩
  cases hn : a.near <;> cases hr : a.nearRequired <;> cases he : a.exceptionAllowed <;> cases hu : a.exceptionUsed <;>
    simp_all

/-- When nearness is required and no exception is allowed, a phone that was not near never approves. -/
theorem far_refused {a : PasskeyApproval} (hr : a.nearRequired = true) (he : a.exceptionAllowed = false)
    (hn : a.near = false) : decidePasskeyApproval a ≠ none := by
  intro h
  rcases (approval_sound h).2.2.2.2.2 with h1 | h1 | ⟨h1, _⟩ <;> simp_all

theorem unverified_refused {a : PasskeyApproval} (h : a.userVerified = false) : decidePasskeyApproval a ≠ none := by
  intro ha
  have := (approval_sound ha).2.2.2.1
  simp_all

theorem ex_near_ok :
    decidePasskeyApproval ⟨true, true, true, true, true, true, true, false, false⟩ = none := by decide
theorem ex_far_refused :
    decidePasskeyApproval ⟨true, true, true, true, true, false, true, false, false⟩ = some "phone-not-near" := by decide
theorem ex_far_exception :
    decidePasskeyApproval ⟨true, true, true, true, true, false, true, true, true⟩ = none := by decide

end Zenos

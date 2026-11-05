import ZenosFormal.Decide

/-!
# Data kept by a server, the ZENOS way: no plaintext at rest, a key for one record at a time

A server program (a ministry's case system, a web service) keeps its records with ZENOS Data (`zdata.py`). Every
record is encrypted with its own key; the encrypted record is copied to several storage peers; its key is split
into shares (k of n), each share sealed to one key peer run by a different party. The server keeps no key. To read a
record it asks the key peers, each for its share, for one named person and one stated purpose. Each key peer checks
the facts below on its own and passes them here; this decides whether that peer releases its share.

* the server is enrolled with the peer and signed the request with its identity key, recent and not seen before;
* the audit node heard from the server within the silence limit (a server that stopped shipping its ledger gets
  nothing);
* the person is verified: a session the peer can check itself (a passkey signature over this request, or a token
  the organization's sign-in service signed), never the server's word alone;
* the purpose is one registered for this server and this kind of record;
* the person's clearance covers the record's level, or a grant signed by enough officers names this record;
* not too many shares for this person and for this server within the rate window.

Proved:
* `share_sound`: a share is released only when all of the above hold.
* `share_level_bound`: a released share is for a record within the person's clearance or under a grant.
* `above_clearance_no_record`: when no grant names the record and the person's clearance is below its level, every
  peer refuses, so the record's key cannot be put together with any threshold of at least one.
* `one_peer_not_enough`: with a threshold of two or more, the share of one peer (however it decides, even if it is
  taken over) never makes the key.
* `share_silent_refused`, `share_unverified_refused`: a server gone silent or a person not verified gets no share.

Trusted, not proved: the splitting itself (Shamir's scheme over GF(2^8), `zdata.py`), AES-256-GCM, Ed25519, and
that the key peers are run by parties that do not collude up to the threshold.
-/

namespace Zenos

structure ShareReq where
  enrolled : Bool
  sigOk : Bool
  fresh : Bool
  now : Nat
  lastSeen : Nat
  silence : Nat
  personVerified : Bool
  purposeOk : Bool
  level : Nat
  clearance : Nat
  grantOk : Bool
  recent : Nat
  rateMax : Nat
  serverRecent : Nat
  serverRateMax : Nat
  deriving Repr, Inhabited, DecidableEq

def decideShare (r : ShareReq) : Option String :=
  if !r.enrolled then some "server"
  else if !r.sigOk then some "signature"
  else if !r.fresh then some "replay"
  else if r.lastSeen + r.silence < r.now then some "silent"
  else if !r.personVerified then some "person-not-verified"
  else if !r.purposeOk then some "purpose"
  else if !(r.level ≤ r.clearance || r.grantOk) then some "level"
  else if r.rateMax ≤ r.recent then some "rate"
  else if r.serverRateMax ≤ r.serverRecent then some "rate"
  else none

theorem share_sound {r : ShareReq} (h : decideShare r = none) :
    r.enrolled = true ∧ r.sigOk = true ∧ r.fresh = true ∧ r.now ≤ r.lastSeen + r.silence ∧
    r.personVerified = true ∧ r.purposeOk = true ∧ (r.level ≤ r.clearance ∨ r.grantOk = true) ∧
    r.recent < r.rateMax ∧ r.serverRecent < r.serverRateMax := by
  unfold decideShare at h
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
  split at h; · cases h
  rename_i h7
  split at h; · cases h
  rename_i h8
  split at h; · cases h
  rename_i h9
  simp only [Bool.not_eq_true, Bool.not_eq_false', Nat.not_lt, Nat.not_le, Bool.or_eq_true,
    decide_eq_true_eq] at h1 h2 h3 h4 h5 h6 h7 h8 h9
  exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩

theorem share_level_bound {r : ShareReq} (h : decideShare r = none) : r.level ≤ r.clearance ∨ r.grantOk = true :=
  (share_sound h).2.2.2.2.2.2.1

theorem share_silent_refused {r : ShareReq} (h : r.lastSeen + r.silence < r.now) : decideShare r ≠ none := by
  intro hd; have := (share_sound hd).2.2.2.1; omega

theorem share_unverified_refused {r : ShareReq} (h : r.personVerified = false) : decideShare r ≠ none := by
  intro hd; have := (share_sound hd).2.2.2.2.1; simp_all

/-! ## Across the key peers

Each key peer decides on its own facts. The key is put together from the shares of the peers that released, and
only when there are at least `k` of them. -/

/-- how many peers released their share -/
def released (rs : List ShareReq) : Nat := (rs.filter fun r => decideShare r = none).length

def keyMade (k : Nat) (rs : List ShareReq) : Bool := k ≤ released rs

theorem above_clearance_no_record {k : Nat} {rs : List ShareReq} (hk : 1 ≤ k)
    (h : ∀ r ∈ rs, r.clearance < r.level ∧ r.grantOk = false) : keyMade k rs = false := by
  have h0 : released rs = 0 := by
    unfold released
    rw [List.length_eq_zero_iff, List.filter_eq_nil_iff]
    intro r hr hd
    have hb := share_level_bound (of_decide_eq_true hd)
    obtain ⟨hl, hg⟩ := h r hr
    rcases hb with hb | hb
    · omega
    · rw [hg] at hb; cases hb
  unfold keyMade; rw [h0]; simp; omega

/-- The share of one peer alone: whatever that peer decides, the others' facts are what they are. -/
theorem one_peer_not_enough {k : Nat} (hk : 2 ≤ k) (r : ShareReq) : keyMade k [r] = false := by
  unfold keyMade released
  have : ([r].filter fun r => decideShare r = none).length ≤ 1 := by
    simp only [List.filter_cons, List.filter_nil]; split <;> simp
  simp; omega

def exampleReq : ShareReq :=
  { enrolled := true, sigOk := true, fresh := true, now := 100, lastSeen := 95, silence := 90, personVerified := true,
    purposeOk := true, level := 3, clearance := 3, grantOk := false, recent := 0, rateMax := 30, serverRecent := 0,
    serverRateMax := 600 }

example : decideShare exampleReq = none := by decide
example : decideShare { exampleReq with level := 4 } = some "level" := by decide
example : decideShare { exampleReq with level := 4, grantOk := true } = none := by decide
example : decideShare { exampleReq with lastSeen := 5 } = some "silent" := by decide

end Zenos

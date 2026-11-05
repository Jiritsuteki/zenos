import ZenosFormal.Decide

/-!
# Vulnerability information from outside, matched against what is on the PC

`zenos-vulnwatch` reads public vulnerability information (CISA's Known Exploited Vulnerabilities catalogue, the
Debian security tracker, NVD, JVN and others) and matches it against the PC's own parts. The information is only
data: from each source ZENOS keeps identifiers, package names, versions and scores, never text, so nothing a
source writes (a description, a "prompt for your AI agent") reaches this decision or any program. What is decided
here for each vulnerability and part:

* the status: not affected, fixed (the installed version is at least the fixed one), mitigated (a mitigation the
  officers signed is in force), or affected;
* the order in which affected ones are handled: those known to be exploited (KEV) first, then by severity (CVSS,
  in tenths), then those reachable over the network;
* whether a mitigation may be applied: only for an affected part, and only when at least the required number (at
  least one) of release officers signed it, as for a release.

Proved:
* `kev_first`: an exploited vulnerability always comes before one not known to be exploited, whatever the scores.
* `severity_before_reach`: between two of the same KEV standing, a higher score comes first even if the other is
  reachable from the network and it is not.
* `mitigation_needs_signatures`: a mitigation is never applied with fewer signatures than required, never without
  any, and never to a part that is not affected.
* `fixed_never_affected`: a part whose installed version has the fix is never reported affected.
-/

namespace Zenos

structure VulnFacts where
  /-- the source lists this part as affected by this vulnerability (in some version) -/
  listed : Bool
  /-- a fixed version exists and the installed version is at least that -/
  fixedInstalled : Bool
  /-- a signed mitigation for it is in force on this PC -/
  mitigated : Bool
  kev : Bool
  /-- CVSS base score in tenths (0..100) -/
  score : Nat
  remote : Bool
  /-- release officers whose signature on the mitigation verified, and how many are required -/
  signatures : Nat
  required : Nat
  deriving Repr, Inhabited, DecidableEq

inductive VulnStatus where
  | notAffected | fixed | mitigated | affected
  deriving Repr, DecidableEq

def vulnStatus (f : VulnFacts) : VulnStatus :=
  if !f.listed then .notAffected
  else if f.fixedInstalled then .fixed
  else if f.mitigated then .mitigated
  else .affected

/-- the order key: larger is handled first -/
def vulnPriority (f : VulnFacts) : Nat :=
  (if f.kev then 1000 else 0) + 2 * min f.score 100 + (if f.remote then 1 else 0)

def mayMitigate (f : VulnFacts) : Bool :=
  vulnStatus f == .affected && decide (1 ≤ f.required) && decide (f.required ≤ f.signatures)

theorem kev_first {a b : VulnFacts} (ha : a.kev = true) (hb : b.kev = false) :
    vulnPriority b < vulnPriority a := by
  unfold vulnPriority; simp only [ha, hb, ite_true, Bool.false_eq_true, ite_false]
  have : min b.score 100 ≤ 100 := Nat.min_le_right _ _
  split <;> split <;> omega

theorem severity_before_reach {a b : VulnFacts} (hk : a.kev = b.kev) (hs : min b.score 100 < min a.score 100) :
    vulnPriority b < vulnPriority a := by
  unfold vulnPriority; rw [hk]
  split <;> split <;> split <;> omega

theorem mitigation_needs_signatures {f : VulnFacts} (h : mayMitigate f = true) :
    1 ≤ f.required ∧ f.required ≤ f.signatures ∧ vulnStatus f = .affected := by
  unfold mayMitigate at h
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h
  exact ⟨h.1.2, h.2, h.1.1⟩

theorem fixed_never_affected {f : VulnFacts} (h : f.fixedInstalled = true) : vulnStatus f ≠ .affected := by
  unfold vulnStatus; split
  · decide
  · decide

def exampleVuln : VulnFacts :=
  { listed := true, fixedInstalled := false, mitigated := false, kev := true, score := 98, remote := true,
    signatures := 1, required := 2 }

example : vulnStatus exampleVuln = .affected := by decide
example : mayMitigate exampleVuln = false := by decide
example : mayMitigate { exampleVuln with signatures := 2 } = true := by decide
example : vulnStatus { exampleVuln with fixedInstalled := true } = .fixed := by decide

end Zenos

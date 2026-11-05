import ZenosFormal.Supply

/-!
# AI model files: only the files that were released, exactly

A model's weights can be rewritten so that it behaves differently while the file looks the same (a few weights
changed, a trigger that wakes on one input). Neither a person looking at it nor a test run is sure to see it. ZENOS
therefore treats a model like a package: it does not judge what the weights do, it checks that every file is the
file that was released.

A model kept on the PC (weights, tokenizer, settings, adapters such as LoRA) has a release record in the same
ledger as packages: every file's SHA-256, the model's name, version, publisher, where it came from, its licence,
and the highest level of data it may see. Before a model is loaded:

* the record is a model record (a package record cannot stand in for it);
* every file in the model's folder is in the record with the same SHA-256, and every file in the record is there
  (nothing added, nothing changed, nothing missing: `filesOk`, checked by the PC);
* the data it is to see is within the record's level;
* and the ledger holds the record as for a package (`decideInstall`): a majority of the audit nodes with the same
  record, enough release officers' signatures, no revocation, the PC's ring open.

A model called through an API cannot be hashed: what is pinned instead is whom it is called at (provider, address,
model name and version). A call goes out only to the pinned identity, never to a provider ZENOS refuses.

Proved:
* `model_sound`: a loaded model passed every check above.
* `changed_file_refused`: a folder with any file added, changed or missing is never loaded.
* `model_one_key_not_enough`, `model_one_node_not_enough`: one officer's key, or one audit node, never lets a
  model in.
* `model_level_bound`: a model never sees data above the level its record allows.
* `api_sound`, `api_other_version_refused`, `api_denied_refused`: an API model is used only at the identity in its
  record, and never at a refused provider.
-/

namespace Zenos

structure ModelReq where
  /-- the ledger facts for the model's record, exactly as for a package (`hashOk`: the model's identity, the
      digest of its files list, is the one in the record) -/
  ledger : InstallReq
  /-- the record is a model record -/
  kindOk : Bool
  /-- every file in the folder is in the record with the same SHA-256, and every file in the record is there -/
  filesOk : Bool
  /-- the level of the data the model is to see -/
  level : Nat
  /-- the highest level the record allows -/
  maxLevel : Nat
  deriving Repr, Inhabited

def decideModel (m : ModelReq) : InstallDecision :=
  if !m.kindOk then .refuse "kind"
  else if !m.filesOk then .refuse "files"
  else if m.maxLevel < m.level then .refuse "level"
  else decideInstall m.ledger

theorem model_sound {m : ModelReq} (h : decideModel m = .allow) :
    m.kindOk = true ∧ m.filesOk = true ∧ m.level ≤ m.maxLevel ∧ decideInstall m.ledger = .allow := by
  unfold decideModel at h
  split at h; · cases h
  rename_i h1
  split at h; · cases h
  rename_i h2
  split at h; · cases h
  rename_i h3
  simp only [Bool.not_eq_true, Bool.not_eq_false', Nat.not_lt] at h1 h2 h3
  exact ⟨h1, h2, h3, h⟩

/-- A folder with any file added, changed or missing is never loaded. -/
theorem changed_file_refused {m : ModelReq} (h : m.filesOk = false) : decideModel m ≠ .allow := by
  intro ha
  have := (model_sound ha).2.1
  simp [h] at this

/-- When two or more officers must sign, one key never lets a model in. -/
theorem model_one_key_not_enough {m : ModelReq} (hq : 2 ≤ m.ledger.required)
    (hs : (countedSigners m.ledger).length ≤ 1) : decideModel m ≠ .allow := by
  intro ha
  exact one_key_not_enough hq hs (model_sound ha).2.2.2

/-- With two or more audit nodes configured, one node never lets a model in. -/
theorem model_one_node_not_enough {m : ModelReq} (hn : 2 ≤ (dedup m.ledger.nodes).length)
    (ha : (agreeing m.ledger).length ≤ 1) : decideModel m ≠ .allow := by
  intro h
  exact one_node_not_enough hn ha (model_sound h).2.2.2

/-- A model never sees data above the level its record allows. -/
theorem model_level_bound {m : ModelReq} (h : decideModel m = .allow) : m.level ≤ m.maxLevel :=
  (model_sound h).2.2.1

structure ApiModelReq where
  /-- the ledger facts for the pinned identity's record (`hashOk`: the identity's digest is the record's) -/
  ledger : InstallReq
  kindOk : Bool
  /-- the call goes to the provider, address, model name and version in the record -/
  sameModel : Bool
  /-- the provider is on ZENOS's refused list -/
  denied : Bool
  level : Nat
  maxLevel : Nat
  deriving Repr, Inhabited

def decideApiModel (m : ApiModelReq) : InstallDecision :=
  if m.denied then .refuse "denied"
  else if !m.kindOk then .refuse "kind"
  else if !m.sameModel then .refuse "version"
  else if m.maxLevel < m.level then .refuse "level"
  else decideInstall m.ledger

theorem api_sound {m : ApiModelReq} (h : decideApiModel m = .allow) :
    m.denied = false ∧ m.kindOk = true ∧ m.sameModel = true ∧ m.level ≤ m.maxLevel ∧
    decideInstall m.ledger = .allow := by
  unfold decideApiModel at h
  split at h; · cases h
  rename_i h0
  split at h; · cases h
  rename_i h1
  split at h; · cases h
  rename_i h2
  split at h; · cases h
  rename_i h3
  simp only [Bool.not_eq_true, Bool.not_eq_false', Nat.not_lt] at h0 h1 h2 h3
  exact ⟨h0, h1, h2, h3, h⟩

/-- A provider that switched the model or its version is not called until the new one is pinned. -/
theorem api_other_version_refused {m : ApiModelReq} (h : m.sameModel = false) : decideApiModel m ≠ .allow := by
  intro ha
  have := (api_sound ha).2.2.1
  simp [h] at this

theorem api_denied_refused {m : ApiModelReq} (h : m.denied = true) : decideApiModel m = .refuse "denied" := by
  simp [decideApiModel, h]

/-! Examples: a released model, the same model with one file changed, and one officer's signature only. -/

def exLedger (signers : List String) : InstallReq :=
  { nodes := ["n1", "n2", "n3"], votes := [⟨"n1", true, "r"⟩, ⟨"n2", true, "r"⟩, ⟨"n3", true, "r"⟩], record := "r",
    hashOk := true, signers, officers := ["ito", "kato", "mori"], required := 2, revoked := false, ringOpen := 0,
    now := 10 }

theorem ex_model_released :
    decideModel { ledger := exLedger ["ito", "kato"], kindOk := true, filesOk := true, level := 2, maxLevel := 2 } = .allow := by
  decide
theorem ex_model_changed :
    decideModel { ledger := exLedger ["ito", "kato"], kindOk := true, filesOk := false, level := 2, maxLevel := 2 } = .refuse "files" := by
  decide
theorem ex_model_one_key :
    decideModel { ledger := exLedger ["ito"], kindOk := true, filesOk := true, level := 1, maxLevel := 2 } = .refuse "signatures" := by
  decide
theorem ex_model_above_level :
    decideModel { ledger := exLedger ["ito", "kato"], kindOk := true, filesOk := true, level := 3, maxLevel := 2 } = .refuse "level" := by
  decide

end Zenos

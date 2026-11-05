import ZenosFormal.Decide
import ZenosFormal.Flow
import ZenosFormal.Ledger
import ZenosFormal.Egress
import ZenosFormal.Cred
import ZenosFormal.KeyService
import ZenosFormal.Supply
import ZenosFormal.Orchestrator
import ZenosFormal.Federation
import ZenosFormal.Model

/-!
`zenos-decide`: reads one JSON request on stdin, writes one JSON answer on stdout, runs the proven decision
functions of `ZenosFormal.Decide` and nothing else. Any input it cannot read is refused (exit status 2, answer
`{"error": ...}`); the services treat that as a refusal.

  {"op":"open", "user", "clearance", "level", "file_hash", "now", "halted", "roster":[..],
   "grant": null | {"requester","holder","file_hash","level","kind":null|str,"expires","digest_ok",
                    "approvals":[{"approver","sig_ok"}]}}
      -> {"allow": bool, "by": "clearance"|"grant"|null, "reason": str|null}
  {"op":"approve", "request":{"id","requester","level","required","status","approvals":[..]}, "roster":[..],
   "who", "act":"approve"|"decline", "sig_ok", "code_ok"}
      -> {"result": "added"|"declined"|"refused", "reason": str|null}
  {"op":"release", "halted", "request":{..}, "roster":[..]}
      -> {"release": bool, "approvers":[..]}
  {"op":"release-required", "roster":[..], "requester", "level"}
      -> {"required": n}
  {"op":"required", "level"}       -> {"required": n}   (approvals a level needs; the services' table must agree)
  {"op":"flow", "src", "sink":"folder"|"window"|"clipboard"|"printer"|"external-ai"|"gov-ai"|"ministry-ai",
   "level" (folder, window), "print_max"}                       -> {"allow": bool}
  {"op":"chain", "start", "records":[{"prev","hash","hash_ok"}]} -> {"ok": bool, "index", "reason", "head"}
  {"op":"send", "sealed", "sig_ok", "size", "huge_max", "plan_ok"} -> {"allow": bool, "reason"}
  {"op":"cred", "ttl", "now", "used":[..], "devices":[{"device","user"}],
   "request":{"id","user","origin","entry_origin","tls_ok","code","created"},
   "answer":{"device","sig_ok","challenge_ok","origin_ok","user_verified","counter_ok","code"}}
      -> {"allow": bool, "reason"}
  {"op":"ask", "window", "max", "now", "log":[..]}            -> {"allow": bool}
  {"op":"key", "enrolled", "sig_ok", "fresh", "now", "last_seen", "silence", "services_ok", "pc_halted", "recent",
   "rate_max", "machine_recent", "machine_rate_max", "assigned", "presence_from", "presence": null | {"registered","sig_ok","challenge_ok","origin_ok",
   "user_verified","counter_ok"}, "open": {the fields of "open" above, without "op"}}
      -> {"allow": bool, "by": "clearance"|"grant"|null, "reason": str|null}   (the key service)
  {"op":"install", "nodes":[..], "votes":[{"node","sig_ok","record"}], "record", "hash_ok", "signers":[..],
   "officers":[..], "required", "revoked", "ring_open", "now"}       -> {"allow": bool, "reason": str|null}
  {"op":"model", the fields of "install" for the model's record, "kind_ok", "files_ok", "level", "max_level"}
      -> {"allow": bool, "reason": str|null}                          (an AI model kept on the PC, before loading)
  {"op":"model_api", the fields of "install" for the pinned identity, "kind_ok", "same_model", "denied", "level",
   "max_level"}                                                       -> {"allow": bool, "reason": str|null}
  {"op":"sysegress", "system", "listed", "loopback", "enforce"}       -> {"cut": bool}   (the network sentinel)
  {"op":"route", "allowed":[..], "frags":[{"to", "atoms":[{"record","role":"ident"|"attr"|"other"}]}]}
      -> {"allow": bool, "reason": str|null}                          (the conductor)
  {"op":"vote", "weights":[{"provider","weight"}], "ballots":[{"provider","answer"}], "answer"} -> {"accept": bool}
  {"op":"step", "kind":"send"|"tool"|"act", "level":"masked"|"split"|"pc", "provider", "allowed":[..],
   "payload_masked", "route_ok", "dest", "dests":[..], "after_taint":[..], "tainted", "confirmed"}
      -> {"allow": bool, "reason": str|null}
  {"op":"federate", "authorities":[..], "k", "members":[{"org","max_level","publish_only","sigs":[{"by","ok"}]}],
   "from", "to", "relay_sig_ok", "fresh", "kind":"message"|"keys"|"alert", "level"}
      -> {"allow": bool, "reason": str|null}                          (relays of different organizations)
  {"op":"place", "base_allow", "level", "zone_required", "gps_inside", "proof_inside", "abroad",
   "close_abroad_from", "emergency", "emergency_share"}               -> {"allow": bool, "reason": str|null}
  zenos-decide egress W THR   (the network sentinel's stream: one send per line
      "key<TAB>destination<TAB>allowed 0|1<TAB>time ms<TAB>bytes", one answer per line "cut" | "ok")
-/


/-! A small JSON reader and writer, so the program needs only Lean's core library (no `Lean` package: the binary
    stays small). It accepts what the services send: objects, arrays, strings, non-negative integers, booleans,
    null. -/

inductive J where
  | null
  | bool (b : Bool)
  | num (n : Nat)
  | str (s : String)
  | arr (xs : List J)
  | obj (kvs : List (String × J))
  deriving Inhabited

namespace J

abbrev P := StateT (List Char) (Except String)

def peek : P (Option Char) := do return (← get).head?
def next : P Char := do
  match ← get with
  | c :: cs => set cs; return c
  | [] => throw "unexpected end"
def ws : P Unit := modify (·.dropWhile (fun c => c == ' ' || c == '\n' || c == '\r' || c == '\t'))
def expect (c : Char) : P Unit := do
  if (← next) != c then throw s!"expected {c}"
def word (w : String) : P Unit := w.toList.forM expect

def hex (c : Char) : P Nat :=
  if '0' ≤ c && c ≤ '9' then pure (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then pure (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c && c ≤ 'F' then pure (c.toNat - 'A'.toNat + 10)
  else throw "bad \\u escape"

partial def strBody (acc : List Char) : P String := do
  match ← next with
  | '"' => return String.ofList acc.reverse
  | '\\' =>
    match ← next with
    | '"' => strBody ('"' :: acc)
    | '\\' => strBody ('\\' :: acc)
    | '/' => strBody ('/' :: acc)
    | 'n' => strBody ('\n' :: acc)
    | 't' => strBody ('\t' :: acc)
    | 'r' => strBody ('\r' :: acc)
    | 'b' => strBody (Char.ofNat 8 :: acc)
    | 'f' => strBody (Char.ofNat 12 :: acc)
    | 'u' =>
      let a ← hex (← next); let b ← hex (← next); let c ← hex (← next); let d ← hex (← next)
      strBody (Char.ofNat (((a * 16 + b) * 16 + c) * 16 + d) :: acc)
    | _ => throw "bad escape"
  | c => strBody (c :: acc)

partial def digits (n : Nat) : P Nat := do
  match ← peek with
  | some c => if '0' ≤ c && c ≤ '9' then do let _ ← next; digits (n * 10 + (c.toNat - '0'.toNat)) else return n
  | none => return n

mutual
partial def value : P J := do
  ws
  match ← peek with
  | some '{' => let _ ← next; ws; if (← peek) == some '}' then (do let _ ← next; return .obj []) else members []
  | some '[' => let _ ← next; ws; if (← peek) == some ']' then (do let _ ← next; return .arr []) else elems []
  | some '"' => let _ ← next; return .str (← strBody [])
  | some 't' => word "true"; return .bool true
  | some 'f' => word "false"; return .bool false
  | some 'n' => word "null"; return .null
  | some c =>
    if '0' ≤ c && c ≤ '9' then do
      let n ← digits 0
      if (← peek) == some '.' then          -- a fraction (time.time()): keep the whole seconds
        let _ ← next
        let _ ← digits 0
      return .num n
    else throw s!"unexpected {c}"
  | none => throw "unexpected end"

partial def members (acc : List (String × J)) : P J := do
  ws; expect '"'
  let k ← strBody []
  ws; expect ':'
  let v ← value
  ws
  match ← next with
  | ',' => members ((k, v) :: acc)
  | '}' => return .obj ((k, v) :: acc).reverse
  | _ => throw "expected , or }"

partial def elems (acc : List J) : P J := do
  let v ← value
  ws
  match ← next with
  | ',' => elems (v :: acc)
  | ']' => return .arr (v :: acc).reverse
  | _ => throw "expected , or ]"
end

def parse (s : String) : Except String J := do
  let (v, rest) ← (do let v ← value; ws; return v).run s.toList
  if rest.isEmpty then return v else throw "trailing input"

def esc (s : String) : String :=
  s.foldl (fun acc c =>
    if c == '"' then acc ++ "\\\"" else if c == '\\' then acc ++ "\\\\"
    else if c.toNat < 32 then
      let d := String.ofList (Nat.toDigits 16 c.toNat)
      acc ++ "\\u" ++ String.ofList (List.replicate (4 - d.length) '0') ++ d
    else acc.push c) ""

partial def render : J → String
  | .null => "null"
  | .bool b => if b then "true" else "false"
  | .num n => toString n
  | .str s => "\"" ++ esc s ++ "\""
  | .arr xs => "[" ++ ",".intercalate (xs.map render) ++ "]"
  | .obj kvs => "{" ++ ",".intercalate (kvs.map fun (k, v) => "\"" ++ esc k ++ "\":" ++ render v) ++ "}"

def get? (j : J) (k : String) : Option J :=
  match j with
  | .obj kvs => kvs.lookup k
  | _ => none

end J

open Zenos

namespace ZenosDecide

def field (j : J) (k : String) : Except String J :=
  match j.get? k with
  | some v => pure v
  | none => throw s!"missing {k}"

def getS (j : J) (k : String) : Except String String := do
  match ← field j k with | .str s => pure s | _ => throw s!"{k}: not a string"
def getN (j : J) (k : String) : Except String Nat := do
  match ← field j k with | .num n => pure n | _ => throw s!"{k}: not a number"
def getB (j : J) (k : String) : Except String Bool := do
  match ← field j k with | .bool b => pure b | _ => throw s!"{k}: not a boolean"
def getArr (j : J) (k : String) : Except String (List J) := do
  match ← field j k with | .arr xs => pure xs | _ => throw s!"{k}: not an array"
def getSs (j : J) (k : String) : Except String (List String) := do
  (← getArr j k).mapM fun | .str s => pure s | _ => throw s!"{k}: not a list of strings"

def approval (j : J) : Except String Approval := do
  return { approver := ← getS j "approver", sigOk := ← getB j "sig_ok" }

def approvalsOf (j : J) (k : String) : Except String (List Approval) := do
  (← getArr j k).mapM approval

def grant (j : J) : Except String Grant := do
  let kind ← match j.get? "kind" with
    | none | some .null => pure none
    | some (.str k) => pure (some k)
    | some _ => throw "kind: not a string"
  return { requester := ← getS j "requester", holder := ← getS j "holder", fileHash := ← getS j "file_hash",
           level := ← getN j "level", kind, expires := ← getN j "expires", digestOk := ← getB j "digest_ok",
           approvals := ← approvalsOf j "approvals" }

def status : String → Except String Status
  | "pending" => pure .pending
  | "declined" => pure .declined
  | "approved" => pure .approved
  | s => throw s!"unknown status {s}"

def request (j : J) : Except String Request := do
  return { id := ← getS j "id", requester := ← getS j "requester", level := ← getN j "level",
           required := ← getN j "required", status := ← status (← getS j "status"),
           approvals := ← approvalsOf j "approvals" }

def openReq (j : J) : Except String OpenReq := do
  let g ← match j.get? "grant" with
    | none | some .null => pure none
    | some v => some <$> grant v
  return { user := ← getS j "user", clearance := ← getN j "clearance", level := ← getN j "level",
           fileHash := ← getS j "file_hash", now := ← getN j "now", halted := ← getB j "halted",
           roster := ← getSs j "roster", grant := g }

def decisionJ : Decision → J
  | .byClearance => .obj [("allow", .bool true), ("by", .str "clearance"), ("reason", .null)]
  | .byGrant => .obj [("allow", .bool true), ("by", .str "grant"), ("reason", .null)]
  | .refuse r => .obj [("allow", .bool false), ("by", .null), ("reason", .str r)]

def presence (j : J) : Except String Presence := do
  return { registered := ← getB j "registered", sigOk := ← getB j "sig_ok", challengeOk := ← getB j "challenge_ok",
           originOk := ← getB j "origin_ok", userVerified := ← getB j "user_verified",
           counterOk := ← getB j "counter_ok" }

def installReq (j : J) : Except String InstallReq := do
  let votes ← (← getArr j "votes").mapM fun v => do
    return ({ node := ← getS v "node", sigOk := ← getB v "sig_ok", record := ← getS v "record" } : Vote)
  return { nodes := ← getSs j "nodes", votes, record := ← getS j "record", hashOk := ← getB j "hash_ok",
           signers := ← getSs j "signers", officers := ← getSs j "officers",
           required := ← getN j "required", revoked := ← getB j "revoked",
           ringOpen := ← getN j "ring_open", now := ← getN j "now" }

def installJ : InstallDecision → J
  | .allow => .obj [("allow", .bool true), ("reason", .null)]
  | .refuse why => .obj [("allow", .bool false), ("reason", .str why)]

def answer (j : J) : Except String J := do
  match ← getS j "op" with
  | "open" => return decisionJ (decideOpen (← openReq j))
  | "key" =>
    let p ← match j.get? "presence" with
      | none | some .null => pure none
      | some v => some <$> presence v
    let k : KeyReq := { enrolled := ← getB j "enrolled", sigOk := ← getB j "sig_ok", fresh := ← getB j "fresh",
                        now := ← getN j "now", lastSeen := ← getN j "last_seen", silence := ← getN j "silence",
                        servicesOk := ← getB j "services_ok", pcHalted := ← getB j "pc_halted",
                        recent := ← getN j "recent", rateMax := ← getN j "rate_max",
                        machineRecent := ← getN j "machine_recent", machineRateMax := ← getN j "machine_rate_max",
                        assigned := ← getB j "assigned",
                        presenceFrom := ← getN j "presence_from", presence := p, openReq := ← openReq (← field j "open") }
    return decisionJ (decideKey k)
  | "install" =>
    let votes ← (← getArr j "votes").mapM fun v => do
      return ({ node := ← getS v "node", sigOk := ← getB v "sig_ok", record := ← getS v "record" } : Vote)
    let r : InstallReq := { nodes := ← getSs j "nodes", votes, record := ← getS j "record", hashOk := ← getB j "hash_ok",
                            signers := ← getSs j "signers", officers := ← getSs j "officers",
                            required := ← getN j "required", revoked := ← getB j "revoked",
                            ringOpen := ← getN j "ring_open", now := ← getN j "now" }
    return match decideInstall r with
      | .allow => .obj [("allow", .bool true), ("reason", .null)]
      | .refuse why => .obj [("allow", .bool false), ("reason", .str why)]
  | "model" =>
    return installJ (decideModel { ledger := ← installReq j, kindOk := ← getB j "kind_ok", filesOk := ← getB j "files_ok",
                                   level := ← getN j "level", maxLevel := ← getN j "max_level" })
  | "model_api" =>
    return installJ (decideApiModel { ledger := ← installReq j, kindOk := ← getB j "kind_ok",
                                      sameModel := ← getB j "same_model", denied := ← getB j "denied",
                                      level := ← getN j "level", maxLevel := ← getN j "max_level" })
  | "route" =>
    let frags ← (← getArr j "frags").mapM fun f => do
      let atoms ← (← getArr f "atoms").mapM fun a => do
        let role ← match ← getS a "role" with
          | "ident" => pure Role.ident
          | "attr" => pure Role.attr
          | "other" => pure Role.other
          | x => throw s!"unknown role {x}"
        return ({ record := ← getS a "record", role } : Atom)
      return ({ atoms, to := ← getS f "to" } : Fragment)
    let r : RouteReq := { allowed := ← getSs j "allowed", frags }
    return match decideRoute r with
      | .allow => .obj [("allow", .bool true), ("reason", .null)]
      | .refuse why => .obj [("allow", .bool false), ("reason", .str why)]
  | "vote" =>
    let ws ← (← getArr j "weights").mapM fun w => do return (← getS w "provider", ← getN w "weight")
    let bs ← (← getArr j "ballots").mapM fun b => do
      return ({ provider := ← getS b "provider", answer := ← getS b "answer" } : Ballot)
    return .obj [("accept", .bool (decideVote { weights := ws, ballots := bs, answer := ← getS j "answer" }))]
  | "step" =>
    let kind ← match ← getS j "kind" with
      | "send" => pure StepKind.send
      | "tool" => pure StepKind.tool
      | "act" => pure StepKind.act
      | x => throw s!"unknown kind {x}"
    let level ← match ← getS j "level" with
      | "masked" => pure Level.masked
      | "split" => pure Level.split
      | "pc" => pure Level.onPC
      | x => throw s!"unknown level {x}"
    let r : StepReq := { kind, level, provider := ← getS j "provider", allowed := ← getSs j "allowed",
                         payloadMasked := ← getB j "payload_masked", routeOk := ← getB j "route_ok",
                         dest := ← getS j "dest", dests := ← getSs j "dests", afterTaint := ← getSs j "after_taint",
                         tainted := ← getB j "tainted", confirmed := ← getB j "confirmed" }
    return match decideStep r with
      | .allow => .obj [("allow", .bool true), ("reason", .null)]
      | .refuse why => .obj [("allow", .bool false), ("reason", .str why)]
  | "federate" =>
    let members ← (← getArr j "members").mapM fun m => do
      let sigs ← (← getArr m "sigs").mapM fun g => do return ({ signer := ← getS g "by", ok := ← getB g "ok" } : FedSig)
      return ({ org := ← getS m "org", maxLevel := ← getN m "max_level", publishOnly := ← getB m "publish_only", sigs } : Member)
    let kind ← match ← getS j "kind" with
      | "message" => pure FedKind.message
      | "keys" => pure FedKind.keys
      | "alert" => pure FedKind.alert
      | x => throw s!"unknown kind {x}"
    let r : FedReq := { authorities := ← getSs j "authorities", k := ← getN j "k", members, fromOrg := ← getS j "from",
                        toOrg := ← getS j "to", relaySigOk := ← getB j "relay_sig_ok", fresh := ← getB j "fresh",
                        kind, level := ← getN j "level" }
    return match decideFederate r with
      | .allow => .obj [("allow", .bool true), ("reason", .null)]
      | .refuse why => .obj [("allow", .bool false), ("reason", .str why)]
  | "place" =>
    let r : PlaceReq := { baseAllow := ← getB j "base_allow", level := ← getN j "level",
                          zoneRequired := ← getB j "zone_required", gpsInside := ← getB j "gps_inside",
                          proofInside := ← getB j "proof_inside", abroad := ← getB j "abroad",
                          closeAbroadFrom := ← getN j "close_abroad_from", emergency := ← getB j "emergency",
                          emergencyShare := ← getB j "emergency_share" }
    return match decidePlace r with
      | .allow => .obj [("allow", .bool true), ("reason", .null)]
      | .refuse why => .obj [("allow", .bool false), ("reason", .str why)]
  | "sysegress" =>
    let e : SysEgress := { system := ← getB j "system", listed := ← getB j "listed", loopback := ← getB j "loopback",
                           enforce := ← getB j "enforce" }
    return .obj [("cut", .bool (decideSysEgress e))]
  | "approve" =>
    let act ← match ← getS j "act" with
      | "approve" => pure Act.approve
      | "decline" => pure Act.decline
      | a => throw s!"unknown act {a}"
    let a : ApproveReq := { request := ← request (← field j "request"), roster := ← getSs j "roster",
                            who := ← getS j "who", act, sigOk := ← getB j "sig_ok", codeOk := ← getB j "code_ok" }
    return match decideApprove a with
      | .added => .obj [("result", .str "added"), ("reason", .null)]
      | .declined => .obj [("result", .str "declined"), ("reason", .null)]
      | .refused r => .obj [("result", .str "refused"), ("reason", .str r)]
  | "release" =>
    let r ← request (← field j "request")
    let roster ← getSs j "roster"
    return .obj [("release", .bool (decideRelease (← getB j "halted") r roster)),
                 ("approvers", .arr ((approvers roster r.requester r.approvals).map .str))]
  | "required" =>
    return .obj [("required", .num (required (← getN j "level")))]
  | "release-required" =>
    return .obj [("required", .num (releaseRequired (← getSs j "roster") (← getS j "requester") (← getN j "level")))]
  | "flow" =>
    let sink ← match ← getS j "sink" with
      | "folder" => pure (Sink.folder (← getN j "level"))
      | "window" => pure (Sink.window (← getN j "level"))
      | "clipboard" => pure Sink.systemClipboard
      | "printer" => pure Sink.printer
      | "external-ai" => pure Sink.externalAI
      | "gov-ai" => pure Sink.govAI
      | "ministry-ai" => pure Sink.ministryAI
      | k => throw s!"unknown sink {k}"
    return .obj [("allow", .bool (mayFlow (← getN j "print_max") (← getN j "src") sink))]
  | "chain" =>
    let recs ← (← getArr j "records").mapM fun r => do
      return ({ prev := ← getS r "prev", hash := ← getS r "hash", hashOk := ← getB r "hash_ok" } : Rec)
    let start ← getS j "start"
    return match chainCheck start recs 0 with
      | none => .obj [("ok", .bool true), ("index", .null), ("reason", .str "intact"),
                      ("head", .str (chainHead start recs))]
      | some (i, why) => .obj [("ok", .bool false), ("index", .num i), ("reason", .str why), ("head", .null)]
  | "send" =>
    let r : SendReq := { sealed := ← getB j "sealed", sigOk := ← getB j "sig_ok", size := ← getN j "size",
                         hugeMax := ← getN j "huge_max", planOk := ← getB j "plan_ok" }
    return match decideSend r with
      | .allow => .obj [("allow", .bool true), ("reason", .str "sealed-ok")]
      | .deny why => .obj [("allow", .bool false), ("reason", .str why)]
  | "cred" =>
    let q ← field j "request"
    let a ← field j "answer"
    let devs ← (← getArr j "devices").mapM fun d => do return (← getS d "device", ← getS d "user")
    let r : CredReq := { id := ← getS q "id", user := ← getS q "user", origin := ← getS q "origin",
                         entryOrigin := ← getS q "entry_origin", tlsOk := ← getB q "tls_ok", code := ← getN q "code",
                         created := ← getN q "created" }
    let ans : CredAnswer := { device := ← getS a "device", sigOk := ← getB a "sig_ok",
                              challengeOk := ← getB a "challenge_ok", originOk := ← getB a "origin_ok",
                              userVerified := ← getB a "user_verified", counterOk := ← getB a "counter_ok",
                              code := ← getN a "code" }
    let st : CredState := { used := ← getSs j "used", devices := devs }
    return match decideCred (← getN j "ttl") (← getN j "now") st r ans with
      | .allow => .obj [("allow", .bool true), ("reason", .str "approved-on-phone")]
      | .deny why => .obj [("allow", .bool false), ("reason", .str why)]
  | "ask" =>
    let log ← (← getArr j "log").mapM fun v => match v with
      | .num n => pure n
      | _ => throw "log: numbers"
    return .obj [("allow", .bool (decideAsk (← getN j "window") (← getN j "max") (← getN j "now") log))]
  | op => throw s!"unknown op {op}"

/-- The network sentinel's stream: one send per line, one answer per line, state kept between lines. -/
partial def egressLoop (w thr : Nat) (inp : IO.FS.Stream) (out : IO.FS.Stream) (st : EState) : IO Unit := do
  let line ← inp.getLine
  if line.isEmpty then return
  let f := (String.ofList (line.toList.filter fun c => c != '\n' && c != '\r')).splitOn "\t"
  let st' ← match f with
    | [key, dst, allowed, t, size] =>
      match t.toNat?, size.toNat? with
      | some t, some size =>
        let (st', cut) := egressStep w thr st { key, dst, allowed := allowed == "1", t, size }
        out.putStrLn (if cut then "cut" else "ok")
        pure st'
      | _, _ => out.putStrLn "error"; pure st
    | _ => out.putStrLn "error"; pure st
  out.flush
  egressLoop w thr inp out st'

end ZenosDecide

open ZenosDecide in
def main (args : List String) : IO UInt32 := do
  if let ["egress", w, thr] := args then
    match w.toNat?, thr.toNat? with
    | some w, some thr => egressLoop w thr (← IO.getStdin) (← IO.getStdout) { win := [], cut := [] }; return 0
    | _, _ => IO.eprintln "usage: zenos-decide egress WINDOW_MS THRESHOLD_BYTES"; return 2
  let input ← (← IO.getStdin).readToEnd
  match (J.parse input).bind answer with
  | .ok j => IO.println j.render; return 0
  | .error e => IO.println (J.render (.obj [("error", .str e)])); return 2

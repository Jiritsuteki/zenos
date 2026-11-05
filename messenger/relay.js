// ZENOS Messages relay (PoC).
// It only ever sees ciphertext: it stores public key bundles and queues encrypted envelopes.
// It records metadata (who, to whom, when, size) to the audit log, never the content.
// Production: run by each ministry on its own server. Every request made for an account is signed by the device the
// account is registered on (see "device binding" below).
"use strict";
require("./distrust");   // refuse compromised CA keys on every TLS connection
const http = require("http");
const fs = require("fs");
const path = require("path");

const HOME = process.env.HOME;
const DIR = path.join(HOME, ".local/share/zenos/msg/relay");
const AUDIT = path.join(HOME, ".local/share/zenos/audit.log");
fs.mkdirSync(DIR, { recursive: true });
const BUNDLES = path.join(DIR, "bundles.json");
const QUEUE = path.join(DIR, "queue.json");
const load = (f, d) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return d; } };
let bundles = load(BUNDLES, {});
let queue = load(QUEUE, {});
const CHANNELS = path.join(DIR, "channels.json");
let channels = load(CHANNELS, {});
// ---------- phone-number accounts (Signal model) ----------
// One phone number = one account (no impersonation: a verified number cannot be claimed by another account).
// The number is never listed to others; people find you by username, or by number only if you allow it.
const crypto = require("crypto");
const PHONES = path.join(DIR, "phones.json");
let phones = load(PHONES, {});                  // e164 -> { id, verified, via, at }
const pending = {};
const lookups = {};                             // caller -> recent lookup times                             // e164 -> { id, hash, exp, tries }
const savePhones = () => fs.writeFileSync(PHONES, JSON.stringify(phones), { mode: 0o600 });
const E164 = /^\+[1-9]\d{7,14}$/;
const UNAME = /^[a-z_][a-z0-9_]{2,29}\.\d{2,9}$/;
const OUTBOX = path.join(DIR, "sms-outbox.log");
async function deliverSms(to, text) {
  // Production: set ZENOS_SMS_WEBHOOK to the ministry's SMS gateway. Until then codes go to a local outbox on this PC only.
  const hook = process.env.ZENOS_SMS_WEBHOOK;
  if (hook) {
    const r = await fetch(hook, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ to, text }) });
    if (!r.ok) throw new Error("SMS gateway refused (" + r.status + ")");
    return "sms";
  }
  fs.appendFileSync(OUTBOX, `${stamp()} [NOT SENT - no SMS gateway] to ${to}: ${text}\n`, { mode: 0o600 });
  return "dev-outbox";
}
const pub = (id) => { const b = bundles[id]; if (!b) return null;
  const ph = Object.keys(phones).find((k) => phones[k].id === id);
  return { id, name: b.name, level: b.level, username: b.username || null, org: b.org || "", phoneVerified: !!(ph && phones[ph].verified) }; };
// second approver: a member cleared for the channel; while the channel has fewer than two cleared members,
// a colleague in the requester's organisation with enough clearance may approve instead.
function canApprove(c, who, pd) {
  const w = bundles[who]; if (!w || who === pd.by || (w.level || 1) < (c.level || 1)) return false;
  if (c.members.includes(who)) return true;
  const cleared = c.members.filter((m) => bundles[m] && (bundles[m].level || 1) >= (c.level || 1)).length;
  return cleared < 2 && (w.org || "") === ((bundles[pd.by] || {}).org || "");
}
const RETENTION_MS = 14 * 24 * 3600 * 1000;   // drop envelopes never collected within 14 days
// ---------- stage 1: the relay delivers to random mailboxes and never learns who sent a message ----------
// mailbox id -> { owner: sha256(owner token), uak: sha256(access key) | null for the public "intro" mailbox }
const MBX = path.join(DIR, "mailboxes.json"); let mailboxes = load(MBX, {});
const SQ = path.join(DIR, "sealed-queue.json"); let squeue = load(SQ, {});
const saveM = () => { fs.writeFileSync(MBX, JSON.stringify(mailboxes), { mode: 0o600 }); fs.writeFileSync(SQ, JSON.stringify(squeue), { mode: 0o600 }); };
const H = (x) => require("crypto").createHash("sha256").update(String(x)).digest("hex");
const introHits = {};
// sender certificates (Signal sealed sender): issued daily per account; the account is visible only at issuance, never per message
const SS = require("@signalapp/libsignal-client");
const CAF = path.join(DIR, "ca.json");
let ca = load(CAF, null);
if (!ca) {
  const trust = SS.PrivateKey.generate(), srv = SS.PrivateKey.generate();
  const sc = SS.ServerCertificate.new(1, srv.getPublicKey(), trust);
  ca = { trustPub: Buffer.from(trust.getPublicKey().serialize()).toString("base64"), trustPriv: Buffer.from(trust.serialize()).toString("base64"),
         srvPriv: Buffer.from(srv.serialize()).toString("base64"), srvCert: Buffer.from(sc.serialize()).toString("base64") };
  fs.writeFileSync(CAF, JSON.stringify(ca), { mode: 0o600 });   // production: the trust root lives offline / in an HSM, not on the relay
}
const BLOBS = path.join(DIR, "blobs"); fs.mkdirSync(BLOBS, { recursive: true });
const MAX_BLOB = 26 * 1024 * 1024;
function sweepBlobs() {
  const cutoff = Date.now() - RETENTION_MS; let n = 0;
  for (const f of fs.readdirSync(BLOBS)) { const p = path.join(BLOBS, f); if (fs.statSync(p).mtimeMs < cutoff) { fs.unlinkSync(p); n++; } }
  if (n) audit("msg-blob-retention-drop", { dropped: n });
}
function sweep() {
  const cutoff = Date.now() - RETENTION_MS; let dropped = 0;
  for (const to of Object.keys(queue)) {
    const before = queue[to].length;
    queue[to] = queue[to].filter((e) => new Date(e.t).getTime() >= cutoff);
    dropped += before - queue[to].length;
    if (!queue[to].length) delete queue[to];
  }
  for (const k of Object.keys(squeue)) { const b = squeue[k].length; squeue[k] = squeue[k].filter((e) => new Date(e.t).getTime() >= cutoff); dropped += b - squeue[k].length; if (!squeue[k].length) delete squeue[k]; }
  if (dropped) audit("msg-retention-drop", { dropped });
}
const save = () => { fs.writeFileSync(BUNDLES, JSON.stringify(bundles)); fs.writeFileSync(QUEUE, JSON.stringify(queue)); fs.writeFileSync(CHANNELS, JSON.stringify(channels)); };

function stamp() {
  const d = new Date(), p = (n) => String(n).padStart(2, "0");
  const off = -d.getTimezoneOffset(), s = off >= 0 ? "+" : "-";
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${s}${p(Math.floor(Math.abs(off) / 60))}${p(Math.abs(off) % 60)}`;
}
function audit(event, kw) {
  const rec = { t: stamp(), user: "relay", event, ...kw };
  fs.appendFileSync(AUDIT, JSON.stringify(rec) + "\n");
}
// a request body: at most 1 MiB, and JSON; anything else is refused with 413/400 (never an uncaught error that stops the relay)
const MAX_BODY = 1 << 20;
function body(req) {
  return new Promise((res, rej) => {
    let b = "", n = 0, over = false;
    req.on("data", (c) => { if (over) return; n += c.length; if (n > MAX_BODY) { over = true; b = ""; return; } b += c; });
    req.on("end", () => {
      if (over) return rej(Object.assign(new Error("The request is too large."), { status: 413 }));
      req.raw = b;
      try { const o = b ? JSON.parse(b) : {}; if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("not an object"); res(o); }
      catch { rej(Object.assign(new Error("The request is not valid JSON."), { status: 400 })); }
    });
    req.on("error", rej);
  });
}
// ---------- who an account is: name, organization and clearance come from the relay's directory, never from the account
// The directory (directory.json next to the relay's data, or ZENOS_RELAY_DIRECTORY) is kept by the relay's administrator;
// an account it does not list is L1 with no organization, whatever its bundle claims.
const DIRF = process.env.ZENOS_RELAY_DIRECTORY || path.join(DIR, "directory.json");
const directory = () => { const d = load(DIRF, {}); return d && typeof d === "object" ? d : {}; };
function vetted(acc, nb) {
  const d = directory()[acc];
  nb.level = d ? Math.max(1, Math.min(5, Math.floor(Number(d.level)) || 1)) : 1;
  nb.org = d ? String(d.org || "").slice(0, 120) : "";
  nb.name = String((d && d.name) || nb.name || acc).slice(0, 120);
  return nb;
}
for (const k of Object.keys(bundles)) vetted(k, bundles[k]);
// ---------- device binding: an account belongs to the identity key it first registered with ----------
// Requests made for an account carry "X-Zenos-Auth: <account> <ms> <sig>", the identity key's signature over
// "<METHOD> <path> <ms> <sha256(body)>". Requests older than five minutes, or seen before, are refused.
// A new device takes an account over only after verifying the number already registered to it (Signal model).
const SEEN = new Map();
const rebind = {};                                   // account -> until (ms): a new device may publish a new identity key
function authed(req, acc) {
  const [a, ts, sig] = String(req.headers["x-zenos-auth"] || "").split(" ");
  const b = bundles[acc];
  if (!acc || a !== acc || !b || !b.identity || !sig || Math.abs(Date.now() - Number(ts)) > 300e3 || SEEN.has(sig)) return false;
  try {
    const ok = SS.PublicKey.deserialize(Buffer.from(b.identity, "base64")).verify(Buffer.from(`${req.method} ${req.url} ${ts} ${H(req.raw || "")}`), Buffer.from(sig, "base64"));
    if (ok) { const now = Date.now(); SEEN.set(sig, now); for (const [k, t] of SEEN) if (now - t > 600e3) SEEN.delete(k); }
    return ok;
  } catch { return false; }
}
function refuse(res, acc, what) {
  audit("msg-auth-refused", { account: acc || null, what });
  return send(res, 403, { error: "This request is not signed by the device this account is registered on." });
}
// relay administration (call servers, channel seeding): a token kept next to the relay's data, readable only on its host
const ADMINF = path.join(DIR, "admin.token");
if (!fs.existsSync(ADMINF)) fs.writeFileSync(ADMINF, crypto.randomBytes(24).toString("hex"), { mode: 0o600 });
const ADMIN = (process.env.ZENOS_RELAY_ADMIN || fs.readFileSync(ADMINF, "utf8")).trim();
const isAdmin = (req) => !!ADMIN && req.headers["x-zenos-admin"] === ADMIN;
// enrollment: with ZENOS_RELAY_ENROLL=1 a new account needs a one-time code the administrator issued for that name
const ENROLL_REQUIRED = process.env.ZENOS_RELAY_ENROLL === "1";
const ENROLLF = path.join(DIR, "enroll.json"); let enrolls = load(ENROLLF, {});   // account -> { hash, exp }
const saveEnroll = () => fs.writeFileSync(ENROLLF, JSON.stringify(enrolls), { mode: 0o600 });
function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(b);
}


// ---------- sealed delivery into a mailbox (from a device here, or from another organization's relay) ----------
function deliverSealed(mbx, uak, b64body) {
  const mb = mailboxes[mbx];
  if (!mb || typeof b64body !== "string") return { status: 404, body: { error: "unknown mailbox" } };
  if (mb.uak) { if (H(uak || "") !== mb.uak) return { status: 403, body: { error: "bad access key" } }; }
  else { const now = Date.now(); introHits[mbx] = (introHits[mbx] || []).filter((x) => now - x < 60e3);
         if (introHits[mbx].length >= 60) return { status: 429, body: { error: "slow down" } }; introHits[mbx].push(now); }
  sweep();
  (squeue[mbx] = squeue[mbx] || []).push({ body: b64body, t: stamp() }); saveM();
  audit("msg-sealed-delivered", { mailbox: mbx.slice(0, 8), bytes: Buffer.from(b64body, "base64").length });
  return { status: 200, body: { ok: true } };
}
function bundleFor(acc) {                    // a key bundle for a new session; the one-time prekey is used up
  const b = bundles[acc];
  if (!b) return null;
  const out = { ...b, preKey: (b.preKeys || []).shift() || null };
  delete out.preKeys; delete out.enroll;
  save();
  return out;
}
// ---------- organizations reaching each other (federation.js, docs/FEDERATION.md) ----------
// an encrypted attachment for another organization's relay: the ciphertext and the level its sender gave it
function blobFor(id) {
  if (!/^[0-9a-f]{32}$/.test(id || "")) return null;
  const p = path.join(BLOBS, id);
  if (!fs.existsSync(p)) return null;
  let level = 5; try { level = Number(fs.readFileSync(p + ".level", "utf8")) || 5; } catch {}
  return { data: fs.readFileSync(p), level };
}
const fed = require("./federation").federation({ DIR, audit, send, body, isAdmin, authed, deliverSealed, bundleFor, blobFor, trust: ca.trustPub,
  levelOf: (a) => (bundles[a] || {}).level || 1 });

// ---------- calls (WebRTC via self-hosted LiveKit SFU). The relay only decides WHO may enter a room;
// media is end-to-end encrypted with a key that travels inside libsignal messages, never through here.
const LKENV = (() => { try { return Object.fromEntries(fs.readFileSync(path.join(HOME, ".local/share/zenos/livekit/keys.env"), "utf8").trim().split("\n").map((l) => l.split("="))); } catch { return {}; } })();
const roomFor = (s) => crypto.createHash("sha256").update("zenos-call|" + s).digest("hex").slice(0, 20);
// Call servers are selectable, like relays: this PC's own LiveKit, LiveKit Cloud, or a ministry's own server.
// Each has a ceiling (maxLevel): a third-party cloud only carries low-level calls. Secrets never leave this file.
const CALLCFG = path.join(DIR, "callservers.json");
let callcfg = load(CALLCFG, null);
if (!callcfg) { callcfg = { selected: "local", servers: { local: { name: "This PC (self-hosted LiveKit)", url: "", key: LKENV.LK_KEY || "", secret: LKENV.LK_SECRET || "", maxLevel: 5, kind: "local" } } }; fs.writeFileSync(CALLCFG, JSON.stringify(callcfg), { mode: 0o600 }); }
const saveCall = () => fs.writeFileSync(CALLCFG, JSON.stringify(callcfg), { mode: 0o600 });
const callPub = () => ({ selected: callcfg.selected, servers: Object.entries(callcfg.servers).map(([id, v]) => ({ id, name: v.name, url: v.url, maxLevel: v.maxLevel, kind: v.kind })) });
// what the call server sees instead of names: a per-room pseudonym (members map it back on their own devices)
const pseudo = (room, acc) => "p" + crypto.createHash("sha256").update("zenos-pseudo|" + (callcfg.salt || (callcfg.salt = crypto.randomBytes(16).toString("hex"), saveCall(), callcfg.salt)) + "|" + room + "|" + acc).digest("hex").slice(0, 16);
http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, "http://x");
    const parts = u.pathname.split("/").filter(Boolean);
    if (await fed(req, res, u, parts)) return;
    if (parts[0] === "call" && parts[1] === "servers") {
      // management is only reachable from this PC (client.js forwards it for the local, non-remote UI only)
      if (req.method === "GET") return send(res, 200, callPub());
      const b = await body(req);
      if (!isAdmin(req)) { audit("msg-auth-refused", { what: "call-servers" }); return send(res, 403, { error: "Call servers are managed on the relay's own host." }); }
      if (b.select) { if (!callcfg.servers[b.select]) return send(res, 404, { error: "Unknown call server." }); callcfg.selected = b.select; saveCall(); audit("msg-callserver-selected", { id: b.select }); return send(res, 200, callPub()); }
      if (b.add) {
        const a = b.add; if (!/^wss:\/\/[a-z0-9.-]+(:\d+)?\/?$/i.test(a.url || "")) return send(res, 400, { error: "The address must start with wss://" });
        if (!a.key || !a.secret) return send(res, 400, { error: "API key and secret are needed." });
        const id = (String(a.name || "server").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "server").slice(0, 30);
        callcfg.servers[id] = { name: String(a.name || id).slice(0, 60), url: a.url.replace(/\/$/, ""), key: String(a.key).trim(), secret: String(a.secret).trim(), maxLevel: Math.max(1, Math.min(5, Number(a.maxLevel) || 2)), kind: "external" };
        callcfg.selected = id; saveCall(); audit("msg-callserver-added", { id, maxLevel: callcfg.servers[id].maxLevel }); return send(res, 200, callPub());
      }
      if (b.remove && b.remove !== "local") { delete callcfg.servers[b.remove]; if (callcfg.selected === b.remove) callcfg.selected = "local"; saveCall(); return send(res, 200, callPub()); }
      return send(res, 400, { error: "Nothing to do." });
    }
    if (req.method === "POST" && parts[0] === "call" && parts[1] === "token") {
      const { ch, acc, peer } = await body(req);
      const me = bundles[acc]; if (!me) return send(res, 403, { error: "Unknown account." });
      if (!authed(req, acc)) return refuse(res, acc, "call-token");
      const srv = callcfg.servers[callcfg.selected];
      if (!srv || !srv.key || !srv.secret) return send(res, 503, { error: "No call server is set up. Add one in Settings → Call server." });
      let room, level = 1;
      if (ch) {
        const c = channels[ch];
        if (!c || !c.members.includes(acc)) { audit("msg-call-refused", { acc, ch, reason: "not-member" }); return send(res, 403, { error: "Only members of this channel can join its call." }); }
        level = c.level || 1;
        if ((me.level || 1) < level) { audit("msg-call-refused", { acc, ch, reason: "clearance" }); return send(res, 403, { error: `This channel is L${level}; your clearance is L${me.level}.` }); }
        room = "c" + roomFor(ch);
      } else if (peer && bundles[peer]) room = "d" + roomFor([acc, peer].sort().join("|"));
      else return send(res, 400, { error: "Nothing to call." });
      if (level > (srv.maxLevel || 1)) return send(res, 403, { error: `The call server "${srv.name}" carries calls up to L${srv.maxLevel}. This one is L${level}.` });
      const { AccessToken } = require("livekit-server-sdk");
      const who = ch ? channels[ch].members : [acc, peer];
      const map = Object.fromEntries(who.map((m) => [pseudo(room, m), m]));
      const t = new AccessToken(srv.key, srv.secret, { identity: pseudo(room, acc), ttl: "2h" });   // no name: the server sees only a pseudonym
      t.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true, canPublishData: false });
      audit("msg-call-token", { acc, room: room.slice(0, 8), server: callcfg.selected });
      return send(res, 200, { room, level, token: await t.toJwt(), url: srv.url || null, map, server: srv.name });
    }
    if (req.method === "POST" && parts[0] === "register" && parts[1] === "start") {
      const { phone, id } = await body(req);
      if (!E164.test(phone || "")) return send(res, 400, { error: "Use the international format, e.g. +81 90 1234 5678." });
      const own = authed(req, id);
      const cur = Object.keys(phones).find((k) => phones[k].verified && phones[k].id === id);
      if (bundles[id] && !own && cur !== phone) return refuse(res, id, "register");   // only the device, or the account's own number
      if (phones[phone] && phones[phone].verified && phones[phone].id !== id) {
        audit("msg-register-conflict", { account: id });
        return send(res, 409, { error: "This number is already registered to another account." });
      }
      const code = String(crypto.randomInt(0, 1e6)).padStart(6, "0");
      pending[phone] = { id, hash: crypto.createHash("sha256").update(code).digest("hex"), exp: Date.now() + 10 * 60e3, tries: 0, own };
      try {
        const via = await deliverSms(phone, `ZENOS code: ${code}. Do not share this code with anyone.`);
        pending[phone].via = via;
        audit("msg-register-code-sent", { account: id, via });
        return send(res, 200, { ok: true, via });
      } catch (err) { return send(res, 502, { error: err.message }); }
    }
    if (req.method === "POST" && parts[0] === "register" && parts[1] === "verify") {
      const { phone, id, code } = await body(req);
      const p = pending[phone];
      if (!p || p.id !== id || Date.now() > p.exp) return send(res, 400, { error: "The code has expired. Send a new one." });
      if (++p.tries > 5) { delete pending[phone]; audit("msg-register-locked", { account: id }); return send(res, 429, { error: "Too many attempts. Send a new code." }); }
      if (crypto.createHash("sha256").update(String(code || "")).digest("hex") !== p.hash) return send(res, 400, { error: "That code is not right." });
      for (const k of Object.keys(phones)) if (phones[k].id === id && k !== phone) delete phones[k];
      phones[phone] = { id, verified: true, via: p.via, at: stamp() };
      delete pending[phone]; savePhones();
      const moving = !!bundles[id] && !p.own;              // verified from a new device with the account's own number
      if (moving) rebind[id] = Date.now() + 10 * 60e3;
      audit("msg-register-verified", { account: id, via: p.via, newDevice: moving });
      return send(res, 200, { ok: true, via: p.via, rebind: moving });
    }
    if (req.method === "GET" && parts[0] === "lookup") {           // same answer for "no such number" and "not findable"
      const caller = u.searchParams.get("by") || "?"; const now = Date.now();
      if (!authed(req, caller)) return refuse(res, caller, "lookup");
      lookups[caller] = (lookups[caller] || []).filter((x) => now - x < 10 * 60e3);
      if (lookups[caller].length >= 20) { audit("msg-lookup-throttled", { by: caller }); return send(res, 429, { error: "Too many lookups. Try again in a few minutes." }); }
      lookups[caller].push(now);
      const ph = u.searchParams.get("phone"), un = (u.searchParams.get("username") || "").toLowerCase();
      let id = null;
      if (ph && phones[ph] && phones[ph].verified && bundles[phones[ph].id] && bundles[phones[ph].id].findByPhone !== false) id = phones[ph].id;
      if (un) id = Object.keys(bundles).find((k) => (bundles[k].username || "") === un) || null;
      audit("msg-lookup", { by: ph ? "phone" : "username", found: !!id });
      return id ? send(res, 200, pub(id)) : send(res, 404, { error: "No one found. Check the number or username." });
    }
    if (req.method === "GET" && parts[0] === "phone") {             // the owner's own registration status
      if (!authed(req, parts[1])) return refuse(res, parts[1], "phone");
      const ph = Object.keys(phones).find((k) => phones[k].id === parts[1]);
      return send(res, 200, ph ? { phone: ph, ...phones[ph] } : { phone: null, verified: false });
    }
    if (req.method === "POST" && parts[0] === "enroll") {        // administrator: issue a one-time code for a new account
      const { account } = await body(req);
      if (!isAdmin(req)) { audit("msg-auth-refused", { what: "enroll" }); return send(res, 403, { error: "Enrollment codes are issued on the relay's own host." }); }
      if (!/^[a-z0-9_.-]{2,40}$/.test(account || "")) return send(res, 400, { error: "bad account name" });
      if (bundles[account]) return send(res, 409, { error: "This account is already registered." });
      const code = crypto.randomBytes(5).toString("hex");
      enrolls[account] = { hash: H(code), exp: Date.now() + 7 * 24 * 3600e3 }; saveEnroll();
      audit("msg-enroll-issued", { account });
      return send(res, 200, { account, code, expires: new Date(enrolls[account].exp).toISOString() });
    }
    if (req.method === "POST" && parts[0] === "directory") {     // administrator: an account's name, organization and clearance
      const { account, level, org, name } = await body(req);
      if (!isAdmin(req)) { audit("msg-auth-refused", { what: "directory" }); return send(res, 403, { error: "The directory is kept on the relay's own host." }); }
      if (!/^[a-z0-9_.-]{2,40}$/.test(account || "")) return send(res, 400, { error: "bad account name" });
      const d = directory(); d[account] = { level: Math.max(1, Math.min(5, Math.floor(Number(level)) || 1)), org: String(org || "").slice(0, 120), name: String(name || account).slice(0, 120) };
      fs.writeFileSync(DIRF, JSON.stringify(d), { mode: 0o600 });
      if (bundles[account]) { vetted(account, bundles[account]); save(); }
      audit("msg-directory-set", { account, level: d[account].level });
      return send(res, 200, { ok: true, ...d[account] });
    }
    if (req.method === "POST" && parts[0] === "keys") {          // publish a public key bundle
      const nb = await body(req);
      if (nb.username && !UNAME.test(nb.username)) return send(res, 400, { error: "bad username" });
      if (nb.username && Object.keys(bundles).some((k) => k !== parts[1] && bundles[k].username === nb.username)) return send(res, 409, { error: "username taken" });
      const old = bundles[parts[1]];
      if (!old && ENROLL_REQUIRED) {
        const e = enrolls[parts[1]];
        if (!e || e.exp < Date.now() || H(nb.enroll || "") !== e.hash) { audit("msg-keys-refused", { account: parts[1], reason: "not-enrolled" });
          return send(res, 403, { error: "This relay registers new accounts only with an enrollment code from the administrator." }); }
        delete enrolls[parts[1]]; saveEnroll(); audit("msg-enrolled", { account: parts[1] });
      }
      delete nb.enroll;
      if (old && old.identity) {
        if (nb.identity === old.identity) { if (!authed(req, parts[1])) return refuse(res, parts[1], "keys"); }
        else if ((rebind[parts[1]] || 0) > Date.now()) { delete rebind[parts[1]]; audit("msg-device-moved", { account: parts[1] }); }
        else { audit("msg-keys-refused", { account: parts[1], reason: "bound" });
               return send(res, 409, { error: "This account is registered on another device. Verify with the account's number to move it here." }); }
      }
      bundles[parts[1]] = vetted(parts[1], nb);
      save();
      audit("msg-keys-published", { account: parts[1] });
      return send(res, 200, { ok: true });
    }
    if (req.method === "GET" && parts[0] === "keys") {           // fetch a bundle (one-time prekey is used up)
      const out = bundleFor(parts[1]);
      return out ? send(res, 200, out) : send(res, 404, { error: "unknown account" });
    }
    if (req.method === "GET" && parts[0] === "accounts") {
      return send(res, 200, Object.keys(bundles).map(pub));
    }
    if (req.method === "GET" && parts[0] === "trust") return send(res, 200, { trust: ca.trustPub });
    if (req.method === "POST" && parts[0] === "cert") {              // the certificate key must be the identity key the account published
      const { acc, identity } = await body(req); const b = bundles[acc];
      if (!b || b.identity !== identity) return send(res, 403, { error: "identity mismatch" });
      const cert = SS.SenderCertificate.new(acc, null, 1, SS.PublicKey.deserialize(Buffer.from(identity, "base64")), Date.now() + 24 * 3600e3,
        SS.ServerCertificate.deserialize(Buffer.from(ca.srvCert, "base64")), SS.PrivateKey.deserialize(Buffer.from(ca.srvPriv, "base64")));
      audit("msg-cert-issued", { account: acc });
      return send(res, 200, { cert: Buffer.from(cert.serialize()).toString("base64"), exp: cert.expiration() });
    }
    if (req.method === "POST" && parts[0] === "mailbox") {           // register a mailbox: no account name is given
      const { id, owner, uak } = await body(req);
      if (!/^[0-9a-f]{32}$/.test(id || "") || !/^[0-9a-f]{64}$/.test(owner || "")) return send(res, 400, { error: "bad mailbox" });
      if (mailboxes[id] && mailboxes[id].owner !== owner) return send(res, 409, { error: "taken" });
      mailboxes[id] = { owner, uak: uak || null, t: stamp() }; saveM();
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && parts[0] === "deliver") {           // sealed envelope: the relay sees a mailbox id and a size, nothing else
      const e = await body(req); const r = deliverSealed(e.mbx, e.uak, e.body);
      return send(res, r.status, r.body);
    }
    if (req.method === "GET" && parts[0] === "collect") {             // only the holder of the owner token can empty a mailbox
      const mb = mailboxes[parts[1]];
      if (!mb || H(req.headers["x-owner"] || "") !== mb.owner) return send(res, 403, { error: "not yours" });
      const q = squeue[parts[1]] || []; squeue[parts[1]] = [];
      if (q.length) saveM();
      return send(res, 200, q);
    }
    if (req.method === "POST" && parts[0] === "blobs") {          // store an encrypted attachment; the key never comes here
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > MAX_BLOB) return send(res, 413, { error: "Attachment too large (max 25 MB)." }); chunks.push(c); }
      const id = require("crypto").randomBytes(16).toString("hex");
      fs.writeFileSync(path.join(BLOBS, id), Buffer.concat(chunks));
      // the level the sender gives the attachment: another organization's relay gets it only within that level
      const lv = Math.max(1, Math.min(5, Number(u.searchParams.get("level")) || 5));
      fs.writeFileSync(path.join(BLOBS, id + ".level"), String(lv)); sweepBlobs();
      audit("msg-blob-stored", { bytes: size });
      return send(res, 200, { id });
    }
    if (req.method === "GET" && parts[0] === "blobs" && /^[0-9a-f]{32}$/.test(parts[1] || "")) {
      const p = path.join(BLOBS, parts[1]);
      if (!fs.existsSync(p)) return send(res, 404, { error: "gone" });
      res.writeHead(200, { "Content-Type": "application/octet-stream" }); return res.end(fs.readFileSync(p));
    }
    if (req.method === "POST" && parts[0] === "send") {          // queue an encrypted envelope
      const e = await body(req);
      if (!bundles[e.to]) return send(res, 404, { error: "unknown account" });
      if (!authed(req, e.from)) return refuse(res, e.from, "send");
      const lv = Number(e.level) || 1;
      if (lv > (bundles[e.from].level || 1) || lv > (bundles[e.to].level || 1)) { audit("msg-refused", { from: e.from, to: e.to, level: lv, reason: "clearance" });
        return send(res, 403, { error: `L${lv} is above the clearance the directory gives the sender or the recipient.` }); }
      if (typeof e.body !== "string" || e.body.length > MAX_BODY) return send(res, 400, { error: "bad envelope" });
      sweep();
      (queue[e.to] = queue[e.to] || []).push({ from: e.from, type: e.type, body: e.body, level: e.level, t: stamp() });
      save();
      audit("msg-sent", { from: e.from, to: e.to, level: e.level, bytes: Buffer.from(e.body, "base64").length });
      return send(res, 200, { ok: true });
    }
    if (req.method === "GET" && parts[0] === "recv") {           // hand over and forget
      if (!authed(req, parts[1])) return refuse(res, parts[1], "recv");
      const q = queue[parts[1]] || [];
      queue[parts[1]] = [];
      if (q.length) { save(); audit("msg-delivered", { to: parts[1], count: q.length }); }
      return send(res, 200, q);
    }
    // ---------- membership guard (lesson of the 2025 US "Signalgate" chat, DODIG-2026-021) ----------
    // 1) clearance must cover the channel level  2) people outside the organisation cannot join L2+ channels
    // 3) L3+ needs a second person to approve (two-person rule)  4) every change is announced and audited
    if (req.method === "POST" && parts[0] === "channels" && parts[2] === "invite") {
      const c = channels[parts[1]]; const { by, target } = await body(req);
      if (!c) return send(res, 404, { error: "Unknown channel." });
      if (!authed(req, by)) return refuse(res, by, "invite");
      if (!c.members.includes(by)) return send(res, 403, { error: "Only members can add people." });
      const t = bundles[target]; if (!t) return send(res, 404, { error: "No such account." });
      if (c.members.includes(target)) return send(res, 409, { error: "Already a member." });
      const ext = (t.org || "") !== (bundles[by].org || "");
      const verdict = { target, name: t.name, level: t.level, org: t.org || "", external: ext };
      if ((t.level || 1) < (c.level || 1)) { audit("msg-invite-refused", { channel: c.id, by, target, reason: "clearance" });
        return send(res, 403, { ...verdict, error: `Blocked: ${t.name.split(" · ")[0]} has clearance L${t.level}; this channel is L${c.level}.` }); }
      if (ext && (c.level || 1) >= 2) { audit("msg-invite-refused", { channel: c.id, by, target, reason: "external" });
        return send(res, 403, { ...verdict, error: `Blocked: ${t.name.split(" · ")[0]} is outside your organisation (${t.org || "unknown"}). External people can only join L1 channels.` }); }
      if ((c.level || 1) >= 3) {
        c.pending = (c.pending || []).filter((x) => x.target !== target);
        c.pending.push({ target, by, t: stamp() }); (c.log = c.log || []).push({ t: stamp(), by, target, act: "requested", external: ext }); save();
        audit("msg-invite-pending", { channel: c.id, by, target });
        return send(res, 202, { ...verdict, pending: true });
      }
      c.members.push(target); (c.log = c.log || []).push({ t: stamp(), by, target, act: "added", external: ext }); save();
      audit("msg-member-added", { channel: c.id, by, target, external: ext });
      return send(res, 200, { ...verdict, added: true });
    }
    if (req.method === "POST" && parts[0] === "channels" && (parts[2] === "approve" || parts[2] === "deny")) {
      const c = channels[parts[1]]; const { by, target } = await body(req);
      if (!authed(req, by)) return refuse(res, by, "approve");
      const pd = c && (c.pending || []).find((x) => x.target === target);
      if (!pd) return send(res, 404, { error: "No such request." });
      if (pd.by === by) return send(res, 403, { error: "A second person must approve. You made this request." });
      if (!canApprove(c, by, pd)) return send(res, 403, { error: "Only a colleague cleared for this channel can approve." });
      c.pending = c.pending.filter((x) => x.target !== target);
      if (parts[2] === "approve") { c.members.push(target); (c.log = c.log || []).push({ t: stamp(), by: pd.by, approvedBy: by, target, act: "added" }); }
      else (c.log = c.log || []).push({ t: stamp(), by, target, act: "denied" });
      save(); audit(parts[2] === "approve" ? "msg-invite-approved" : "msg-invite-denied", { channel: c.id, requester: pd.by, approver: by, target });
      return send(res, 200, { ok: true, requester: pd.by });
    }
    if (req.method === "GET" && parts[0] === "approvals") {
      const who = u.searchParams.get("who"); const out = [];
      if (!authed(req, who)) return refuse(res, who, "approvals");
      for (const c of Object.values(channels)) for (const pd of (c.pending || [])) if (canApprove(c, who, pd))
        out.push({ ch: c.id, level: c.level, target: pd.target, by: pd.by, t: pd.t });
      return send(res, 200, out);
    }
    if (req.method === "POST" && parts[0] === "channels" && parts[2] === "remove") {
      const c = channels[parts[1]]; const { by, target } = await body(req);
      if (!authed(req, by)) return refuse(res, by, "remove");
      if (!c || !c.members.includes(by)) return send(res, 403, { error: "Only members can remove people." });
      c.members = c.members.filter((m) => m !== target); (c.log = c.log || []).push({ t: stamp(), by, target, act: "removed" }); save();
      audit("msg-member-removed", { channel: c.id, by, target }); return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && parts[0] === "invite-sms") {     // invite someone who is not on ZENOS yet
      const { by, phone } = await body(req);
      if (!authed(req, by)) return refuse(res, by, "invite-sms");
      if (!E164.test(phone || "")) return send(res, 400, { error: "Use the international format, e.g. +81 90 1234 5678." });
      if (phones[phone] && phones[phone].verified) return send(res, 409, { error: "This number is already on ZENOS. Search for them instead." });
      try { const via = await deliverSms(phone, `${(bundles[by] || {}).name || "A colleague"} invited you to ZENOS Messages. Install from your ministry's portal and register with this number.`);
        audit("msg-invite-sms", { by, via }); return send(res, 200, { ok: true, via }); }
      catch (err) { return send(res, 502, { error: err.message }); }
    }
    if (req.method === "POST" && parts[0] === "channels") {        // create/update a channel (metadata only; messages stay E2E, fanned out per member)
      const c = await body(req);
      if (c.by ? !authed(req, c.by) : !isAdmin(req)) return refuse(res, c.by, "channel-upsert");   // without "by": relay administration only
      const prev = channels[c.id] || {};
      if (prev.id && c.by && !prev.members.includes(c.by)) return send(res, 403, { error: "Only members can change a channel." });
      if (!prev.id && c.by && !/^[a-z0-9][a-z0-9-]{1,40}$/.test(c.id)) return send(res, 400, { error: "Use lowercase letters, numbers and dashes." });
      if (typeof c.id !== "string" || !c.id || c.id.length > 64) return send(res, 400, { error: "bad channel id" });
      const want = Math.max(1, Math.min(5, Math.floor(Number(c.level)) || 1));
      if (c.by && want > ((bundles[c.by] || {}).level || 1)) return send(res, 403, { error: `Your clearance is L${(bundles[c.by] || {}).level || 1}; a channel cannot be above it.` });
      // a member creates a channel with only themselves in it; everyone else comes in through invite (clearance,
      // organization and the second approver are checked there). Only the administrator seeds a member list.
      channels[c.id] = { id: c.id, name: String(c.name || c.id).slice(0, 80), members: (!c.by && Array.isArray(c.members)) ? c.members.map(String) : (prev.members || [c.by]), level: (prev.id && c.by) ? Math.max(prev.level || 1, want) : (prev.id ? (Number(c.level) ? want : prev.level || 1) : want), kind: (!c.by && c.kind) ? String(c.kind).slice(0, 20) : (prev.kind || "channel"),
                         owner: prev.owner || c.by || null, log: prev.log || (c.by ? [{ t: stamp(), by: c.by, act: "created" }] : []), pending: prev.pending || [] };
      save();
      audit("msg-channel-upsert", { channel: c.id, members: (c.members || []).length });
      return send(res, 200, { ok: true });
    }
    if (req.method === "GET" && parts[0] === "channels") {          // list channels a member belongs to
      const m = u.searchParams.get("member");
      if (!isAdmin(req) && !authed(req, m)) return refuse(res, m, "channels");    // a member sees their own channels only
      return send(res, 200, Object.values(channels).filter((c) => !m || c.members.includes(m)));
    }
    send(res, 404, { error: "not found" });
  } catch (err) {
    if (!res.headersSent) send(res, err.status || 500, { error: err.status ? err.message : "The relay could not handle this request." });
  }
}).listen(Number(process.env.ZENOS_RELAY_PORT) || 8095, "127.0.0.1", () => console.log("relay on " + (Number(process.env.ZENOS_RELAY_PORT) || 8095)));

// ZENOS Messages client (PoC). One instance = one person's device.
// Encryption is the Signal protocol (X3DH/PQXDH key agreement + Double Ratchet) from Signal's own libsignal.
// Keys are made and kept on this device; the relay only ever receives ciphertext.
// Levels: a message carries a level; it can only be sent to people whose clearance covers that level.
// PoC limits: keys and history are stored as files on this PC (production: device secure element, encrypted history).
"use strict";
require("./distrust");   // refuse compromised CA keys on every TLS connection
const S = require("@signalapp/libsignal-client");
const http = require("http");
const fs = require("fs");
const path = require("path");

const ACC = process.argv[2];
const PORT = Number(process.argv[3]);
const DEF_RELAY = process.env.ZENOS_RELAY || "http://127.0.0.1:8095";
let RELAY = DEF_RELAY;   // chosen relay; see relays.json (selectable on the PC)
// phone: the account anchor (one number = one account), never shown to others. username: how others find you.
// Test accounts use +81 0x numbers, which no Japanese line can have.
const PEOPLE = {
  zenos: { name: "ZENOS User", level: 4, phone: "+81000000001", username: "zenos.01", org: "ZENOS Gov" },
  sato: { name: "Sato Kenji · Section Chief", level: 4, phone: "+81000000004", username: "sato.04", org: "ZENOS Gov" },
  tanaka: { name: "Tanaka Yuko · Director", level: 5, phone: "+81000000005", username: "tanaka.05", org: "ZENOS Gov" },
  suzuki: { name: "Suzuki Akira · Security Officer", level: 5, phone: "+81000000007", username: "suzuki.07", org: "ZENOS Gov" },
  // test account outside the organisation (a journalist), used to prove the membership guard
  press: { name: "Test Reporter · The Daily Example", level: 1, phone: "+81000000099", username: "press.99", org: "The Daily Example (press)" },
};
// production: org and clearance come from the government directory / PKI, never from the client
const HOME = process.env.HOME;
const DIR = path.join(HOME, ".local/share/zenos/msg/store", ACC);
const AUDIT = path.join(HOME, ".local/share/zenos/audit.log");
fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
const STATE = path.join(DIR, "state.json");
const HIST = path.join(DIR, "history.json");
// ---------- selectable relay: each profile carries the highest level it may carry (a cloud test relay: L2; a ministry-run relay: L5)
const MDATA = path.join(HOME, ".local/share/zenos/msg");   // per-user messenger data (the code may be read-only)
const RELAYS_F = fs.existsSync(path.join(MDATA, "relays.json")) ? path.join(MDATA, "relays.json") : path.join(__dirname, "relays.json");
const RCHOICE = path.join(DIR, "relay.json");
const relayList = () => { try { return JSON.parse(fs.readFileSync(RELAYS_F, "utf8")); } catch { return [{ id: "local", name: "This PC (local test relay)", url: DEF_RELAY, maxLevel: 5, kind: "local" }]; } };
let RELAYCFG = (() => { let c = {}; try { c = JSON.parse(fs.readFileSync(RCHOICE, "utf8")); } catch {} return relayList().find((r) => r.id === c.id) || relayList()[0]; })();
RELAY = RELAYCFG.url;
const capErr = (level) => Number(level) > (RELAYCFG.maxLevel || 5)
  ? `The relay in use ("${RELAYCFG.name}") is approved only up to L${RELAYCFG.maxLevel}. Send L${level} through a ministry-run relay.` : null;
const b64 = (u) => Buffer.from(u).toString("base64");
const ub = (s) => Buffer.from(s, "base64");
const load = (f, d) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return d; } };
let st = load(STATE, null);
let hist = load(HIST, []);
const persist = () => fs.writeFileSync(STATE, JSON.stringify(st), { mode: 0o600 });
const saveHist = () => fs.writeFileSync(HIST, JSON.stringify(hist), { mode: 0o600 });

function stamp() {
  const d = new Date(), p = (n) => String(n).padStart(2, "0");
  const off = -d.getTimezoneOffset(), s = off >= 0 ? "+" : "-";
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${s}${p(Math.floor(Math.abs(off) / 60))}${p(Math.abs(off) % 60)}`;
}
function audit(event, kw) {
  fs.appendFileSync(AUDIT, JSON.stringify({ t: stamp(), user: ACC, event, ...kw }) + "\n");
}

// ---------- key stores (backed by this device's state file) ----------
class Sessions extends S.SessionStore {
  async saveSession(a, r) { st.sessions[a.toString()] = b64(r.serialize()); persist(); }
  async getSession(a) { const x = st.sessions[a.toString()]; return x ? S.SessionRecord.deserialize(ub(x)) : null; }
  async getExistingSessions(as) { return (await Promise.all(as.map((a) => this.getSession(a)))).filter(Boolean); }
}
class Identity extends S.IdentityKeyStore {
  async getIdentityKey() { return S.IdentityKeyPair.deserialize(ub(st.idkp)).privateKey; }
  async getLocalRegistrationId() { return st.regId; }
  async saveIdentity(a, k) {
    const n = a.name(), nk = b64(k.serialize()), old = st.identities[n];
    st.identities[n] = nk; persist();
    return old && old !== nk ? S.IdentityChange.ReplacedExisting : S.IdentityChange.NewOrUnchanged;
  }
  async isTrustedIdentity(a, k) {   // trust on first use; a changed identity key is refused and audited
    const old = st.identities[a.name()];
    if (old && old !== b64(k.serialize())) { audit("msg-identity-changed", { peer: a.name() }); return false; }
    return true;
  }
  async getIdentity(a) { const x = st.identities[a.name()]; return x ? S.PublicKey.deserialize(ub(x)) : null; }
}
class PreKeys extends S.PreKeyStore {
  async savePreKey(id, r) { st.preKeys[id] = b64(r.serialize()); persist(); }
  async getPreKey(id) { return S.PreKeyRecord.deserialize(ub(st.preKeys[id])); }
  async removePreKey(id) { delete st.preKeys[id]; persist(); }
}
class SignedPreKeys extends S.SignedPreKeyStore {
  async saveSignedPreKey(id, r) { st.signed[id] = b64(r.serialize()); persist(); }
  async getSignedPreKey(id) { return S.SignedPreKeyRecord.deserialize(ub(st.signed[id])); }
}
class KyberPreKeys extends S.KyberPreKeyStore {
  async saveKyberPreKey(id, r) { st.kyber[id] = b64(r.serialize()); persist(); }
  async getKyberPreKey(id) { return S.KyberPreKeyRecord.deserialize(ub(st.kyber[id])); }
  async markKyberPreKeyUsed() { /* last-resort key in this PoC */ }
}
const sess = new Sessions(), ident = new Identity(), pks = new PreKeys(), spks = new SignedPreKeys(), kpks = new KyberPreKeys();
const LOCAL = S.ProtocolAddress.new(ACC, 1);

// ---------- stage 1: mailboxes and sealed sender ----------
const rnd = (n) => require("crypto").randomBytes(n).toString("hex");
const sha = (x) => require("crypto").createHash("sha256").update(String(x)).digest("hex");
let TRUST = null, CERT = null;
async function ensureMailboxes() {
  st.mb = st.mb || { intro: { id: rnd(16), tok: rnd(32) }, priv: { id: rnd(16), tok: rnd(32), uak: rnd(16) } };
  st.peers = st.peers || {}; st.intros = st.intros || {}; persist();
  await rq("POST", "/mailbox", { id: st.mb.intro.id, owner: sha(st.mb.intro.tok), uak: null });
  await rq("POST", "/mailbox", { id: st.mb.priv.id, owner: sha(st.mb.priv.tok), uak: sha(st.mb.priv.uak) });
}
async function senderCert() {
  if (CERT && CERT.exp - Date.now() > 3600e3) return CERT.cert;
  const idkp = S.IdentityKeyPair.deserialize(ub(st.idkp));
  const r = await rq("POST", "/cert", { acc: ACC, identity: b64(idkp.publicKey.serialize()) });
  if (!r.cert) throw new Error("no sender certificate: " + (r.error || "?"));
  CERT = { cert: S.SenderCertificate.deserialize(ub(r.cert)), exp: r.exp };
  return CERT.cert;
}
async function trustRoot() { if (!TRUST) { const r = await rq("GET", "/trust"); TRUST = S.PublicKey.deserialize(ub(r.trust)); } return TRUST; }

// Every request made for this account is signed with the account's identity key: the relay binds an account to
// the device that registered it and refuses requests (and key changes) from anywhere else.
function authHdr(method, p, raw) {
  if (!st || !st.idkp) return {};
  const ts = String(Date.now());
  const sig = S.IdentityKeyPair.deserialize(ub(st.idkp)).privateKey.sign(Buffer.from(`${method} ${p} ${ts} ${sha(raw || "")}`));
  const h = { "X-Zenos-Auth": `${ACC} ${ts} ${b64(sig)}` };
  if (p.startsWith("/call/servers")) { const t = adminToken(); if (t) h["X-Zenos-Admin"] = t; }
  return h;
}
const adminToken = () => { try { return fs.readFileSync(path.join(HOME, ".local/share/zenos/msg/relay/admin.token"), "utf8").trim(); } catch { return ""; } };
async function rqr(method, p, obj) {
  const raw = obj ? JSON.stringify(obj) : "";
  return fetch(RELAY + p, { method, headers: { "Content-Type": "application/json", ...authHdr(method, p, raw) }, body: raw || undefined });
}
async function rq(method, p, obj) { return (await rqr(method, p, obj)).json(); }

// ---------- first start: make this device's keys and publish the public halves ----------
// one-time enrollment code from the administrator, for relays that register new accounts only that way
const enrollCode = () => { try { return process.env.ZENOS_ENROLL_CODE || fs.readFileSync(path.join(MDATA, "enroll-code"), "utf8").trim(); } catch { return undefined; } };
async function setup() {
  if (st) await ensureMailboxes();
  if (!st) {
    const idkp = S.IdentityKeyPair.generate();
    st = { idkp: b64(idkp.serialize()), regId: 1 + Math.floor(Math.random() * 16000), preKeys: {}, signed: {}, kyber: {}, sessions: {}, identities: {} };
    const spk = S.PrivateKey.generate();
    const spkSig = idkp.privateKey.sign(spk.getPublicKey().serialize());
    st.signed[1] = b64(S.SignedPreKeyRecord.new(1, Date.now(), spk.getPublicKey(), spk, spkSig).serialize());
    const kp = S.KEMKeyPair.generate();
    const kSig = idkp.privateKey.sign(kp.getPublicKey().serialize());
    st.kyber[1] = b64(S.KyberPreKeyRecord.new(1, Date.now(), kp, kSig).serialize());
    for (let i = 1; i <= 20; i++) {
      const k = S.PrivateKey.generate();
      st.preKeys[i] = b64(S.PreKeyRecord.new(i, k.getPublicKey(), k).serialize());
    }
    persist();
    audit("msg-keys-created", { device: ACC });
    await ensureMailboxes();
  }
  const idkp = S.IdentityKeyPair.deserialize(ub(st.idkp));
  const s = S.SignedPreKeyRecord.deserialize(ub(st.signed[1]));
  const k = S.KyberPreKeyRecord.deserialize(ub(st.kyber[1]));
  await rq("POST", `/keys/${ACC}`, {
    name: PEOPLE[ACC].name, level: PEOPLE[ACC].level, regId: st.regId, username: PEOPLE[ACC].username, org: PEOPLE[ACC].org, findByPhone: true, intro: st.mb ? st.mb.intro.id : null,
    identity: b64(idkp.publicKey.serialize()),
    enroll: enrollCode(),
    signed: { id: 1, pub: b64(s.publicKey().serialize()), sig: b64(s.signature()) },
    kyber: { id: 1, pub: b64(k.publicKey().serialize()), sig: b64(k.signature()) },
    preKeys: Object.keys(st.preKeys).map((id) => ({ id: Number(id), pub: b64(S.PreKeyRecord.deserialize(ub(st.preKeys[id])).publicKey().serialize()) })),
  });
}

async function send(to, text, level, meta) {
  if (FEDADDR.test(to)) return sendFed(to, text, level, meta);
  if (!PEOPLE[to]) throw new Error("Unknown recipient.");
  if (level > PEOPLE[ACC].level) throw new Error(`Your clearance is L${PEOPLE[ACC].level}.`);
  if (level > PEOPLE[to].level) {
    audit("msg-refused", { to, level, reason: "recipient-clearance" });
    throw new Error(`${PEOPLE[to].name} has clearance L${PEOPLE[to].level}. An L${level} message cannot be sent to them.`);
  }
  const addr = S.ProtocolAddress.new(to, 1);
  if (!(await sess.getSession(addr))) {
    const b = await rq("GET", `/keys/${to}`);
    if (!b || !b.signed || !b.kyber) throw new Error(`${PEOPLE[to].name} has no device registered on this relay yet.`);
    const bundle = S.PreKeyBundle.new(
      b.regId, 1,
      b.preKey ? b.preKey.id : null, b.preKey ? S.PublicKey.deserialize(ub(b.preKey.pub)) : null,
      b.signed.id, S.PublicKey.deserialize(ub(b.signed.pub)), ub(b.signed.sig),
      S.PublicKey.deserialize(ub(b.identity)),
      b.kyber.id, S.KEMPublicKey.deserialize(ub(b.kyber.pub)), ub(b.kyber.sig));
    await S.processPreKeyBundle(bundle, addr, LOCAL, sess, ident);
    if (b.intro) { st.intros[to] = b.intro; persist(); }
    audit("msg-session-created", { peer: to });
  }
  if (!st.peers[to] && !st.intros[to]) { const b = await rq("GET", `/keys/${to}`); if (b.intro) { st.intros[to] = b.intro; persist(); } }
  const t = stamp();
  meta = meta || {};
  const payload = { text, level, t, ch: meta.ch || null, room: meta.room || null, thread: meta.thread || null, id: meta.id || null,
                    kind: meta.kind || "msg", target: meta.target || null, emoji: meta.emoji || null, on: meta.on !== false, att: meta.att || null, ev: meta.ev || null, status: meta.status || null, cancel: !!meta.cancel,
                    rt: { mbx: st.mb.priv.id, uak: st.mb.priv.uak } };   // reply-to: only the recipient ever sees our private mailbox
  const sealed = await S.sealedSenderEncryptMessage(Buffer.from(JSON.stringify(payload)), addr, await senderCert(), sess, ident);
  const dest = st.peers[to] || { mbx: st.intros[to], uak: null };
  if (!dest.mbx) throw new Error("No mailbox known for this person yet.");
  const r = await rq("POST", "/deliver", { mbx: dest.mbx, uak: dest.uak, body: b64(sealed) });
  if (r.error && st.peers[to]) {           // private mailbox refused (e.g. rotated): fall back to the public intro mailbox once
    delete st.peers[to]; persist();
    const r2 = await rq("POST", "/deliver", { mbx: st.intros[to], uak: null, body: b64(sealed) });
    if (r2.error) throw new Error("Delivery failed: " + r2.error);
  } else if (r.error) throw new Error("Delivery failed: " + r.error);
  if (!meta.ch) { hist.push({ scope: "dm", peer: to, from: ACC, dir: "out", text, level, t, id: payload.id, thread: payload.thread,
                              kind: payload.kind, target: payload.target, emoji: payload.emoji, on: payload.on, att: pubAtt(payload.att), ev: payload.ev, status: payload.status, cancel: payload.cancel }); saveHist();
    if (["msg", "event"].includes(payload.kind)) recordMsg(hist[hist.length - 1]); }
}

// ---------- people at another organization ("account@organization", docs/FEDERATION.md) ----------
// This relay passes the envelope to the other organization's relay only when both are on the signed member list
// and the level is within what that organization may receive (decided by zenos-decide "federate" on both relays).
// The other relay sees this relay, a mailbox and a size; never who sent it. Attachments and channels stay inside one
// organization for now.
const FEDADDR = /^[a-z_][a-z0-9_.]{1,40}@[a-z0-9][a-z0-9.-]{1,80}$/;
let MYORG = null, FEDTRUST = { t: 0, roots: {} };
async function myOrg() { if (!MYORG) { const r = await rq("GET", "/.well-known/zenos-relay"); if (!r.org) throw new Error("This relay is not connected to other organizations."); MYORG = r.org; } return MYORG; }
async function fedTrust() {
  if (Date.now() - FEDTRUST.t > 600e3) { const r = await rq("GET", "/fed/trust"); FEDTRUST = { t: Date.now(), roots: r && !r.error ? r : {} }; }
  return FEDTRUST.roots;
}
async function sendFed(to, text, level, meta) {
  const [acc, org] = to.split("@");
  if (level > PEOPLE[ACC].level) throw new Error(`Your clearance is L${PEOPLE[ACC].level}.`);
  meta = meta || {};
  if (meta.ch && !(meta.room && meta.room.id === meta.ch)) throw new Error("Only rooms (not this relay's channels) reach other organizations.");
  if ((meta.kind || "msg") !== "msg") throw new Error("Only messages and files reach other organizations for now.");
  const addr = S.ProtocolAddress.new(to, 1);
  if (!(await sess.getSession(addr))) {
    const b = await rq("GET", `/fed/keys/${org}/${encodeURIComponent(acc)}?by=${ACC}`);
    if (!b || !b.signed || !b.kyber) throw new Error("Could not reach this person: " + ((b && b.error) || "no keys"));
    await S.processPreKeyBundle(S.PreKeyBundle.new(b.regId, 1, b.preKey ? b.preKey.id : null, b.preKey ? S.PublicKey.deserialize(ub(b.preKey.pub)) : null,
      b.signed.id, S.PublicKey.deserialize(ub(b.signed.pub)), ub(b.signed.sig), S.PublicKey.deserialize(ub(b.identity)),
      b.kyber.id, S.KEMPublicKey.deserialize(ub(b.kyber.pub)), ub(b.kyber.sig)), addr, LOCAL, sess, ident);
    if (b.intro) { st.intros[to] = b.intro; persist(); }
    audit("msg-session-created", { peer: to });
  }
  const t = stamp();
  const org0 = await myOrg();
  const att = meta.att ? { ...meta.att, org: meta.att.org || org0 } : null;    // the other side fetches it from this relay
  const payload = { text, level, t, ch: meta.ch || null, room: meta.room || null, thread: meta.thread || null, id: meta.id || null, kind: "msg", att,
                    rt: { mbx: st.mb.priv.id, uak: st.mb.priv.uak, org: org0 } };
  const sealed = await S.sealedSenderEncryptMessage(Buffer.from(JSON.stringify(payload)), addr, await senderCert(), sess, ident);
  const dest = st.peers[to] || { mbx: st.intros[to], uak: null };
  if (!dest.mbx) throw new Error("No mailbox known for this person yet.");
  const r = await rq("POST", "/fed/send", { by: ACC, to_org: org, mbx: dest.mbx, uak: dest.uak, body: b64(sealed), level });
  if (r.error) throw new Error("Delivery failed: " + r.error);
  if (!meta.ch) { hist.push({ scope: "dm", peer: to, from: ACC, dir: "out", text, level, t, id: payload.id, thread: payload.thread, kind: "msg", on: true, att: pubAtt(att) }); saveHist();
    recordMsg(hist[hist.length - 1]); }
}

// ---------- rooms: groups that can include people at other organizations ----------
// A room is kept by its members' devices, not by a relay: the person who makes it lists the members (accounts here,
// account@organization elsewhere). Every message carries the room (id, name, level, members) and goes to each
// member as its own sealed message, so each relay applies its own rules to each member (for another organization:
// the signed member list and its level, decided by zenos-decide). Only the person who made the room changes who is
// in it. The room's level caps every message in it.
const ROOMS_F = path.join(DIR, "rooms.json");
let rooms = load(ROOMS_F, {});
const saveRooms = () => fs.writeFileSync(ROOMS_F, JSON.stringify(rooms), { mode: 0o600 });
const isRoom = (ch) => /^room-[0-9a-f]{16}$/.test(ch || "");
async function hereOrg() { try { return await myOrg(); } catch { return "local"; } }   // rooms also work on a relay without federation
async function absAddr(a) { return a.includes("@") ? a : a + "@" + await hereOrg(); }
async function localAddr(a) { const [acc, org] = a.split("@"); return org === await hereOrg() ? acc : a; }
async function makeRoom(name, members, level) {
  if (level > PEOPLE[ACC].level) throw new Error(`Your clearance is L${PEOPLE[ACC].level}.`);
  const me = await absAddr(ACC), list = [me];
  for (const m of members || []) {
    const a = await absAddr(String(m).trim().toLowerCase());
    if (!FEDADDR.test(a)) throw new Error("Not an address: " + m);
    if (!list.includes(a)) list.push(a);
  }
  if (list.length > 200) throw new Error("A room has at most 200 members.");
  const id = "room-" + crypto.randomBytes(8).toString("hex");
  rooms[id] = { id, name: String(name || "Room").slice(0, 60), level: Math.max(1, Number(level) || 1), members: list, by: me, t: stamp() };
  saveRooms(); audit("msg-room-made", { room: id, members: list.length, level: rooms[id].level });
  await sendRoom(id, `Room "${rooms[id].name}" made by ${PEOPLE[ACC].name.split(" · ")[0]}.`, 1, null, {});
  return rooms[id];
}
async function sendRoom(id, text, level, thread, extra) {
  const r = rooms[id]; extra = extra || {};
  if (!r) throw new Error("Unknown room.");
  if (level > r.level) throw new Error(`This room is L${r.level}. An L${level} message cannot go to it.`);
  const mid = `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, t = stamp(), me = await absAddr(ACC);
  hist.push({ scope: "channel", ch: id, peer: "#" + r.name, from: ACC, dir: "out", text, level, t, thread: thread || null, id: mid,
              kind: extra.kind || "msg", target: extra.target || null, emoji: extra.emoji || null, on: extra.on !== false, att: pubAtt(extra.att), ev: extra.ev || null, status: extra.status || null, cancel: !!extra.cancel });
  saveHist();
  if (!extra.kind || extra.kind === "msg") recordMsg(hist[hist.length - 1]);
  const room = { id, name: r.name, level: r.level, members: r.members, by: r.by };
  let delivered = 0; const failed = [];
  for (const m of r.members) {
    if (m === me) continue;
    const to = await localAddr(m);
    try { await send(to, text, level, { ch: id, room, thread: thread || null, id: mid, ...extra }); delivered++; }
    catch (err) { failed.push(m); audit("msg-room-send-failed", { room: id, to: m, error: String(err.message || err).slice(0, 80) }); }
  }
  audit("msg-room-sent", { room: id, delivered, failed: failed.length, level });
  return { delivered, failed };
}
/** A room message from `from` (an address as this device writes it): learn the room, if the sender is in it. */
async function learnRoom(from, m) {
  if (!m.room || !isRoom(m.ch) || m.room.id !== m.ch) return false;
  const fromAbs = await absAddr(from), me = await absAddr(ACC), x = m.room;
  const members = Array.isArray(x.members) ? x.members.map(String).filter((a) => FEDADDR.test(a)).slice(0, 200) : [];
  if (!members.includes(fromAbs) || !members.includes(me)) return false;
  const cur = rooms[m.ch];
  if (!cur) rooms[m.ch] = { id: m.ch, name: String(x.name || "Room").slice(0, 60), level: Math.max(1, Math.min(5, Number(x.level) || 1)), members, by: String(x.by || fromAbs), t: stamp() };
  else if (cur.by === fromAbs && x.by === cur.by) { cur.members = members; cur.name = String(x.name || cur.name).slice(0, 60); }   // only the maker changes the room
  else if (!cur.members.includes(fromAbs)) return false;
  saveRooms();
  return true;
}
/** Open a sealed envelope: this relay's trust root first, then the listed organizations' roots. */
async function openSealed(body) {
  const tryRoot = (root) => S.sealedSenderDecryptMessage(ub(body), root, Date.now(), null, ACC, 1, sess, ident, pks, spks, kpks);
  try { const out = await tryRoot(await trustRoot()); return { out, org: null }; }
  catch (first) {
    for (const [org, k] of Object.entries(await fedTrust())) {
      try { const out = await tryRoot(S.PublicKey.deserialize(ub(k))); return { out, org }; } catch {}
    }
    throw first;
  }
}

async function sendChannel(ch, text, level, thread, extra) {
  if (isRoom(ch)) return sendRoom(ch, text, level, thread, extra);
  extra = extra || {};
  const chans = await rq("GET", `/channels?member=${ACC}`);
  const c = (chans || []).find((x) => x.id === ch);
  if (!c) throw new Error("Unknown channel.");
  if (level > PEOPLE[ACC].level) throw new Error(`Your clearance is L${PEOPLE[ACC].level}.`);
  const id = `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const t = stamp();
  hist.push({ scope: "channel", ch, peer: "#" + ch, from: ACC, dir: "out", text, level, t, thread: thread || null, id,
              kind: extra.kind || "msg", target: extra.target || null, emoji: extra.emoji || null, on: extra.on !== false, att: pubAtt(extra.att), ev: extra.ev || null, status: extra.status || null, cancel: !!extra.cancel });
  saveHist();
  if (!extra.kind || ["msg", "event"].includes(extra.kind)) recordMsg(hist[hist.length - 1]);
  let delivered = 0;
  for (const m of c.members) {
    if (m === ACC) continue;
    try { await send(m, text, level, { ch, thread: thread || null, id, ...extra }); delivered++; }
    catch (err) { audit("msg-channel-send-failed", { ch, to: m, error: String(err).slice(0, 80) }); }
  }
  audit("msg-channel-sent", { ch, delivered, level });
}

async function collect(box) {
  const r = await fetch(RELAY + "/collect/" + box.id, { headers: { "X-Owner": box.tok } });
  return r.ok ? r.json() : [];
}
async function receiveSealed() {
  if (!st.mb) return;
  const items = [...await collect(st.mb.intro), ...await collect(st.mb.priv)];
  for (const e of items) {
    let from = "?";
    try {
      const { out, org } = await openSealed(e.body);
      from = org ? out.senderUuid() + "@" + org : out.senderUuid();
      if (!org && !PEOPLE[from]) { audit("msg-dropped", { reason: "unknown sender" }); continue; }
      const m = JSON.parse(Buffer.from(out.message()).toString("utf8"));
      if (org) {                       // from another organization: plain messages only (no releases, calls, channels, attachments)
        const roomOk = !m.ch || (isRoom(m.ch) && await learnRoom(from, m));
        if (m.kind !== "msg" || !roomOk || (m.att && m.att.org !== org) || (m.rt && m.rt.org !== org)) { audit("msg-dropped", { reason: "not allowed across organizations", org }); continue; }
        if (m.rt && /^[0-9a-f]{32}$/.test(m.rt.mbx || "")) { st.peers[from] = { mbx: m.rt.mbx, uak: m.rt.uak }; persist(); }
        await ingest(from, { ...m, ev: null, status: null, target: null });
        continue;
      }
      if (m.rt && /^[0-9a-f]{32}$/.test(m.rt.mbx || "")) { st.peers[from] = { mbx: m.rt.mbx, uak: m.rt.uak }; persist(); }
      if (isRoom(m.ch) && !(await learnRoom(from, m))) { audit("msg-dropped", { reason: "not a member of the room" }); continue; }
      await ingest(from, m);
    } catch (err) { audit("msg-decrypt-failed", { from, error: String(err).slice(0, 120) }); }
  }
}
async function receive() {
  await receiveSealed();
  const q = await rq("GET", `/recv/${ACC}`);
  for (const e of q) {
    try {
      const addr = S.ProtocolAddress.new(e.from, 1);
      const buf = ub(e.body);
      const pt = e.type === S.CiphertextMessageType.PreKey
        ? await S.signalDecryptPreKey(S.PreKeySignalMessage.deserialize(buf), addr, LOCAL, sess, ident, pks, spks, kpks)
        : await S.signalDecrypt(S.SignalMessage.deserialize(buf), addr, LOCAL, sess, ident);
      const m = JSON.parse(Buffer.from(pt).toString("utf8"));
      await ingest(e.from, m);
    } catch (err) {
      audit("msg-decrypt-failed", { from: e.from, error: String(err).slice(0, 120) });
    }
  }
}
// what another device may send: known kinds, a level 1..5, a short emoji without markup, text as a string. Anything
// else is dropped here, before it reaches the history or the window.
const IN_KINDS = new Set(["msg", "react", "event", "rsvp", "evupd", "call", "callkey", "callsig", "share", "room", "system", "zrel", "zrel-sig", "zrel-res", "zrel-st"]);
function wellFormed(m) {
  if (!m || typeof m !== "object" || !IN_KINDS.has(m.kind || "msg")) return false;
  const lv = Number(m.level); if (!Number.isInteger(lv) || lv < 1 || lv > 5) return false;
  if (m.text != null && typeof m.text !== "string") return false;
  if (m.emoji != null && !(typeof m.emoji === "string" && m.emoji.length <= 16 && !/[<>&"'`\\]/.test(m.emoji))) return false;
  for (const k of ["ch", "thread", "id", "target", "t", "status"]) if (m[k] != null && typeof m[k] !== "string") return false;
  return true;
}
async function ingest(fromAcc, m) {
  const e = { from: fromAcc };
  if (!wellFormed(m)) { audit("msg-dropped", { from: fromAcc, reason: "malformed" }); return; }
  {
    try {
      if (m.level > PEOPLE[ACC].level) { audit("msg-dropped", { from: e.from, level: m.level }); return; }
      if (m.att) m.att = await openAttachment(m.att, m.level);
      hist.push({ scope: m.ch ? "channel" : "dm", ch: m.ch || null, peer: m.ch ? ("#" + m.ch) : e.from,
                  from: e.from, dir: "in", text: m.text, level: m.level, t: m.t, thread: m.thread || null, id: m.id || null,
                  kind: m.kind || "msg", target: m.target || null, emoji: m.emoji || null, on: m.on !== false, att: m.att || null, ev: m.ev || null, status: m.status || null, cancel: !!m.cancel });
      saveHist();
      if (m.kind === "zrel-sig" && m.ev && ACC === DESK) await carryAnswer(e.from, m);
      if (m.kind === "zrel" && m.ev) {
        pushAll({ title: "Release request · " + String((PEOPLE[e.from] || { name: e.from }).name).split(" · ")[0], body: `A ZENOS PC stopped (L${m.level}). Open ZENOS to answer.`, tag: "zrel", red: true },
                { urgency: "high", ttl: 24 * 3600 }).catch(() => {});
      }
      if ((m.kind || "msg") === "msg") {
        recordMsg(hist[hist.length - 1]);
        const nm = String((PEOPLE[e.from] || { name: e.from }).name).split(" · ")[0];
        const mention = new RegExp("@(" + ACC + "|here|channel)\\b", "i").test(m.text || "");
        const bodyTxt = m.level <= 2 ? String(m.text).slice(0, 140) : `🔒 L${m.level} message. Open ZENOS to read it.`;
        pushAll({ title: (mention ? "@ " : "") + nm + (m.ch ? " · #" + m.ch : ""), body: bodyTxt, tag: m.id || undefined, red: m.ch === "alerts" },
                { urgency: mention || m.ch === "alerts" ? "high" : "normal" }).catch(() => {});
      }
      if (m.kind === "event" && m.ev) {
        recordMsg(hist[hist.length - 1]);
        const nm = String((PEOPLE[e.from] || { name: e.from }).name).split(" · ")[0];
        pushAll({ title: "📅 " + nm + (m.ch ? " · #" + m.ch : ""), body: m.level <= 2 ? `${m.ev.title} — ${m.ev.date} ${m.ev.start || ""}` : `🔒 L${m.level} event. Open ZENOS to see it.`, tag: m.id || undefined }).catch(() => {});
      }
    } catch (err) {
      audit("msg-decrypt-failed", { from: e.from, error: String(err).slice(0, 120) });
    }
  }
}

// ---------- linked phones (remote port) + Web Push ----------
const crypto = require("crypto");
const webpush = require("web-push");
const QR = require("qrcode");
const DEVF = path.join(DIR, "devices.json");
let devices = load(DEVF, {});
const saveDev = () => fs.writeFileSync(DEVF, JSON.stringify(devices), { mode: 0o600 });
const sh = (x) => crypto.createHash("sha256").update(x).digest("hex");
const linkTokens = {};
const VF = path.join(DIR, "vapid.json");
let vapid = load(VF, null);
if (!vapid) { vapid = webpush.generateVAPIDKeys(); fs.writeFileSync(VF, JSON.stringify(vapid), { mode: 0o600 }); }
webpush.setVapidDetails("mailto:security@zenos.example", vapid.publicKey, vapid.privateKey);
const TUNNEL = path.join(MDATA, "tunnel-url." + ACC);
async function pushTo(keys, payload, opt) {
  opt = opt || {}; let sent = 0;
  for (const k of keys) {
    const d = devices[k]; if (!d || !d.push) continue;
    try { await webpush.sendNotification(d.push, JSON.stringify(payload), { TTL: opt.ttl || 3600, urgency: opt.urgency || "normal" }); sent++; }
    catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) { d.push = null; saveDev(); }
      audit("msg-push-failed", { code: err.statusCode || 0, error: String(err.body || err.message).slice(0, 80) });
    }
  }
  return sent;
}
const pushAll = (p, o) => {
  const dnd = (load(path.join(DIR, "local.json"), {}).dnd) || 0;
  if (dnd && Date.now() < dnd && !p.red) return Promise.resolve(0);   // paused; red alerts still go through
  return pushTo(Object.keys(devices), p, o);
};
function page(title, msg) {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>ZENOS</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#0E0F13;color:#D2D5DC;font-family:Inter,system-ui,sans-serif">
<div style="max-width:340px;padding:24px;text-align:center"><div style="width:48px;height:48px;border-radius:14px;background:#3B82F6;color:#fff;font-weight:700;font-size:20px;display:grid;place-items:center;margin:0 auto 16px">Z</div>
<h2 style="color:#F2F4F6;font-size:18px;margin:0 0 8px">${title}</h2><p style="font-size:14px;line-height:1.6;color:#9AA0AB;margin:0">${msg}</p></div>`;
}
function cookieSid(req) { const m = (req.headers.cookie || "").match(/(?:^|;\s*)zsid=([A-Za-z0-9_-]{20,})/); return m ? m[1] : null; }
async function remoteGate(req, res, u) {
  if (u.pathname === "/link") {
    const t = u.searchParams.get("t") || ""; const exp = linkTokens[t]; delete linkTokens[t];
    if (!exp || Date.now() > exp) { res.writeHead(410, { "Content-Type": "text/html; charset=utf-8" }); res.end(page("This link has expired", "On your ZENOS PC, open More → Link a phone, and scan the new code.")); return true; }
    const sid = crypto.randomBytes(32).toString("base64url");
    devices[sh(sid)] = { name: String(req.headers["user-agent"] || "device").slice(0, 160), created: stamp(), lastSeen: stamp(), push: null };
    saveDev(); audit("msg-device-linked", { device: sh(sid).slice(0, 12) });
    res.writeHead(302, { "Set-Cookie": `zsid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`, Location: "/" }); res.end(); return true;
  }
  const sid = cookieSid(req), d = sid && devices[sh(sid)];
  if (!d) {
    if (["/manifest.webmanifest", "/app-icon.svg", "/app-icon-180.png", "/app-icon-512.png", "/sw.js"].includes(u.pathname)) return false;
    if (u.pathname.startsWith("/api/")) { json(res, 401, { error: "This device is not linked." }); return true; }
    res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
    res.end(page("This device is not linked", "On your ZENOS PC, open More → Link a phone, and scan the QR code with this phone's camera."));
    return true;
  }
  req.dev = sh(sid);
  if (Date.now() - new Date(d.lastSeen).getTime() > 60e3) { d.lastSeen = stamp(); saveDev(); }
  if (["/api/link/new", "/api/push/alert", "/api/devices", "/api/devices/revoke", "/api/register/start", "/api/register/verify", "/api/relays/add", "/api/relays/select"].includes(u.pathname)) { json(res, 403, { error: "Only on the ZENOS PC." }); return true; }
  return false;
}
// ---------- sign-in with this phone: the PC's vault service (zenos_credd) asks, the linked phone answers.
// This process only carries the request and the phone's answer; the answer is a passkey signature over the request and
// the entry's key encrypted to the vault service, so nothing here can open a password.
const net = require("net");
const CREDD = process.env.ZENOS_CREDD_SOCK || "/run/zenos/credd.sock";
function credd(msg, timeout) {
  return new Promise((resolve) => {
    const s = net.createConnection(CREDD); let b = ""; let over = false;
    const done = (o) => { if (over) return; over = true; try { s.destroy(); } catch {} resolve(o); };
    s.setTimeout(timeout || 10000, () => done({ ok: false, error: "The sign-in service did not answer." }));
    s.on("connect", () => s.write(JSON.stringify(msg) + "\n"));
    s.on("data", (d) => { b += d; if (b.endsWith("\n")) { try { done(JSON.parse(b)); } catch { done({ ok: false, error: "bad answer" }); } } });
    s.on("error", () => done({ ok: false, error: "The sign-in service is not running on this PC." }));
  });
}
const credSeen = new Set();
setInterval(async () => {          // a new request: wake the phone (also when notifications are paused: the person is signing in now)
  const r = await credd({ op: "pending" }, 3000);
  if (!r.ok) return;
  for (const p of r.pending) if (!credSeen.has(p.id)) {
    credSeen.add(p.id);
    // the notification says only that a request is waiting. The site and the account are shown in ZENOS Messages,
    // which fetches them from this PC over the linked session: the lock screen and the push service never see them.
    pushTo(Object.keys(devices), { title: "Sign-in request", body: "Open ZENOS Messages to review it.", tag: "cred", url: "/", red: true }, { ttl: 120, urgency: "high" });
  }
}, 2000);
const phoneOrigin = () => { try { return new URL(fs.readFileSync(TUNNEL, "utf8").trim()); } catch { return null; } };
const pickCred = (b) => { const o = {}; for (const k of ["id", "code", "decline", "credential_id", "authenticator_data", "client_data_json", "signature", "phone_key", "iv", "ct", "challenge", "attestation_object", "prf", "name"]) if (b[k] !== undefined) o[k] = b[k]; return o; };
// ---------- official records: every message leaves a hash in the tamper-evident ledger (DODIG-2026-021: messages auto-deleted, records not kept)
const { execFile } = require("child_process");
const LEDGER = path.join(HOME, ".local/share/zenos/ledger.jsonl");
const DEVID = crypto.createHash("sha256").update("msg-" + ACC).digest("hex").slice(0, 16);
function ledger(event, kw) {
  execFile("python3", ["-c", "import sys,json;sys.path[0:0]=[p for p in ('/usr/local/lib/zenos','/usr/lib/zenos')];import zledger;a=json.loads(sys.argv[1]);zledger.append(a.pop('_p'),a.pop('_e'),a.pop('_a'),a.pop('_d'),**a)",
    JSON.stringify({ _p: LEDGER, _e: event, _a: ACC, _d: DEVID, ...kw })], (err) => { if (err) audit("msg-ledger-failed", { error: String(err).slice(0, 80) }); });
}
const recordMsg = (m) => ledger("msg-record", { id: m.id || null, dir: m.dir, peer: m.ch ? "#" + m.ch : m.peer, level: m.level,
  sha256: crypto.createHash("sha256").update(`${m.id}|${m.t}|${m.text}`).digest("hex"), att: m.att ? m.att.sha256 : null });
// ---------- government-issued devices: a linked phone sees and sends L3+ only after the PC registers it as official
const official = (req) => !!(req.dev && devices[req.dev] && devices[req.dev].official);
const restrict = (arr, remote, req) => {
  const cl = PEOPLE[ACC].level;
  const a = arr.filter((m) => (m.level || 1) <= cl);
  return (remote && !official(req)) ? a.map((m) => (m.level > 2 && ["msg", "event", "call", "callkey", "share", "callsig", "zrel"].includes(m.kind || "msg"))
    ? { ...m, text: "", att: null, ev: m.kind === "zrel" && m.ev && m.ev.core ? { lockedId: m.ev.core.id } : null, locked: true } : m) : a;
};
// ---------- attachments (Signal model): AES-256-GCM with a fresh key per file; ciphertext to the relay, key only inside the E2E message
const ATT = path.join(DIR, "att"); fs.mkdirSync(ATT, { recursive: true, mode: 0o700 });
const SAFE_INLINE = ["image/png", "image/jpeg", "image/gif", "image/webp"];
const pubAtt = (a) => a && { sha256: a.sha256, name: a.name, mime: a.mime, size: a.size, error: a.error || null };
async function sealAttachment(buf, name, mime, level) {
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(buf), c.final(), c.getAuthTag()]);
  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
  const r = await fetch(RELAY + "/blobs?level=" + (Number(level) || 5), { method: "POST", body: ct }); const j = await r.json();
  if (!j.id) throw new Error(j.error || "upload failed");
  fs.writeFileSync(path.join(ATT, sha256), buf, { mode: 0o600 });
  return { id: j.id, key: key.toString("base64"), iv: iv.toString("base64"), sha256, name: String(name).slice(0, 120), mime: String(mime).slice(0, 80), size: buf.length };
}
async function openAttachment(a, level) {
  try {
    // from another organization: through this relay, which fetches the ciphertext from the sender's relay
    const r = a.org && a.org !== MYORG && /^[0-9a-f]{32}$/.test(a.id || "")
      ? await rqr("GET", `/fed/blob/${encodeURIComponent(a.org)}/${a.id}?by=${ACC}&level=${Number(level) || 1}`)
      : await fetch(RELAY + "/blobs/" + a.id);
    if (!r.ok) throw new Error("not available (" + r.status + ")");
    const ct = Buffer.from(await r.arrayBuffer());
    const d = crypto.createDecipheriv("aes-256-gcm", Buffer.from(a.key, "base64"), Buffer.from(a.iv, "base64"));
    d.setAuthTag(ct.subarray(ct.length - 16));
    const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
    if (crypto.createHash("sha256").update(pt).digest("hex") !== a.sha256) throw new Error("fingerprint mismatch");
    fs.writeFileSync(path.join(ATT, a.sha256), pt, { mode: 0o600 });
    return pubAtt(a);
  } catch (err) {
    const raw = String(err.message || err);
    const why = /authenticate|fingerprint/.test(raw) ? "it was altered on the way, so it was refused" : raw;
    audit("msg-attachment-failed", { error: raw.slice(0, 80) }); return { ...pubAtt(a), error: why };
  }
}
// ---------- release requests: when the root guard stops this PC, the request goes to the officers' own devices.
// Each officer signs on their own device with a key that never leaves it (WebCrypto, non-extractable). This desk only
// carries the signature to the guard, which checks it against the administrator-enrolled public key and against the
// request it holds itself. The match code is never sent out: the officer reads it off the stopped PC's screen.
const GSYS = "/var/lib/zenos", GSOCK = process.env.ZENOS_GUARDD_SOCK || "/run/zenos/guardd.sock", APPROVERS = "/etc/zenos/approvers";
const CORE_KEYS = ["id", "kind", "requester", "file", "file_hash", "level", "reason", "created", "scope"];   // = zenos.CORE_KEYS
const DESK = process.env.ZENOS_DESK || (() => { try { const l = fs.readFileSync(path.join(MDATA, "ports.env"), "utf8").split("\n").find((x) => /^[a-z0-9_]+=/.test(x)); return l ? l.split("=")[0] : "zenos"; } catch { return "zenos"; } })();
const ZRF = path.join(DIR, "zrel.json");
let zrel = load(ZRF, {});
const saveZrel = () => fs.writeFileSync(ZRF, JSON.stringify(zrel), { mode: 0o600 });
const zid = () => `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
function guardd(msg) {
  return new Promise((resolve) => {
    const c = require("net").connect(GSOCK); let buf = "";
    c.setTimeout(10000, () => { c.destroy(); resolve({ ok: false, message: "The guard did not answer." }); });
    c.on("connect", () => c.write(JSON.stringify(msg) + "\n"));
    c.on("data", (d) => { buf += d; if (buf.endsWith("\n")) { c.end(); try { resolve(JSON.parse(buf)); } catch { resolve({ ok: false, message: "Bad answer from the guard." }); } } });
    c.on("error", () => resolve({ ok: false, message: "The guard is not running on this PC." }));
  });
}
const officers = () => { try { return fs.readdirSync(APPROVERS).filter((f) => f.endsWith(".pub")).map((f) => f.slice(0, -4)); } catch { return []; } };
// the same path carries the requester's own requests: opening a file above their level, and pre-filed operations
const UREQ = path.join(HOME, ".local/share/zenos/requests");
const ZENOS_PY = ["/usr/share/zenos/bin/zenos.py", path.join(__dirname, "..", "bin", "zenos.py"), path.join(HOME, ".local/share/zenos/bin/zenos.py")].find((p) => fs.existsSync(p));
const readJ = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } };
const reqFile = (id) => {
  const b = path.basename(String(id || "")) + ".json";
  for (const d of [path.join(GSYS, "requests"), UREQ]) if (fs.existsSync(path.join(d, b))) return path.join(d, b);
  return null;
};
async function offer(r, extra) {
  const core = {}; for (const k of CORE_KEYS) if (k in r) core[k] = r[k];
  const level = Math.min(Number(r.level) || 1, PEOPLE[ACC].level);
  const to = officers().filter((o) => o !== ACC && PEOPLE[o] && PEOPLE[o].level >= r.level);
  zrel[r.id] = { to: [], level, t: stamp() }; saveZrel();
  const kind = r.kind || "access";
  const ev = { core, kind, required: r.required, name: r.name || "", ...extra };
  const what = { release: "Release request", access: "Access request", plan: "Pre-filed operation" }[kind] || "Request";
  for (const o of to) {
    try { await send(o, `${what}: ${r.reason}`, level, { id: zid(), kind: "zrel", ev }); zrel[r.id].to.push(o); }
    catch (err) { audit("msg-zrel-send-failed", { to: o, error: String(err).slice(0, 80) }); }
  }
  saveZrel(); audit("msg-zrel-sent", { request: r.id, kind, to: zrel[r.id].to });
}
async function watchRelease() {
  if (ACC !== DESK) return;
  // a stop of this PC (installed system: the root guard holds it)
  if (fs.existsSync(GSOCK)) {
    const h = readJ(path.join(GSYS, "halt.json"));
    if (h && h.status === "halted" && h.request && !zrel[h.request]) {
      const r = readJ(path.join(GSYS, "requests", path.basename(h.request) + ".json"));
      if (r) await offer(r, { rule_text: h.rule_text || "", stopped: h.t || "" });
    }
  }
  // this user's own access requests and pre-filed operations
  let names = []; try { names = fs.readdirSync(UREQ).filter((f) => f.endsWith(".json")); } catch {}
  for (const f of names) {
    const r = readJ(path.join(UREQ, f));
    if (!r || r.status !== "pending" || zrel[r.id] || (r.kind === "release" && fs.existsSync(GSOCK))) continue;
    if (Date.now() - (Date.parse(String(r.created || "").replace(/([+-]\d\d)(\d\d)$/, "$1:$2")) || 0) > 24 * 3600e3) continue;
    await offer(r, {});
  }
  // decided or replaced: tell the officers, so the request leaves their screen
  for (const [id, z] of Object.entries(zrel)) {
    if (z.done) continue;
    const p = reqFile(id), r = p && readJ(p);
    const status = !r ? "gone" : r.status;
    if (status === "pending") continue;
    z.done = true; saveZrel();
    for (const o of z.to) await send(o, "", z.level, { id: zid(), kind: "zrel-st", ev: { id, status } }).catch(() => {});
  }
}
function signedAnswer(args) {
  return new Promise((resolve) => {
    if (!ZENOS_PY) return resolve({ ok: false, message: "ZENOS core not found on this PC." });
    execFile("python3", ["-I", ZENOS_PY, "signed-answer", ...args], { timeout: 20000 }, (err, out) => {
      try { resolve(JSON.parse(String(out).trim().split("\n").pop())); } catch { resolve({ ok: false, message: "The answer could not be recorded." }); }
    });
  });
}
async function carryAnswer(from, m) {
  // the approver is the Signal-authenticated sender; the guard (or zenos.py) still requires that person's own
  // signature, checked against the administrator-enrolled key
  const a = { ...m.ev }, op = a.op === "decline" ? "decline" : "approve";
  // an answer from afar is never "near" this PC, whatever it says (the passkey does not sign that field)
  try { const j = JSON.parse(String(a.sig || "")); if (j && j.passkey === 1) a.sig = JSON.stringify({ ...j, attachment: "relayed" }); } catch {}
  const p = reqFile(a.id);
  const out = !p ? { ok: false, message: "Unknown request." }
    : p.startsWith(GSYS) ? await guardd({ op, request: String(a.id || ""), approver: from, sig: String(a.sig || ""), code: String(a.code || "") })
    : await signedAnswer([path.basename(p, ".json"), from, op, String(a.sig || ""), String(a.code || "")]);
  audit("msg-zrel-answer", { request: String(a.id || "").slice(0, 40), from, op, ok: !!out.ok });
  await send(from, "", Math.min(Number(m.level) || 1, PEOPLE[ACC].level), { id: zid(), kind: "zrel-res", ev: { id: a.id, op, ok: !!out.ok, message: String(out.message || "").slice(0, 200) } })
    .catch((err) => audit("msg-zrel-reply-failed", { to: from, error: String(err).slice(0, 80) }));
}
// an approval signature: an Ed25519 signature (base64, 64 bytes) or a passkey signature (JSON, zapprove.py)
function sigShape(s) {
  s = String(s || "");
  if (/^[A-Za-z0-9+/]{86}==$/.test(s)) return true;
  if (s.length > 4096) return false;
  try { const a = JSON.parse(s); return a && a.passkey === 1 && ["credential_id", "authenticator_data", "client_data_json", "signature"].every((k) => /^[A-Za-z0-9_-]{1,2048}$/.test(String(a[k] || ""))); }
  catch { return false; }
}
const readBody = async (req) => { let b = ""; for await (const c of req) b += c; return b ? JSON.parse(b) : {}; };

function json(res, code, o) { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); }
const UI = path.join(__dirname, "ui.html");

// The local port answers only this PC's own window: the request must name 127.0.0.1/localhost at this port (no other
// host name, so a web page cannot reach it through DNS rebinding), carry no other site's Origin, and show the key that
// is written at start to a file only this account can read (cookie set by /open, or the X-Zenos-Local header).
const LOCAL_KEY = crypto.randomBytes(32).toString("base64url");
fs.writeFileSync(path.join(DIR, "local.key"), LOCAL_KEY, { mode: 0o600 }); fs.chmodSync(path.join(DIR, "local.key"), 0o600);
const OWN = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);
const eqKey = (k) => { const a = Buffer.from(String(k || "")), b = Buffer.from(LOCAL_KEY); return a.length === b.length && crypto.timingSafeEqual(a, b); };
function localGate(req, res, u) {
  const origin = req.headers.origin;
  if (!OWN.has(String(req.headers.host || "")) || (origin && !["http://127.0.0.1:" + PORT, "http://localhost:" + PORT].includes(origin))) {
    json(res, 403, { error: "Only this PC's own window may use this port." }); return true; }
  if (u.pathname === "/open") {
    if (!eqKey(u.searchParams.get("k"))) { json(res, 403, { error: "bad key" }); return true; }
    res.writeHead(302, { "Set-Cookie": `zlk=${LOCAL_KEY}; Path=/; HttpOnly; SameSite=Strict`, Location: "/" }); res.end(); return true;
  }
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)zlk=([A-Za-z0-9_-]+)/);
  if (eqKey(m && m[1]) || eqKey(req.headers["x-zenos-local"])) return false;
  json(res, 401, { error: "Open this from the ZENOS menu." }); return true;
}

async function handle(req, res, remote) {
  const u = new URL(req.url, "http://x");
  try {
    if (remote && (await remoteGate(req, res, u))) return;
    if (!remote && localGate(req, res, u)) return;
    if (u.pathname.startsWith("/rtc")) {
      const pr = http.request({ host: "127.0.0.1", port: 7880, path: req.url, method: req.method, headers: { ...req.headers, cookie: "" } }, (r2) => { res.writeHead(r2.statusCode, r2.headers); r2.pipe(res); });
      pr.on("error", () => { res.writeHead(502); res.end(); }); req.pipe(pr); return; }
    if (u.pathname === "/api/cred/pending") {
      if (!remote) return json(res, 200, { pending: [] });             // answered only on the phone
      const r = await credd({ op: "pending" }, 3000);
      return json(res, 200, { pending: r.ok ? r.pending : [], error: r.ok ? null : r.error });
    }
    if (remote && req.method === "POST" && ["/api/cred/answer", "/api/cred/enroll/start", "/api/cred/enroll/finish"].includes(u.pathname)) {
      const b = pickCred(await readBody(req));
      let m;
      if (u.pathname === "/api/cred/answer") m = { op: "answer", ...b };
      else if (u.pathname === "/api/cred/enroll/finish") m = { op: "enroll-finish", ...b };
      else { const o = phoneOrigin(); if (!o) return json(res, 200, { error: "The secure tunnel is not running yet." });
        m = { op: "enroll-start", code: String(b.code || ""), origin: o.origin, rp_id: o.hostname }; }
      const r = await credd(m, 15000);
      audit("msg-cred-" + u.pathname.split("/").pop(), { ok: !!r.ok, error: r.ok ? null : String(r.error).slice(0, 60) });
      return json(res, 200, r.ok ? r : { error: r.error });
    }
    if (!remote && u.pathname === "/api/link/new" && req.method === "POST") {
      let url; try { url = fs.readFileSync(TUNNEL, "utf8").trim(); } catch { return json(res, 200, { error: "The secure tunnel is not running yet." }); }
      const t = crypto.randomBytes(24).toString("base64url"); linkTokens[t] = Date.now() + 5 * 60e3;
      const link = `${url}/link?t=${t}`;
      audit("msg-link-issued", {});
      return json(res, 200, { url: link, expires: 300, qr: await QR.toDataURL(link, { margin: 1, width: 300, color: { dark: "#0E0F13", light: "#FFFFFF" } }) });
    }
    if (!remote && u.pathname === "/api/devices") return json(res, 200, Object.entries(devices).map(([k, d]) => ({ id: k.slice(0, 12), name: d.name, created: d.created, lastSeen: d.lastSeen, push: !!d.push, official: d.official || null })));
    if (!remote && u.pathname === "/api/devices/official" && req.method === "POST") {
      const { id, tag } = await readBody(req);
      if (!/^[0-9a-f]{12}$/.test(String(id || "")) || !/^[A-Za-z0-9-]{3,32}$/.test(String(tag || ""))) return json(res, 400, { error: "Enter the asset tag printed on the device (letters, numbers, dashes)." });
      const k = Object.keys(devices).find((x) => x.startsWith(id)); if (!k) return json(res, 404, { error: "No such device." });
      devices[k].official = { tag, at: stamp() }; saveDev();
      ledger("device-official", { device: id, tag }); audit("msg-device-official", { device: id, tag });
      return json(res, 200, { ok: true });
    }
    if (!remote && u.pathname === "/api/devices/revoke" && req.method === "POST") {
      const { id } = await readBody(req); if (!/^[0-9a-f]{12}$/.test(String(id || ""))) return json(res, 400, { error: "bad device id" });
      for (const k of Object.keys(devices)) if (k.startsWith(id)) delete devices[k];
      saveDev(); audit("msg-device-revoked", { device: String(id).slice(0, 12) }); return json(res, 200, { ok: true });
    }
    if (!remote && u.pathname === "/api/push/alert" && req.method === "POST") {
      const b = await readBody(req);
      const n = await pushAll({ title: String(b.title || "ZENOS RED ALERT").slice(0, 80), body: String(b.body || "").slice(0, 300), tag: b.tag || "red", red: true }, { urgency: "high", ttl: 24 * 3600 });
      audit("msg-push-alert", { sent: n }); return json(res, 200, { ok: true, sent: n });
    }
    if (!remote && u.pathname === "/api/register/start" && req.method === "POST") {
      const r = await rqr("POST", "/register/start", { phone: PEOPLE[ACC].phone, id: ACC });
      return json(res, 200, await r.json());
    }
    if (!remote && u.pathname === "/api/register/verify" && req.method === "POST") {
      const { code } = await readBody(req);
      const r = await rqr("POST", "/register/verify", { phone: PEOPLE[ACC].phone, id: ACC, code });
      const j = await r.json();
      if (j.ok && j.rebind) await setup().catch(() => {});      // a new device verified with the account's number: publish its keys now
      return json(res, 200, j);
    }
    if (u.pathname.startsWith("/api/channel/") && req.method === "POST") {
      const act = u.pathname.split("/")[3]; const b = await readBody(req);
      const nm = (id) => String((PEOPLE[id] || { name: id }).name).split(" · ")[0];
      const sys = (ch, text, target) => sendChannel(ch, text, 1, null, { kind: "system", target: target || null }).catch(() => {});
      if (act === "create") {
        const r = await rq("POST", "/channels", { id: String(b.id || ""), name: "#" + b.id, level: Math.min(Number(b.level) || 1, PEOPLE[ACC].level), members: [ACC], by: ACC });
        if (!r.error) { await sys(b.id, `${nm(ACC)} created #${b.id} (L${Math.min(Number(b.level) || 1, PEOPLE[ACC].level)}).`); audit("msg-channel-created", { ch: b.id }); }
        return json(res, 200, r);
      }
      if (["invite", "approve", "deny", "remove"].includes(act)) {
        if (act === "remove") await sys(b.ch, `${nm(ACC)} removed ${nm(b.target)}.`, b.target);
        const rr = await rqr("POST", `/channels/${encodeURIComponent(b.ch)}/${act}`, { by: ACC, target: b.target });
        const r = await rr.json();
        if (!r.error) {
          const ext = r.external ? ` — outside the organisation (${r.org})` : "";
          if (act === "invite" && r.added) await sys(b.ch, `${nm(ACC)} added ${nm(b.target)}${ext}.`, b.target);
          if (act === "invite" && r.pending) await sys(b.ch, `${nm(ACC)} asked to add ${nm(b.target)}. A second cleared member must approve before they can read anything.`, b.target);
          if (act === "approve") await sys(b.ch, `${nm(ACC)} approved ${nm(r.requester)}'s request: ${nm(b.target)} was added.`, b.target);
          if (act === "deny") await sys(b.ch, `${nm(ACC)} declined ${nm(r.requester)}'s request to add ${nm(b.target)}.`, b.target);
        }
        return json(res, 200, r);
      }
      if (act === "invite-sms") return json(res, 200, await rq("POST", "/invite-sms", { by: ACC, phone: b.phone }));
      return json(res, 404, { error: "unknown action" });
    }
    if (u.pathname === "/api/zrel/here") {
      // an officer standing at this PC approves on its screen with their own phone: the phone reads the QR code the
      // browser shows, the passkey standard checks over Bluetooth that the phone is near, and the passkey (enrolled by
      // the administrator for that officer) signs the request. The passkey is what proves the officer here.
      if (remote) return json(res, 403, { error: "This is done on the PC's own screen." });
      const pk = (n) => readJ(path.join(APPROVERS, path.basename(n) + ".passkey.json"));
      if (req.method === "GET") {
        let names = []; try { names = fs.readdirSync(APPROVERS).filter((f) => f.endsWith(".passkey.json")).map((f) => f.slice(0, -13)); } catch {}
        const r = readJ(reqFile(u.searchParams.get("id")) || "/nonexistent");
        if (!r || r.status !== "pending") return json(res, 404, { error: "No such request." });
        const core = {}; for (const k of CORE_KEYS) if (k in r) core[k] = r[k];
        return json(res, 200, { core, officers: names.filter((n) => n !== r.requester).map((n) => ({ name: n, cred_id: pk(n).cred_id, rp_id: pk(n).rp_id })) });
      }
      const b = await readBody(req);
      if (!["approve", "decline"].includes(b.op) || !sigShape(b.sig) || !pk(String(b.approver || ""))) return json(res, 400, { error: "The signature is missing or malformed." });
      if (b.op === "approve" && !/^\d{4}$/.test(String(b.code || ""))) return json(res, 200, { error: "Enter the 4-digit match code shown on this screen." });
      const p = reqFile(b.id);
      const out = !p ? { ok: false, message: "Unknown request." }
        : p.startsWith(GSYS) ? await guardd({ op: b.op, request: String(b.id), approver: path.basename(String(b.approver)), sig: String(b.sig), code: String(b.code || "") })
        : await signedAnswer([path.basename(p, ".json"), path.basename(String(b.approver)), b.op, String(b.sig), String(b.code || "")]);
      audit("msg-zrel-here", { request: String(b.id).slice(0, 40), approver: path.basename(String(b.approver)), op: b.op, ok: !!out.ok });
      return json(res, 200, out.ok ? { ok: true, message: out.message } : { error: out.message });
    }
    if (u.pathname === "/api/myrequests") {
      // this PC user's own requests, newest first; the match code is shown here so the user can read it to an officer
      if (remote) return json(res, 403, { error: "Open My requests on your ZENOS PC." });
      const me = require("os").userInfo().username, out = [];
      for (const d of [UREQ, path.join(GSYS, "requests")]) {
        let names = []; try { names = fs.readdirSync(d).filter((f) => f.endsWith(".json")); } catch {}
        for (const f of names) {
          const r = readJ(path.join(d, f));
          if (!r || r.requester !== me) continue;
          out.push({ id: r.id, kind: r.kind || "access", name: r.name || "", level: r.level, status: r.status, reason: r.reason || "",
                     created: r.created, required: r.required, approvals: (r.approvals || []).map((a) => a.approver),
                     declined_by: r.declined_by || null, code: r.status === "pending" ? r.code : null });
        }
      }
      out.sort((a, b) => String(b.created).localeCompare(String(a.created)));
      return json(res, 200, out.slice(0, 50));
    }
    if (u.pathname === "/api/zrel/answer" && req.method === "POST") {
      // an officer's answer, signed in their browser; it goes back to the stopped PC over the same Signal channel
      const b = await readBody(req);
      const z = [...hist].reverse().find((m) => m.kind === "zrel" && m.dir === "in" && m.ev && m.ev.core && m.ev.core.id === b.id);
      if (!z) return json(res, 404, { error: "No such request." });
      if (remote && !official(req) && z.level > 2) return json(res, 200, { error: "Answer this on a government-issued device." });
      if (!["approve", "decline"].includes(b.op) || !sigShape(b.sig)) return json(res, 400, { error: "The signature is missing or malformed." });
      if (b.op === "approve" && !/^\d{4}$/.test(String(b.code || ""))) return json(res, 200, { error: "Enter the 4-digit match code shown on the stopped PC." });
      try {
        await send(z.from, "", z.level, { id: zid(), kind: "zrel-sig", ev: { id: b.id, op: b.op, code: b.op === "approve" ? String(b.code) : "", sig: b.sig } });
        audit("msg-zrel-signed", { request: String(b.id).slice(0, 40), op: b.op });
        return json(res, 200, { ok: true });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/approvals") return json(res, 200, await rq("GET", `/approvals?who=${ACC}`));
    if (u.pathname === "/api/attach" && req.method === "POST") {
      const q = u.searchParams, level = Number(q.get("level")) || 1;
      if (capErr(level)) return json(res, 200, { error: capErr(level) });
      if (remote && !official(req) && level > 2) return json(res, 200, { error: "This phone is not registered as government-issued. Above L2, send from an official device." });
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > 25 * 1024 * 1024) return json(res, 200, { error: "Attachment too large (max 25 MB)." }); chunks.push(c); }
      try {
        const att = await sealAttachment(Buffer.concat(chunks), q.get("name") || "file", q.get("mime") || "application/octet-stream", level);
        const text = String(q.get("text") || ""), thread = q.get("thread") || null;
        // a file presented in a call: same end-to-end encrypted attachment, tagged with the call room
        const extra = q.get("kind") === "share" ? { att, kind: "share", ev: { room: String(q.get("room") || "").slice(0, 40) } } : { att };
        if (q.get("ch")) await sendChannel(q.get("ch"), text, level, thread, extra);
        else await send(q.get("to"), text, level, { id: `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, thread, ...extra });
        audit("msg-attachment-sent", { bytes: size, level });
        return json(res, 200, { ok: true, sha256: att.sha256 });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname.startsWith("/api/att/")) {
      const sha = u.pathname.split("/")[3] || "";
      const m = hist.find((x) => x.att && x.att.sha256 === sha);
      if (!/^[0-9a-f]{64}$/.test(sha) || !m || !fs.existsSync(path.join(ATT, sha))) return json(res, 404, { error: "not found" });
      if (remote && !official(req) && m.level > 2) return json(res, 403, { error: "Open on a government-issued device." });
      const inline = SAFE_INLINE.includes(m.att.mime);
      res.writeHead(200, { "Content-Type": inline ? m.att.mime : "application/octet-stream", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'", "Cache-Control": "private, max-age=3600",
        "Content-Disposition": `${inline && !u.searchParams.has("dl") ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(m.att.name)}` });
      return res.end(fs.readFileSync(path.join(ATT, sha)));
    }
    if (u.pathname === "/api/relays") return json(res, 200, { current: RELAYCFG.id, relays: relayList() });
    if (!remote && u.pathname === "/api/relays/add" && req.method === "POST") {
      const b = await readBody(req); const url = String(b.url || "").replace(/\/+$/, "");
      if (!/^https?:\/\/[A-Za-z0-9.-]+(:\d+)?(\/.*)?$/.test(url)) return json(res, 400, { error: "Enter a URL like https://relay.example.go.jp" });
      let ok = false; try { const r = await fetch(url + "/trust", { signal: AbortSignal.timeout(5000) }); ok = r.ok && !!(await r.json()).trust; } catch {}
      if (!ok) return json(res, 200, { error: "No ZENOS relay answered at that address." });
      const list = relayList(); const id = "r" + Date.now().toString(36);
      list.push({ id, name: String(b.name || url).slice(0, 60), url, maxLevel: Math.max(1, Math.min(5, Number(b.maxLevel) || 2)), kind: String(b.kind || "custom").slice(0, 20) });
      fs.writeFileSync(RELAYS_F, JSON.stringify(list, null, 1)); audit("msg-relay-added", { id, url });
      return json(res, 200, { ok: true, id });
    }
    if (!remote && u.pathname === "/api/relays/select" && req.method === "POST") {
      const { id } = await readBody(req); const r = relayList().find((x) => x.id === id);
      if (!r) return json(res, 404, { error: "No such relay." });
      const prev = RELAYCFG; RELAYCFG = r; RELAY = r.url; TRUST = null; CERT = null;
      try { st.peers = {}; st.intros = {}; persist(); await setup(); }
      catch (err) { RELAYCFG = prev; RELAY = prev.url; TRUST = null; CERT = null; try { await setup(); } catch {} return json(res, 200, { error: "Could not register on that relay: " + err.message }); }
      fs.writeFileSync(RCHOICE, JSON.stringify({ id }), { mode: 0o600 }); audit("msg-relay-selected", { id, url: r.url });
      return json(res, 200, { ok: true });
    }
    if (u.pathname === "/api/callservers") {
      if (remote) return json(res, 403, { error: "Change the call server on the ZENOS PC." });
      if (req.method === "GET") return json(res, 200, await rq("GET", "/call/servers"));
      return json(res, 200, await rq("POST", "/call/servers", await readBody(req)));
    }
    if (u.pathname === "/api/call/signal" && req.method === "POST") {
      // small call signals (page turned, hand raised, sharing stopped) travel as libsignal messages like everything else
      const b = await readBody(req);
      try {
        const conv = (m) => b.ch ? m.ch === b.ch : (!m.ch && m.peer === b.to);
        const last = [...hist].reverse().find((m) => m.kind === "call" && conv(m) && m.ev && m.ev.status === "start");
        if (!last) throw new Error("There is no call here.");
        const e = b.ev || {}; if (!["page", "hand", "stopshare"].includes(e.type)) throw new Error("Unknown signal.");
        const ev = { type: e.type, room: last.ev.room, sha: /^[0-9a-f]{64}$/.test(e.sha || "") ? e.sha : null, page: Math.max(1, Math.min(9999, Number(e.page) || 1)), on: !!e.on };
        if (remote && !official(req) && (last.level || 1) > 2) throw new Error("Not on this device.");
        if (b.ch) await sendChannel(b.ch, "", last.level || 1, null, { kind: "callsig", ev }); else await send(b.to, "", last.level || 1, { id: `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, kind: "callsig", ev });
        return json(res, 200, { ok: true });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/call/rekey" && req.method === "POST") {
      // Signal-style rotation: a fresh key goes only to the people actually in the call (who already passed the
      // membership + clearance gate to get into the room). Someone who left never receives it.
      const b = await readBody(req);
      try {
        const conv = (m) => b.ch ? m.ch === b.ch : (!m.ch && m.peer === b.to);
        const last = [...hist].reverse().find((m) => m.kind === "call" && conv(m) && m.ev && m.ev.status === "start");
        if (!last) throw new Error("There is no call here.");
        const level = last.level || 1;
        if (remote && !official(req) && level > 2) throw new Error("Not on this device.");
        let allowed = [];
        if (b.ch) { const chans = await rq("GET", `/channels?member=${ACC}`); const c = (chans || []).find((x) => x.id === b.ch); allowed = c ? c.members : []; }
        else allowed = [b.to];
        const idx = Math.max(0, Math.min(15, Number(b.idx) || 0));
        const key = crypto.randomBytes(32).toString("base64");
        const back = b.map || {};
        const to = (b.members || []).map((m) => back[m] || m).filter((m) => m !== ACC && allowed.includes(m) && PEOPLE[m] && PEOPLE[m].level >= level);
        for (const m of to) {
          try { await send(m, "", level, { ch: b.ch || null, id: `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, kind: "callkey", ev: { room: last.ev.room, key, idx } }); }
          catch (err) { audit("msg-callkey-failed", { to: m, error: String(err).slice(0, 60) }); }
        }
        audit("msg-call-rekey", { n: to.length, idx });
        return json(res, 200, { key, idx, sent: to.length });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (["/api/call/start", "/api/call/join", "/api/call/end"].includes(u.pathname) && req.method === "POST") {
      const b = await readBody(req);
      try {
        const conv = (m) => b.ch ? m.ch === b.ch : (!m.ch && m.peer === b.to);
        const last = [...hist].reverse().find((m) => m.kind === "call" && conv(m) && m.ev);
        let level = Number(b.level) || 1;
        if (b.ch) { const chans = await rq("GET", `/channels?member=${ACC}`); const c = (chans || []).find((x) => x.id === b.ch); if (!c) throw new Error("Unknown channel."); level = Math.max(level, c.level || 1); }
        if (u.pathname !== "/api/call/start") { if (!last) throw new Error("There is no call here."); level = last.level || level; }
        if (capErr(level)) return json(res, 200, { error: capErr(level) });
        if (level > PEOPLE[ACC].level) return json(res, 200, { error: `This call is L${level}; your clearance is L${PEOPLE[ACC].level}.` });
        if (remote && !official(req) && level > 2) return json(res, 200, { error: "This phone is not registered as government-issued. Calls above L2 need an official device." });
        if (u.pathname === "/api/call/end") {
          const ev = { status: "end", room: last.ev.room };
          if (b.ch) await sendChannel(b.ch, "", level, null, { kind: "call", ev }); else await send(b.to, "", level, { id: `${ACC}-${Date.now()}`, kind: "call", ev });
          return json(res, 200, { ok: true });
        }
        const tk = await rq("POST", "/call/token", { ch: b.ch || null, peer: b.to || null, acc: ACC });
        if (tk.error) return json(res, 200, { error: tk.error });
        let key;
        if (u.pathname === "/api/call/start") {
          key = crypto.randomBytes(32).toString("base64");
          const ev = { status: "start", room: tk.room, key, video: !!b.video };
          if (b.ch) await sendChannel(b.ch, "", level, null, { kind: "call", ev }); else await send(b.to, "", level, { id: `${ACC}-${Date.now()}`, kind: "call", ev });
          audit("msg-call-started", { level });
        } else {
          if (last.ev.status !== "start") throw new Error("That call has ended.");
          key = last.ev.key;
        }
        const host = String(req.headers.host || "127.0.0.1").split(":")[0];
        return json(res, 200, { url: tk.url || (remote ? `wss://${req.headers.host}` : `ws://${host}:7880`), token: tk.token, key, level, room: tk.room, map: tk.map || {}, me: Object.keys(tk.map || {}).find((k) => tk.map[k] === ACC) || ACC, server: tk.server });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (["/api/event", "/api/rsvp", "/api/evupd"].includes(u.pathname) && req.method === "POST") {
      const b = await readBody(req);
      const clean = (ev) => {
        const o = {}; if (!ev) return o;
        if (ev.title !== undefined) o.title = String(ev.title).slice(0, 120);
        if (ev.date !== undefined) { if (!/^\d{4}-\d{2}-\d{2}$/.test(ev.date)) throw new Error("Pick a date."); o.date = ev.date; }
        for (const k of ["start", "end"]) if (ev[k] !== undefined) { if (ev[k] && !/^\d{2}:\d{2}$/.test(ev[k])) throw new Error("Use a time like 10:00."); o[k] = ev[k] || ""; }
        if (ev.place !== undefined) o.place = String(ev.place).slice(0, 120);
        if (ev.note !== undefined) o.note = String(ev.note).slice(0, 1000);
        if (ev.attendees !== undefined) o.attendees = (ev.attendees || []).filter((x) => PEOPLE[x]).slice(0, 200);
        return o;
      };
      try {
        if (u.pathname === "/api/event") {
          const level = Number(b.level) || 1;
          if (capErr(level)) return json(res, 200, { error: capErr(level) });
          if (remote && !official(req) && level > 2) return json(res, 200, { error: "This phone is not registered as government-issued. Above L2, use an official device." });
          const ev = clean(b.ev); if (!ev.title || !ev.date) return json(res, 200, { error: "A title and a date are needed." });
          const id = `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
          if (b.ch) await sendChannel(b.ch, ev.title, level, null, { kind: "event", ev });
          else await send(b.to, ev.title, level, { id, kind: "event", ev });
          audit("msg-event-created", { level }); return json(res, 200, { ok: true });
        }
        const t = hist.find((m) => m.id === b.target && m.kind === "event");
        if (!t) return json(res, 404, { error: "No such event." });
        const extra = u.pathname === "/api/rsvp"
          ? { kind: "rsvp", target: t.id, status: ["yes", "maybe", "no"].includes(b.status) ? b.status : "yes" }
          : { kind: "evupd", target: t.id, ev: clean(b.ev), cancel: !!b.cancel };
        if (extra.kind === "evupd" && (t.from || (t.dir === "out" ? ACC : t.peer)) !== ACC) return json(res, 403, { error: "Only the person who created the event can change it." });
        if (t.ch) await sendChannel(t.ch, "", t.level, null, extra);
        else await send(t.peer, "", t.level, { id: `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, ...extra });
        return json(res, 200, { ok: true });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/lookup") { u.searchParams.set("by", ACC); return json(res, 200, await rq("GET", "/lookup?" + u.searchParams.toString())); }
    if (u.pathname === "/api/push/key") return json(res, 200, { key: vapid.publicKey });
    if (u.pathname === "/api/push/subscribe" && req.method === "POST") {
      if (!remote) return json(res, 200, { error: "Use a linked phone for push." });
      const { sub } = await readBody(req); devices[req.dev].push = sub; saveDev();
      audit("msg-push-subscribed", { device: req.dev.slice(0, 12) }); return json(res, 200, { ok: true });
    }
    if (u.pathname === "/api/push/test" && req.method === "POST") {
      const n = await pushTo(remote ? [req.dev] : Object.keys(devices), { title: "ZENOS", body: "Notifications are working on this phone.", tag: "test" }, { urgency: "high" });
      return json(res, 200, { ok: true, sent: n });
    }
    if (u.pathname === "/") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(fs.readFileSync(UI)); }
    if (u.pathname === "/manifest.webmanifest") { res.writeHead(200, { "Content-Type": "application/manifest+json" }); return res.end(fs.readFileSync(path.join(__dirname, "manifest.webmanifest"))); }
    if (u.pathname === "/sw.js") { res.writeHead(200, { "Content-Type": "text/javascript" }); return res.end(fs.readFileSync(path.join(__dirname, "sw.js"))); }
    { const am = u.pathname.match(/^\/av\/([a-z0-9]+-(t|c))\.jpg$/); if (am) { const f = path.join(__dirname, "av", am[1] + ".jpg"); if (fs.existsSync(f)) { res.writeHead(200, { "Content-Type": "image/jpeg", "Cache-Control": "max-age=86400" }); return res.end(fs.readFileSync(f)); } } }
    if (u.pathname === "/app-icon-180.png" || u.pathname === "/app-icon-512.png") { res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "no-cache" }); return res.end(fs.readFileSync(path.join(__dirname, u.pathname.slice(1)))); }
    if (u.pathname === "/pdf/pdf.min.mjs" || u.pathname === "/pdf/pdf.worker.min.mjs") {   // Mozilla pdf.js renders shared PDFs on the device
      res.writeHead(200, { "Content-Type": "text/javascript", "Cache-Control": "no-cache" }); return res.end(fs.readFileSync(path.join(__dirname, "node_modules/pdfjs-dist/legacy/build", path.basename(u.pathname)))); }
    if (u.pathname === "/zcred.js") { res.writeHead(200, { "Content-Type": "text/javascript", "Cache-Control": "no-cache" }); return res.end(fs.readFileSync(path.join(__dirname, "zcred.js"))); }
    if (u.pathname === "/zcall.js" || u.pathname === "/lk/livekit-client.umd.js" || u.pathname === "/lk/livekit-client.e2ee.worker.js") {
      const fp = u.pathname === "/zcall.js" ? path.join(__dirname, "zcall.js") : path.join(__dirname, "node_modules/livekit-client/dist", path.basename(u.pathname));
      res.writeHead(200, { "Content-Type": "text/javascript", "Cache-Control": "no-cache" }); return res.end(fs.readFileSync(fp)); }
    if (u.pathname === "/app-icon.svg") { res.writeHead(200, { "Content-Type": "image/svg+xml" }); return res.end(fs.readFileSync(path.join(__dirname, "app-icon.svg"))); }
    if (u.pathname === "/api/me") {
      const ph = await rq("GET", `/phone/${ACC}`).catch(() => ({}));
      return json(res, 200, { id: ACC, name: PEOPLE[ACC].name, level: PEOPLE[ACC].level, username: PEOPLE[ACC].username, org: PEOPLE[ACC].org,
        phone: PEOPLE[ACC].phone, phoneVerified: !!(ph && ph.verified && ph.phone === PEOPLE[ACC].phone), phoneVia: ph && ph.via || null,
        remote: !!remote, push: remote ? !!devices[req.dev].push : null, official: remote ? official(req) : true,
        readLevel: remote && !official(req) ? Math.min(2, PEOPLE[ACC].level) : PEOPLE[ACC].level,
        maxLevel: Math.min(remote && !official(req) ? Math.min(2, PEOPLE[ACC].level) : PEOPLE[ACC].level, RELAYCFG.maxLevel || 5),
        relay: { id: RELAYCFG.id, name: RELAYCFG.name, maxLevel: RELAYCFG.maxLevel, kind: RELAYCFG.kind } });
    }
    if (u.pathname === "/api/contacts") return json(res, 200, await rq("GET", "/accounts"));
    if (u.pathname === "/api/messages") return json(res, 200, restrict(hist.filter((m) => m.peer === u.searchParams.get("peer") && !m.ch), remote, req));
    if (u.pathname === "/api/channels") {
      const here = await rq("GET", `/channels?member=${ACC}`);
      return json(res, 200, [...(Array.isArray(here) ? here : []),
        ...Object.values(rooms).map((r) => ({ id: r.id, name: r.name, members: r.members, level: r.level, kind: "room", by: r.by }))]);
    }
    if (u.pathname === "/api/rooms" && req.method === "POST") {      // a room that can include people at other organizations
      const b = await readBody(req);
      if (capErr(b.level)) return json(res, 200, { error: capErr(b.level) });
      try { return json(res, 200, { ok: true, room: await makeRoom(b.name, b.members, Number(b.level) || 1) }); }
      catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/channel-messages") { const ch = u.searchParams.get("ch"); return json(res, 200, restrict(hist.filter((m) => m.ch === ch), remote, req)); }
    if (u.pathname === "/api/channel-send" && req.method === "POST") {
      let b = ""; for await (const c of req) b += c;
      const { ch, text, level, thread } = JSON.parse(b);
      if (capErr(level)) return json(res, 200, { error: capErr(level) });
      if (remote && !official(req) && Number(level) > 2) return json(res, 200, { error: "This phone is not registered as government-issued. Above L2, send from an official device." });
      try { await sendChannel(ch, String(text), Number(level), thread || null); return json(res, 200, { ok: true }); }
      catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/all") return json(res, 200, restrict(hist, remote, req));
    if (u.pathname === "/api/local") {
      const LF = path.join(DIR, "local.json");
      // a phone that is not government-issued sees and changes only what L1-L2 allows: no drafts (they hold the text
      // being typed in any conversation, L3+ included), no saved list, no do-not-disturb settings
      const limited = remote && !official(req);
      const KEYS = limited ? ["read"] : ["saved", "drafts", "read", "dnd", "dndStep"];
      if (req.method === "POST") { let b = ""; for await (const c of req) b += c; const o = JSON.parse(b);
        const cur = load(LF, {}); for (const k of KEYS) if (o[k] !== undefined) cur[k] = o[k];
        fs.writeFileSync(LF, JSON.stringify(cur), { mode: 0o600 }); return json(res, 200, { ok: true }); }
      const all = load(LF, {});
      return json(res, 200, limited ? { read: all.read } : all);
    }
    if (u.pathname === "/api/react" && req.method === "POST") {
      let b = ""; for await (const c of req) b += c;
      const { ch, peer, target, emoji, on } = JSON.parse(b);
      const tm = hist.find((m) => m.id === target);
      const level = tm ? tm.level : 1;
      const extra = { kind: "react", target: String(target), emoji: String(emoji).slice(0, 16), on: on !== false };
      try {
        if (ch) await sendChannel(ch, "", level, null, extra);
        else await send(peer, "", level, { id: `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, ...extra });
        return json(res, 200, { ok: true });
      } catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/send" && req.method === "POST") {
      let b = ""; for await (const c of req) b += c;
      const { to, text, level, thread } = JSON.parse(b);
      if (capErr(level)) return json(res, 200, { error: capErr(level) });
      if (remote && !official(req) && Number(level) > 2) return json(res, 200, { error: "This phone is not registered as government-issued. Above L2, send from an official device." });
      const id = `${ACC}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
      try { await send(to, String(text), Number(level), { id, thread: thread || null }); return json(res, 200, { ok: true, id }); }
      catch (err) { return json(res, 200, { error: err.message }); }
    }
    if (u.pathname === "/api/safety") {
      const peer = u.searchParams.get("peer");
      const theirs = st.identities[peer];
      if (!theirs) return json(res, 200, { error: "Exchange a message first, then compare the safety number." });
      const fp = S.Fingerprint.new(5200, 2, Buffer.from(ACC), S.IdentityKeyPair.deserialize(ub(st.idkp)).publicKey,
        Buffer.from(peer), S.PublicKey.deserialize(ub(theirs)));
      return json(res, 200, { number: fp.displayableFingerprint().toString().replace(/(\d{5})/g, "$1 ").trim() });
    }
    json(res, 404, { error: "not found" });
  } catch (err) { json(res, 500, { error: String(err) }); }
}
// The local port is this PC's own window. The remote port is only reachable through the encrypted tunnel, and every request needs a linked-device cookie.
// Linked phones reach the call server only through this gate: the LiveKit signalling websocket (/rtc) is
// passed through for linked devices (cookie) — the SFU itself is never exposed. Media then flows to the SFU directly.
const RSRV = http.createServer((q, r) => handle(q, r, true));
RSRV.on("upgrade", (req, sock, head) => {
  const u = new URL(req.url, "http://x"); const sid = cookieSid(req);
  if (!u.pathname.startsWith("/rtc") || !(sid && devices[sh(sid)])) { sock.end("HTTP/1.1 401 Unauthorized\r\n\r\n"); return; }
  const up = require("net").connect(7880, "127.0.0.1", () => {
    let h = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() !== "cookie") h += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    up.write(h + "\r\n"); if (head && head.length) up.write(head); sock.pipe(up).pipe(sock);
  });
  up.on("error", () => sock.destroy()); sock.on("error", () => up.destroy());
});
RSRV.listen(PORT + 100, "127.0.0.1");
http.createServer((q, r) => handle(q, r, false)).listen(PORT, "127.0.0.1", async () => {
  await setup();
  setInterval(() => receive().catch((e) => console.error(e)), 1000);
  let zbusy = false;
  setInterval(() => { if (zbusy) return; zbusy = true; watchRelease().catch((e) => console.error(e)).finally(() => { zbusy = false; }); }, 2000);
  console.log(`${ACC} on ${PORT}`);
});

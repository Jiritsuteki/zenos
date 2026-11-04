// ZENOS Messages across organizations (docs/FEDERATION.md).
// Each organization runs its own relay. Relays reach each other only when both organizations are on the member list:
// an entry counts only with signatures of at least k (never fewer than 2) distinct responsible bodies, so one
// stolen signing key cannot add an organization. Every relay-to-relay request is signed with the sending relay's own
// key (Ed25519), the key its listed entry names. Whether a request may pass is decided by zenos-decide ("federate",
// proven in formal/ZenosFormal/Federation.lean), never by this file: when zenos-decide is missing, everything is refused.
// Content stays Signal-protocol ciphertext end to end. The receiving relay learns which relay sent an envelope and
// which mailbox it is for, not which person sent it.
// Disaster alerts (CAP-like, from a publish-only member such as GEOID) are kept here for the organization's devices;
// each device decides on its own whether it is inside the area (the device's location never comes to the relay).
// Answers (safe / need help) are counted without accounts; only counts go to other organizations.
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const DECIDE = [process.env.ZENOS_DECIDE, "/usr/lib/zenos/zenos-decide",
  path.join(__dirname, "..", "formal", ".lake", "build", "bin", "zenos-decide")].find((p) => p && fs.existsSync(p));

function decide(req) {
  if (!DECIDE) return { allow: false, reason: "zenos-decide missing" };
  const r = spawnSync(DECIDE, [], { input: JSON.stringify(req), encoding: "utf8", timeout: 5000 });
  try { const a = JSON.parse(r.stdout); return a.error ? { allow: false, reason: a.error } : a; }
  catch { return { allow: false, reason: "zenos-decide failed" }; }
}

const sha = (x) => crypto.createHash("sha256").update(x).digest("hex");
const b64 = (u) => Buffer.from(u).toString("base64");
// Ed25519 public keys travel as 32 raw bytes in base64
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const pubFromRaw = (raw) => crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(raw, "base64")]), format: "der", type: "spki" });
const rawFromPub = (k) => b64(k.export({ format: "der", type: "spki" }).subarray(12));
function verify(rawKey, text, sig) {
  try { return crypto.verify(null, Buffer.from(text), pubFromRaw(rawKey), Buffer.from(sig, "base64")); } catch { return false; }
}

/** What an authority signs for an entry of the member list. */
const entryText = (e) => "zenos-member-v1\n" + JSON.stringify([e.org, e.url, e.key, Number(e.max_level), !!e.publish_only]);
/** What a relay signs for each request to another relay. */
const reqText = (method, p, ts, raw) => `zenos-relay-v1 ${method} ${p} ${ts} ${sha(raw || "")}`;

const ORG = /^[a-z0-9][a-z0-9.-]{1,80}$/;
const SEVERITY = ["extreme", "severe", "moderate", "minor", "unknown"];

function load(f, d) { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return d; } }

function signer(keyFile) {
  let priv;
  if (fs.existsSync(keyFile)) priv = crypto.createPrivateKey(fs.readFileSync(keyFile));
  else {
    const kp = crypto.generateKeyPairSync("ed25519"); priv = kp.privateKey;
    fs.writeFileSync(keyFile, priv.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  }
  return { pub: rawFromPub(crypto.createPublicKey(priv)), sign: (text) => b64(crypto.sign(null, Buffer.from(text), priv)) };
}

/** A signed request to another relay. */
async function relayRequest(me, url, method, p, obj) {
  const raw = obj ? JSON.stringify(obj) : ""; const ts = String(Date.now());
  const h = { "Content-Type": "application/json", "X-Zenos-Relay": `${me.org} ${ts} ${me.sign(reqText(method, p, ts, raw))}` };
  const r = await fetch(url.replace(/\/$/, "") + p, { method, headers: h, body: raw || undefined, signal: AbortSignal.timeout(15000) });
  let j = {}; try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
}

/**
 * The relay's federation endpoints. ctx: { DIR, audit, send, body, isAdmin, authed, deliverSealed(mbx, uak, body) ->
 * {status, body}, bundleFor(acc) -> bundle|null, trust }
 */
function federation(ctx) {
  const F = path.join(ctx.DIR, "federation.json");     // { org, url, max_level }   set by the relay's administrator
  const M = path.join(ctx.DIR, "members.json");        // { k, authorities:[{id,key}], entries:[{org,url,key,max_level,publish_only,sigs:[{by,sig}]}] }
  const A = path.join(ctx.DIR, "alerts.json");
  const key = signer(path.join(ctx.DIR, "relay-key.pem"));
  let cfg = load(F, null), members = load(M, null), alerts = load(A, {});
  const saveAlerts = () => fs.writeFileSync(A, JSON.stringify(alerts), { mode: 0o600 });
  const me = { get org() { return cfg && cfg.org; }, sign: key.sign };
  const SEEN = new Map();

  /** The member list as zenos-decide sees it: each authority signature checked here, the counting proven there. */
  function decideReq(from, to, kind, level, relaySigOk, fresh) {
    const ml = members || { k: 0, authorities: [], entries: [] };
    const auth = Object.fromEntries((ml.authorities || []).map((a) => [a.id, a.key]));
    return {
      op: "federate", authorities: Object.keys(auth), k: Number(ml.k) || 0, from, to, relay_sig_ok: !!relaySigOk, fresh: !!fresh,
      kind, level: Number(level) || 0,
      members: (ml.entries || []).map((e) => ({ org: String(e.org), max_level: Number(e.max_level) || 0, publish_only: !!e.publish_only,
        sigs: (e.sigs || []).map((s) => ({ by: String(s.by), ok: !!auth[s.by] && verify(auth[s.by], entryText(e), s.sig) })) })),
    };
  }
  // the entry the decision will use: the first one whose signatures count (same rule as `lookup` in the proof)
  function entryOf(org) {
    const d = decideReq(org, org, "alert", 0, true, true), need = d.k;
    const i = d.members.findIndex((m) => m.org === org && need >= 2 && new Set(m.sigs.filter((s) => s.ok && d.authorities.includes(s.by)).map((s) => s.by)).size >= need);
    return i < 0 ? null : members.entries[i];
  }

  /** Check a request from another relay: its signature, freshness and the proven decision. */
  function inbound(req, raw, kind, level) {
    const hdr = String(req.headers["x-zenos-relay"] || "").split(" ");
    const [from, ts, sig] = hdr;
    if (!cfg || !cfg.org) return { allow: false, reason: "federation is not set up on this relay" };
    if (!ORG.test(from || "") || !ts || !sig) return { allow: false, reason: "unsigned" };
    const e = entryOf(from);
    const sigOk = !!e && verify(e.key, reqText(req.method, req.url, ts, raw), sig);
    const now = Date.now(); const fresh = Math.abs(now - Number(ts)) < 300e3 && !SEEN.has(sig);
    const d = decide(decideReq(from, cfg.org, kind, level, sigOk, fresh));
    if (d.allow) { SEEN.set(sig, now); for (const [k, t] of SEEN) if (now - t > 600e3) SEEN.delete(k); }
    return { ...d, from };
  }
  function outbound(to, kind, level) {
    if (!cfg || !cfg.org) return { allow: false, reason: "federation is not set up on this relay" };
    const d = decide(decideReq(cfg.org, to, kind, level, true, true));
    return d.allow ? { ...d, entry: entryOf(to) } : d;
  }
  async function rawBody(req) { const c = []; let n = 0; for await (const x of req) { n += x.length; if (n > 30 * 1024 * 1024) throw new Error("too large"); c.push(x); } return Buffer.concat(c).toString("utf8"); }

  function validAlert(a) {
    if (!a || typeof a !== "object") return "not an alert";
    if (!/^[A-Za-z0-9._:-]{4,80}$/.test(a.id || "")) return "id";
    if (!SEVERITY.includes(a.severity)) return "severity";
    if (!["official", "simulation"].includes(a.label)) return "label (official or simulation)";
    if (!a.issuer || String(a.issuer).length > 120) return "issuer";
    if (!/^https:\/\//.test(a.source_url || "") || !/^[0-9a-f]{64}$/.test(a.source_sha256 || "")) return "source (https URL and SHA-256)";
    if (isNaN(Date.parse(a.sent)) || isNaN(Date.parse(a.expires))) return "sent / expires";
    const ar = a.area || {};
    const polys = Array.isArray(ar.polygons) ? ar.polygons : [], codes = Array.isArray(ar.codes) ? ar.codes : [];
    if (!polys.length && !codes.length) return "area";
    for (const p of polys) if (!Array.isArray(p) || p.length < 3 || !p.every((q) => Array.isArray(q) && q.length === 2 && q.every(Number.isFinite))) return "polygon";
    return null;
  }
  const pick = (a) => ({ id: a.id, kind: String(a.kind || "").slice(0, 60), severity: a.severity, label: a.label, issuer: String(a.issuer),
    headline: String(a.headline || "").slice(0, 300), sent: a.sent, expires: a.expires, area: { polygons: a.area.polygons || [], codes: a.area.codes || [] },
    source_url: a.source_url, source_sha256: a.source_sha256 });

  return async function handle(req, res, u, parts) {
    const { send } = ctx;
    if (req.method === "GET" && u.pathname === "/.well-known/zenos-relay")
      return send(res, 200, { version: 1, org: cfg ? cfg.org : null, url: cfg ? cfg.url : null, key: key.pub, trust: ctx.trust }), true;
    if (parts[0] === "fed" && parts[1] === "config" && req.method === "POST") {          // administration only
      if (!ctx.isAdmin(req)) return send(res, 403, { error: "administration only" }), true;
      const b = await ctx.body(req);
      if (b.org !== undefined) { if (!ORG.test(b.org) || !/^https?:\/\//.test(b.url || "")) return send(res, 400, { error: "org and url" }), true;
        cfg = { org: b.org, url: b.url, max_level: Number(b.max_level) || 1 }; fs.writeFileSync(F, JSON.stringify(cfg), { mode: 0o600 }); }
      if (b.members !== undefined) { members = b.members; fs.writeFileSync(M, JSON.stringify(members), { mode: 0o600 }); }
      ctx.audit("fed-config", { org: cfg && cfg.org, entries: members ? (members.entries || []).length : 0 });
      return send(res, 200, { ok: true, key: key.pub }), true;
    }
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "members") return send(res, 200, members || {}), true;
    // the sealed-sender trust roots of the listed organizations, fetched from their relays and kept only when the
    // relay's answer names the key its entry lists
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "trust") {
      const out = {};
      for (const e of (members && members.entries) || []) {
        if (e.publish_only || entryOf(e.org) !== e || (cfg && e.org === cfg.org)) continue;
        try { const r = await fetch(e.url.replace(/\/$/, "") + "/.well-known/zenos-relay", { signal: AbortSignal.timeout(8000) }); const j = await r.json();
              if (j.org === e.org && j.key === e.key && j.trust) out[e.org] = j.trust; } catch {}
      }
      return send(res, 200, out), true;
    }

    // ---- a person here sends to a mailbox at another organization: the person is checked here (device signature),
    // the other relay only sees this relay
    if (req.method === "POST" && parts[0] === "fed" && parts[1] === "send") {
      const b = await ctx.body(req);
      if (!ctx.authed(req, b.by)) return send(res, 403, { error: "unsigned" }), true;
      const d = outbound(b.to_org, "message", b.level);
      if (!d.allow) { ctx.audit("fed-refused", { to_org: b.to_org, reason: d.reason }); return send(res, 403, { error: "Not allowed: " + d.reason }), true; }
      const r = await relayRequest(me, d.entry.url, "POST", "/fed/deliver", { mbx: b.mbx, uak: b.uak || null, body: b.body, level: Number(b.level) || 0 });
      ctx.audit("fed-sent", { to_org: b.to_org, status: r.status, bytes: Buffer.from(String(b.body || ""), "base64").length });
      return send(res, r.status, r.body), true;
    }
    if (req.method === "POST" && parts[0] === "fed" && parts[1] === "deliver") {
      const raw = await rawBody(req); let b; try { b = JSON.parse(raw); } catch { return send(res, 400, { error: "bad json" }), true; }
      const d = inbound(req, raw, "message", b.level);
      if (!d.allow) { ctx.audit("fed-refused", { from_org: d.from || null, reason: d.reason }); return send(res, 403, { error: "Not allowed: " + d.reason }), true; }
      const r = await ctx.deliverSealed(b.mbx, b.uak, b.body);
      ctx.audit("fed-delivered", { from_org: d.from, mailbox: String(b.mbx || "").slice(0, 8), status: r.status });
      return send(res, r.status, r.body), true;
    }
    // ---- key bundles of a person at another organization (needed to start a Signal session)
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "keys" && parts.length === 4) {
      const by = u.searchParams.get("by");
      if (!ctx.authed(req, by)) return send(res, 403, { error: "unsigned" }), true;
      const d = outbound(parts[2], "keys", 1);
      if (!d.allow) return send(res, 403, { error: "Not allowed: " + d.reason }), true;
      const r = await relayRequest(me, d.entry.url, "GET", "/fed/bundle/" + encodeURIComponent(parts[3]));
      ctx.audit("fed-keys", { to_org: parts[2], status: r.status });
      return send(res, r.status, r.body), true;
    }
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "bundle" && parts.length === 3) {
      const d = inbound(req, "", "keys", 1);
      if (!d.allow) return send(res, 403, { error: "Not allowed: " + d.reason }), true;
      const b = ctx.bundleFor(decodeURIComponent(parts[2]));
      if (!b) return send(res, 404, { error: "unknown account" }), true;
      ctx.audit("fed-bundle-given", { from_org: d.from });
      // only what a Signal session needs, and the name and level shown to the other side (no phone, no settings)
      const keep = ["regId", "identity", "signed", "kyber", "preKey", "intro", "name", "level"];
      return send(res, 200, { ...Object.fromEntries(keep.map((k) => [k, b[k] === undefined ? null : b[k]])), org: cfg.org }), true;
    }

    // ---- an attachment sent by a person at another organization: the ciphertext is fetched from the sender's relay
    // (the key is only in the sealed message). The sender's relay gives it only to a listed organization that may
    // receive the level the sender gave it.
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "blob" && parts.length === 4) {
      const by = u.searchParams.get("by"), level = Number(u.searchParams.get("level")) || 0;
      if (!ctx.authed(req, by)) return send(res, 403, { error: "unsigned" }), true;
      const d = outbound(parts[2], "message", level);
      if (!d.allow) return send(res, 403, { error: "Not allowed: " + d.reason }), true;
      if (!/^[0-9a-f]{32}$/.test(parts[3])) return send(res, 400, { error: "blob id" }), true;
      const ts = String(Date.now()), p = "/fed/blobs/" + parts[3];
      try {
        const r = await fetch(d.entry.url.replace(/\/$/, "") + p, { headers: { "X-Zenos-Relay": `${me.org} ${ts} ${me.sign(reqText("GET", p, ts, ""))}` }, signal: AbortSignal.timeout(30000) });
        const buf = Buffer.from(await r.arrayBuffer());
        ctx.audit("fed-blob-fetched", { from_org: parts[2], status: r.status, bytes: buf.length });
        res.writeHead(r.status, { "Content-Type": r.ok ? "application/octet-stream" : "application/json" }); res.end(buf);
      } catch (err) { send(res, 502, { error: "the other organization's relay did not answer" }); }
      return true;
    }
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "blobs" && parts.length === 3) {
      const b = ctx.blobFor ? ctx.blobFor(parts[2]) : null;
      const d = inbound(req, "", "message", b ? b.level : 5);
      if (!d.allow) { ctx.audit("fed-refused", { from_org: d.from || null, reason: d.reason, kind: "blob" }); return send(res, 403, { error: "Not allowed: " + d.reason }), true; }
      if (!b) return send(res, 404, { error: "gone" }), true;
      ctx.audit("fed-blob-given", { to_org: d.from, bytes: b.data.length, level: b.level });
      res.writeHead(200, { "Content-Type": "application/octet-stream" }); res.end(b.data);
      return true;
    }

    // ---- disaster alerts
    if (req.method === "POST" && parts[0] === "fed" && parts[1] === "alert") {
      const raw = await rawBody(req); let a; try { a = JSON.parse(raw); } catch { return send(res, 400, { error: "bad json" }), true; }
      const d = inbound(req, raw, "alert", 1);
      if (!d.allow) { ctx.audit("fed-refused", { from_org: d.from || null, reason: d.reason, kind: "alert" }); return send(res, 403, { error: "Not allowed: " + d.reason }), true; }
      const bad = validAlert(a); if (bad) return send(res, 400, { error: "alert: " + bad }), true;
      const key2 = d.from + "/" + a.id;
      alerts[key2] = { ...pick(a), from: d.from, received: new Date().toISOString(), answers: (alerts[key2] || {}).answers || {} };
      for (const k of Object.keys(alerts)) if (Date.parse(alerts[k].expires) < Date.now() - 7 * 86400e3) delete alerts[k];
      saveAlerts();
      ctx.audit("fed-alert", { from_org: d.from, id: a.id, label: a.label, severity: a.severity });
      return send(res, 200, { ok: true }), true;
    }
    if (req.method === "GET" && parts[0] === "alerts" && parts.length === 1) {
      const since = Date.parse(u.searchParams.get("since") || "") || 0;
      return send(res, 200, Object.entries(alerts).filter(([, a]) => Date.parse(a.received) > since && Date.parse(a.expires) > Date.now())
        .map(([k, a]) => { const { answers, ...rest } = a; return { key: k, ...rest }; })), true;
    }
    // an answer card: one answer per device token (only its hash is kept), no account
    if (req.method === "POST" && parts[0] === "alerts" && parts[3] === "answer") {
      const k = decodeURIComponent(parts[1]) + "/" + decodeURIComponent(parts[2]); const a = alerts[k];
      const b = await ctx.body(req);
      if (!a) return send(res, 404, { error: "unknown alert" }), true;
      if (!["safe", "help"].includes(b.status) || !/^[0-9a-f]{32,64}$/.test(b.token || "")) return send(res, 400, { error: "status safe|help and a device token" }), true;
      a.answers[sha("zenos-answer|" + k + "|" + b.token)] = b.status; saveAlerts();
      return send(res, 200, { ok: true }), true;
    }
    const counts = (a) => { const v = Object.values(a.answers || {}); return { safe: v.filter((x) => x === "safe").length, help: v.filter((x) => x === "help").length }; };
    if (req.method === "GET" && parts[0] === "alerts" && parts[3] === "counts") {
      const a = alerts[decodeURIComponent(parts[1]) + "/" + decodeURIComponent(parts[2])];
      if (!a) return send(res, 404, { error: "unknown alert" }), true;
      return send(res, 200, { org: cfg && cfg.org, ...counts(a) }), true;
    }
    // counts for another organization (a prefecture, a ministry): signed request, counts only
    if (req.method === "GET" && parts[0] === "fed" && parts[1] === "counts" && parts.length === 4) {
      const d = inbound(req, "", "alert", 1);
      if (!d.allow) return send(res, 403, { error: "Not allowed: " + d.reason }), true;
      const a = alerts[decodeURIComponent(parts[2]) + "/" + decodeURIComponent(parts[3])];
      if (!a) return send(res, 404, { error: "unknown alert" }), true;
      ctx.audit("fed-counts-given", { to_org: d.from, id: a.id });
      return send(res, 200, { org: cfg.org, ...counts(a) }), true;
    }
    return false;
  };
}

/** For a publish-only member (GEOID): sign an alert and push it to every listed organization that receives messages. */
async function publishAlert({ org, keyFile, members, alert }) {
  const me = { org, sign: signer(keyFile).sign };
  const out = [];
  for (const e of members.entries || []) {
    if (e.publish_only || e.org === org) continue;
    try { const r = await relayRequest(me, e.url, "POST", "/fed/alert", alert); out.push({ org: e.org, status: r.status, error: r.body.error || null }); }
    catch (err) { out.push({ org: e.org, status: 0, error: String(err.message || err) }); }
  }
  return out;
}

module.exports = { federation, publishAlert, signer, entryText, reqText, relayRequest, decide };

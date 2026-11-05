// Messenger federation: two organizations' relays reach each other only through the signed member list, and a
// Signal-protocol message (sealed sender) goes from a person at one organization to a person at the other, end to end.
// Also: unlisted, singly signed, replayed, tampered and over-level requests are refused; a publish-only member (GEOID)
// pushes alerts and cannot send messages; answers are counted without accounts and only counts go to another relay.
//   node tests/messenger_federation.js   (needs messenger/node_modules: cd messenger && npm ci; and zenos-decide built:
//   cd formal && lake build)
const path = require("path"), os = require("os"), fs = require("fs"), crypto = require("crypto"), { spawn } = require("child_process");
const MSG = path.join(__dirname, "..", "messenger");
const S = require(require.resolve("@signalapp/libsignal-client", { paths: [MSG] }));
const F = require(path.join(MSG, "federation.js"));
const b64 = (u) => Buffer.from(u).toString("base64"), ub = (s) => Buffer.from(s, "base64");
const sha = (x) => crypto.createHash("sha256").update(String(x)).digest("hex");
const ADMIN = crypto.randomBytes(12).toString("hex");
const base = 18900 + Math.floor(Math.random() * 400);
const relays = {}, homes = [];
function start(name, port) {
  const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "zfed-")); homes.push(HOME);
  const p = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(port), ZENOS_RELAY_ADMIN: ADMIN }, stdio: "ignore" });
  relays[name] = { p, url: `http://127.0.0.1:${port}`, HOME };
}
const finish = (code) => { for (const r of Object.values(relays)) r.p.kill(); for (const h of homes) fs.rmSync(h, { recursive: true, force: true }); process.exit(code); };
let fail = 0; const check = (name, cond, got) => { console.log((cond ? "ok   " : "FAIL ") + name, cond ? "" : JSON.stringify(got)); if (!cond) fail++; };
async function j(url, method = "GET", obj, headers = {}) {
  const raw = obj === undefined ? undefined : (typeof obj === "string" ? obj : JSON.stringify(obj));
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json", ...headers }, body: raw }); let b = {}; try { b = await r.json(); } catch {} return [r.status, b];
}

// one person's device, in memory
function device(acc) {
  const st = { idkp: S.IdentityKeyPair.generate(), regId: 1 + Math.floor(Math.random() * 16000), sessions: {}, ids: {}, pre: {}, signed: {}, kyber: {} };
  const sess = new (class extends S.SessionStore {
    async saveSession(a, r) { st.sessions[a.toString()] = r.serialize(); }
    async getSession(a) { const x = st.sessions[a.toString()]; return x ? S.SessionRecord.deserialize(x) : null; }
    async getExistingSessions(as) { return (await Promise.all(as.map((a) => this.getSession(a)))).filter(Boolean); } })();
  const ident = new (class extends S.IdentityKeyStore {
    async getIdentityKey() { return st.idkp.privateKey; } async getLocalRegistrationId() { return st.regId; }
    async saveIdentity(a, k) { st.ids[a.name()] = k; return S.IdentityChange.NewOrUnchanged; }
    async isTrustedIdentity() { return true; } async getIdentity(a) { return st.ids[a.name()] || null; } })();
  const pks = new (class extends S.PreKeyStore { async savePreKey(i, r) { st.pre[i] = r; } async getPreKey(i) { return st.pre[i]; } async removePreKey(i) { delete st.pre[i]; } })();
  const spks = new (class extends S.SignedPreKeyStore { async saveSignedPreKey(i, r) { st.signed[i] = r; } async getSignedPreKey(i) { return st.signed[i]; } })();
  const kpks = new (class extends S.KyberPreKeyStore { async saveKyberPreKey(i, r) { st.kyber[i] = r; } async getKyberPreKey(i) { return st.kyber[i]; } async markKyberPreKeyUsed() {} })();
  const sk = S.PrivateKey.generate(), s = S.SignedPreKeyRecord.new(1, Date.now(), sk.getPublicKey(), sk, st.idkp.privateKey.sign(sk.getPublicKey().serialize()));
  const kk = S.KEMKeyPair.generate(), k = S.KyberPreKeyRecord.new(1, Date.now(), kk, st.idkp.privateKey.sign(kk.getPublicKey().serialize()));
  const pk = S.PrivateKey.generate(); st.pre[7] = S.PreKeyRecord.new(7, pk.getPublicKey(), pk); st.signed[1] = s; st.kyber[1] = k;
  const intro = { id: crypto.randomBytes(16).toString("hex"), tok: crypto.randomBytes(32).toString("hex") };
  const auth = (method, p, raw) => { const ts = String(Date.now()); return { "X-Zenos-Auth": `${acc} ${ts} ${b64(st.idkp.privateKey.sign(Buffer.from(`${method} ${p} ${ts} ${sha(raw || "")}`)))}` }; };
  return { acc, st, sess, ident, pks, spks, kpks, intro, auth, addr: S.ProtocolAddress.new(acc, 1),
    bundle: () => ({ name: acc, level: 3, regId: st.regId, intro: intro.id, identity: b64(st.idkp.publicKey.serialize()), findByPhone: true,
      signed: { id: 1, pub: b64(s.publicKey().serialize()), sig: b64(s.signature()) }, kyber: { id: 1, pub: b64(k.publicKey().serialize()), sig: b64(k.signature()) },
      preKeys: [{ id: 7, pub: b64(pk.getPublicKey().serialize()) }] }) };
}
async function signed(dev, url, method, p, obj) { const raw = obj ? JSON.stringify(obj) : ""; return j(url + p, method, raw || undefined, dev.auth(method, p, raw)); }

(async () => {
  start("ministry", base); start("city", base + 1); start("rogue", base + 2);
  for (const r of Object.values(relays)) for (let i = 0; i < 60; i++) { try { await fetch(r.url + "/trust"); break; } catch { await new Promise((z) => setTimeout(z, 100)); } }
  const A = relays.ministry, B = relays.city, C = relays.rogue, ad = { "X-Zenos-Admin": ADMIN };
  // each relay's own key (made on first start)
  for (const [n, r] of Object.entries(relays)) { const [, wk] = await j(r.url + "/.well-known/zenos-relay"); r.key = wk.key; check(n + ": publishes its relay key", /^[A-Za-z0-9+/]{43}=$/.test(wk.key || ""), wk); }
  const geoHome = fs.mkdtempSync(path.join(os.tmpdir(), "zfed-geo-")); homes.push(geoHome);
  const geoKeyFile = path.join(geoHome, "geoid-key.pem"), geo = F.signer(geoKeyFile);
  // two responsible bodies sign the member list (k = 2)
  const au = { ministry: crypto.generateKeyPairSync("ed25519"), prefecture: crypto.generateKeyPairSync("ed25519") };
  const raw = (kp) => b64(kp.publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const sign = (who, e) => ({ by: who, sig: b64(crypto.sign(null, Buffer.from(F.entryText(e)), au[who].privateKey)) });
  const entry = (org, url, key, max_level, publish_only, by) => { const e = { org, url, key, max_level, publish_only }; e.sigs = by.map((w) => sign(w, e)); return e; };
  const members = { k: 2, authorities: [{ id: "ministry", key: raw(au.ministry) }, { id: "prefecture", key: raw(au.prefecture) }], entries: [
    entry("ministry.example", A.url, A.key, 5, false, ["ministry", "prefecture"]),
    entry("city.example", B.url, B.key, 3, false, ["ministry", "prefecture"]),
    entry("geoid.example", "https://geoid.example", geo.pub, 1, true, ["ministry", "prefecture"]),
    entry("rogue.example", C.url, C.key, 5, false, ["ministry", "ministry"]),          // one authority, twice
  ] };
  for (const [org, r] of [["ministry.example", A], ["city.example", B], ["rogue.example", C]]) {
    const [s] = await j(r.url + "/fed/config", "POST", { org, url: r.url, max_level: 5, members }, ad); check(org + ": configured by its administrator", s === 200);
  }
  let [s0] = await j(B.url + "/fed/config", "POST", { org: "evil.example", url: "http://x" }); check("configuration refused without the administrator", s0 === 403);

  // people: alice at the ministry, bob at the city
  const alice = device("alice"), bob = device("bob");
  await j(A.url + "/keys/alice", "POST", alice.bundle()); await j(B.url + "/keys/bob", "POST", bob.bundle());
  await j(B.url + "/mailbox", "POST", { id: bob.intro.id, owner: sha(bob.intro.tok), uak: null });

  let r = await j(A.url + "/fed/keys/city.example/bob?by=alice");
  check("unsigned key lookup refused", r[0] === 403, r);
  r = await signed(alice, A.url, "GET", "/fed/keys/city.example/bob?by=alice");
  check("bob's keys reach alice through the two relays", r[0] === 200 && r[1].identity === bob.bundle().identity && r[1].org === "city.example", r);
  check("no phone or settings go to the other organization", r[1].findByPhone === undefined && r[1].phone === undefined, Object.keys(r[1]));
  const b = r[1];
  await S.processPreKeyBundle(S.PreKeyBundle.new(b.regId, 1, b.preKey.id, S.PublicKey.deserialize(ub(b.preKey.pub)), b.signed.id,
    S.PublicKey.deserialize(ub(b.signed.pub)), ub(b.signed.sig), S.PublicKey.deserialize(ub(b.identity)), b.kyber.id,
    S.KEMPublicKey.deserialize(ub(b.kyber.pub)), ub(b.kyber.sig)), bob.addr, alice.addr, alice.sess, alice.ident);
  const [, cr] = await j(A.url + "/cert", "POST", { acc: "alice", identity: b64(alice.st.idkp.publicKey.serialize()) });
  const sealed = async (text) => b64(await S.sealedSenderEncryptMessage(Buffer.from(text), bob.addr, S.SenderCertificate.deserialize(ub(cr.cert)), alice.sess, alice.ident));
  const env = await sealed("Evacuation centre at the north school is open.");

  r = await j(A.url + "/fed/send", "POST", { by: "alice", to_org: "city.example", mbx: bob.intro.id, body: env, level: 3 });
  check("unsigned send refused", r[0] === 403, r);
  r = await signed(alice, A.url, "POST", "/fed/send", { by: "alice", to_org: "city.example", mbx: bob.intro.id, body: env, level: 3 });
  check("L3 message from the ministry delivered at the city", r[0] === 200 && r[1].ok, r);
  r = await signed(alice, A.url, "POST", "/fed/send", { by: "alice", to_org: "city.example", mbx: bob.intro.id, body: env, level: 4 });
  check("L4 to the city (listed up to L3) refused", r[0] === 403 && /level/.test(r[1].error), r);
  r = await signed(alice, A.url, "POST", "/fed/send", { by: "alice", to_org: "rogue.example", mbx: bob.intro.id, body: env, level: 1 });
  check("to an organization signed by one authority only: refused", r[0] === 403 && /unlisted/.test(r[1].error), r);

  const [, trust] = await j(B.url + "/fed/trust");
  check("the city's relay knows the ministry's sealed-sender trust root, and not the rogue's", !!trust["ministry.example"] && !trust["rogue.example"], trust);
  const [, got] = await j(B.url + "/collect/" + bob.intro.id, "GET", undefined, { "X-Owner": bob.intro.tok });
  check("one envelope waiting for bob", got.length === 1, got.length);
  const out = await S.sealedSenderDecryptMessage(ub(got[0].body), S.PublicKey.deserialize(ub(trust["ministry.example"])), Date.now(), null, "bob", 1,
    bob.sess, bob.ident, bob.pks, bob.spks, bob.kpks);
  check("bob reads it, end to end, and it is from alice", Buffer.from(out.message()).toString() === "Evacuation centre at the north school is open." && out.senderUuid() === "alice");
  const audB = fs.readFileSync(path.join(B.HOME, ".local/share/zenos/audit.log"), "utf8");
  check("the city's audit log names the ministry's relay, not alice", /fed-delivered.*ministry\.example/.test(audB) && !/alice/.test(audB));

  // requests made by hand, as another relay would
  const me = (org, keyFile) => ({ org, sign: F.signer(keyFile).sign });
  const cKey = path.join(C.HOME, ".local/share/zenos/msg/relay/relay-key.pem"), aKey = path.join(A.HOME, ".local/share/zenos/msg/relay/relay-key.pem");
  r = await F.relayRequest(me("rogue.example", cKey), B.url, "POST", "/fed/deliver", { mbx: bob.intro.id, body: env, level: 1 });
  check("delivery from the rogue relay refused (no valid entry, so no key to check it against)", r.status === 403 && /signature|unlisted/.test(r.body.error), r);
  r = await F.relayRequest(me("ministry.example", cKey), B.url, "POST", "/fed/deliver", { mbx: bob.intro.id, body: env, level: 1 });
  check("a relay claiming to be the ministry with another key: refused (signature)", r.status === 403 && /signature/.test(r.body.error), r);
  const p = "/fed/deliver", rawB = JSON.stringify({ mbx: bob.intro.id, body: await sealed("second"), level: 1 }), ts = String(Date.now());
  const hdr = { "X-Zenos-Relay": `ministry.example ${ts} ${F.signer(aKey).sign(F.reqText("POST", p, ts, rawB))}` };
  r = await j(B.url + p, "POST", rawB, hdr); check("signed request from the ministry's relay accepted", r[0] === 200, r);
  r = await j(B.url + p, "POST", rawB, hdr); check("the same request again: refused (replay)", r[0] === 403 && /replay/.test(r[1].error), r);
  r = await j(B.url + p, "POST", rawB.replace("\"level\":1", "\"level\":2"), hdr); check("body changed under the signature: refused", r[0] === 403, r);

  // disaster alerts from the publish-only member
  const alert = { id: "jma-2026-11-01-0001", kind: "heavy-rain", severity: "severe", label: "official", issuer: "Japan Meteorological Agency",
    headline: "Heavy rain warning", sent: new Date().toISOString(), expires: new Date(Date.now() + 6 * 3600e3).toISOString(),
    area: { polygons: [[[37.40, 139.90], [37.40, 140.00], [37.50, 140.00], [37.50, 139.90]]], codes: ["072028"] },
    source_url: "https://www.jma.go.jp/bosai/warning/", source_sha256: sha("source document") };
  const pub = await F.publishAlert({ org: "geoid.example", keyFile: geoKeyFile, members, alert });
  check("GEOID's alert reaches the ministry and the city, not the unlisted relay", pub.length === 3 && pub.filter((x) => x.status === 200).map((x) => x.org).sort().join() === "city.example,ministry.example", pub);
  r = await F.relayRequest({ org: "geoid.example", sign: geo.sign }, B.url, "POST", "/fed/alert", { ...alert, id: "bad-source-1", source_sha256: "x" });
  check("an alert without the source's digest is refused", r.status === 400, r);
  r = await F.relayRequest({ org: "geoid.example", sign: geo.sign }, B.url, "POST", "/fed/deliver", { mbx: bob.intro.id, body: env, level: 1 });
  check("the publish-only member cannot send messages", r.status === 403 && /publish-only/.test(r.body.error), r);
  const [, al] = await j(B.url + "/alerts");
  check("the city's devices see the alert, with its label and source", al.length === 1 && al[0].label === "official" && al[0].from === "geoid.example" && !al[0].answers, al);
  const k = encodeURIComponent("geoid.example") + "/" + encodeURIComponent(alert.id);
  const carol = device("carol"); await j(B.url + "/keys/carol", "POST", carol.bundle());
  const ans = (dev, status) => signed(dev, B.url, "POST", `/alerts/${k}/answer`, { by: dev.acc, status });
  await ans(bob, "help");
  await ans(bob, "safe");                                                                          // the same person changes their answer
  await ans(carol, "safe");
  r = await j(`${B.url}/alerts/${k}/answer`, "POST", { status: "help", token: crypto.randomBytes(16).toString("hex") });
  check("an unsigned answer is refused (the counts cannot be stuffed)", r[0] === 403, r);
  r = await j(`${B.url}/alerts/${k}/counts`);
  check("answers counted once per registered person", r[1].safe === 2 && r[1].help === 0, r);
  r = await F.relayRequest(me("ministry.example", aKey), B.url, "GET", `/fed/counts/${k}`);
  check("the ministry gets the city's counts only", r.status === 200 && r.body.safe === 2 && Object.keys(r.body).sort().join() === "help,org,safe", r);
  r = await F.relayRequest(me("rogue.example", cKey), B.url, "GET", `/fed/counts/${k}`);
  check("the rogue relay gets no counts", r.status === 403, r);
  finish(fail ? 1 : 0);
})().catch((e) => { console.error(e); finish(1); });

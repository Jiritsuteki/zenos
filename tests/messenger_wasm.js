// libsignal compiled for the browser (messenger/wasm) talks to the PC's libsignal (Node) through the real relay:
// a sealed-sender message each way, end to end, with Signal's own code on both sides (the same version, v0.105.1).
//   cd messenger/wasm && wasm-pack build --release --target nodejs     then     node tests/messenger_wasm.js
const path = require("path"), os = require("os"), fs = require("fs"), crypto = require("crypto"), { spawn } = require("child_process");
const MSG = path.join(__dirname, "..", "messenger");
const S = require(require.resolve("@signalapp/libsignal-client", { paths: [MSG] }));
const W = require(path.join(MSG, "wasm", "pkg", "zenos_signal_wasm.js"));
const b64 = (u) => Buffer.from(u).toString("base64"), ub = (s) => Buffer.from(s, "base64");
const sha = (x) => crypto.createHash("sha256").update(String(x)).digest("hex");
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "zwasm-")), PORT = 19800 + Math.floor(Math.random() * 300), R = `http://127.0.0.1:${PORT}`;
const relay = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME, ZENOS_RELAY_PORT: String(PORT) }, stdio: "ignore" });
const finish = (c) => { relay.kill(); fs.rmSync(HOME, { recursive: true, force: true }); process.exit(c); };
let fail = 0; const check = (n, c, g) => { console.log((c ? "ok   " : "FAIL ") + n, c ? "" : JSON.stringify(g)); if (!c) fail++; };
const j = async (p, method = "GET", obj, h = {}) => { const r = await fetch(R + p, { method, headers: { "Content-Type": "application/json", ...h }, body: obj === undefined ? undefined : JSON.stringify(obj) }); return r.json(); };
(async () => {
  for (let i = 0; i < 60; i++) { try { await fetch(R + "/trust"); break; } catch { await new Promise((z) => setTimeout(z, 100)); } }
  const { trust } = await j("/trust");
  // the PC side: alice, with the Node libsignal the client uses
  const st = { idkp: S.IdentityKeyPair.generate(), sessions: {}, ids: {}, pre: {}, signed: {}, kyber: {} };
  const sess = new (class extends S.SessionStore { async saveSession(a, r) { st.sessions[a.toString()] = r.serialize(); }
    async getSession(a) { const x = st.sessions[a.toString()]; return x ? S.SessionRecord.deserialize(x) : null; }
    async getExistingSessions(as) { return (await Promise.all(as.map((a) => this.getSession(a)))).filter(Boolean); } })();
  const ident = new (class extends S.IdentityKeyStore { async getIdentityKey() { return st.idkp.privateKey; } async getLocalRegistrationId() { return 4242; }
    async saveIdentity(a, k) { st.ids[a.name()] = k; return S.IdentityChange.NewOrUnchanged; } async isTrustedIdentity() { return true; } async getIdentity(a) { return st.ids[a.name()] || null; } })();
  const pks = new (class extends S.PreKeyStore { async savePreKey(i, r) { st.pre[i] = r; } async getPreKey(i) { return st.pre[i]; } async removePreKey(i) { delete st.pre[i]; } })();
  const spks = new (class extends S.SignedPreKeyStore { async saveSignedPreKey(i, r) { st.signed[i] = r; } async getSignedPreKey(i) { return st.signed[i]; } })();
  const kpks = new (class extends S.KyberPreKeyStore { async saveKyberPreKey(i, r) { st.kyber[i] = r; } async getKyberPreKey(i) { return st.kyber[i]; } async markKyberPreKeyUsed() {} })();
  const sk = S.PrivateKey.generate(), srec = S.SignedPreKeyRecord.new(1, Date.now(), sk.getPublicKey(), sk, st.idkp.privateKey.sign(sk.getPublicKey().serialize()));
  const kk = S.KEMKeyPair.generate(), krec = S.KyberPreKeyRecord.new(1, Date.now(), kk, st.idkp.privateKey.sign(kk.getPublicKey().serialize()));
  st.signed[1] = srec; st.kyber[1] = krec;
  const aIntro = { id: crypto.randomBytes(16).toString("hex"), tok: crypto.randomBytes(32).toString("hex") };
  await j("/keys/alice", "POST", { name: "alice", level: 2, regId: 4242, intro: aIntro.id, identity: b64(st.idkp.publicKey.serialize()),
    signed: { id: 1, pub: b64(srec.publicKey().serialize()), sig: b64(srec.signature()) }, kyber: { id: 1, pub: b64(krec.publicKey().serialize()), sig: b64(krec.signature()) }, preKeys: [] });
  await j("/mailbox", "POST", { id: aIntro.id, owner: sha(aIntro.tok), uak: null });

  // the browser side: bob, with libsignal compiled to WebAssembly
  const t0 = Date.now(); const bob = new W.Device("bob", 777, 3, Date.now());
  check("the WebAssembly device makes its keys (" + (Date.now() - t0) + " ms)", true);
  const bIntro = { id: crypto.randomBytes(16).toString("hex"), tok: crypto.randomBytes(32).toString("hex") };
  let r = await j("/keys/bob", "POST", { ...JSON.parse(bob.bundle()), name: "bob", level: 2, intro: bIntro.id });
  check("its bundle is accepted by the relay as it is", r.ok, r);
  await j("/mailbox", "POST", { id: bIntro.id, owner: sha(bIntro.tok), uak: null });

  // PC -> browser
  const b = await j("/keys/bob");
  await S.processPreKeyBundle(S.PreKeyBundle.new(b.regId, 1, b.preKey.id, S.PublicKey.deserialize(ub(b.preKey.pub)), b.signed.id, S.PublicKey.deserialize(ub(b.signed.pub)),
    ub(b.signed.sig), S.PublicKey.deserialize(ub(b.identity)), b.kyber.id, S.KEMPublicKey.deserialize(ub(b.kyber.pub)), ub(b.kyber.sig)),
    S.ProtocolAddress.new("bob", 1), S.ProtocolAddress.new("alice", 1), sess, ident);
  check("the PC's libsignal accepts the WebAssembly device's bundle (signatures, PQXDH)", true);
  const ac = await j("/cert", "POST", { acc: "alice", identity: b64(st.idkp.publicKey.serialize()) });
  const env = await S.sealedSenderEncryptMessage(Buffer.from("Shelter list attached in the next message."), S.ProtocolAddress.new("bob", 1), S.SenderCertificate.deserialize(ub(ac.cert)), sess, ident);
  await j("/deliver", "POST", { mbx: bIntro.id, uak: null, body: b64(env) });
  let q = await j("/collect/" + bIntro.id, "GET", undefined, { "X-Owner": bIntro.tok });
  const got = JSON.parse(bob.open(trust, q[0].body, Date.now()));
  check("the browser device opens the PC's sealed message", got.sender === "alice" && got.text === "Shelter list attached in the next message.", got);
  check("a wrong trust root is refused", (() => { try { bob.open(b64(S.PrivateKey.generate().getPublicKey().serialize()), q[0].body, Date.now()); return false; } catch { return true; } })());

  // browser -> PC, on the session the first message made
  const p = "/cert", raw = JSON.stringify({ acc: "bob", identity: JSON.parse(bob.bundle()).identity }), ts = String(Date.now());
  const bc = await j(p, "POST", JSON.parse(raw));
  check("the relay issues the browser device a sender certificate", !!bc.cert, bc);
  const back = bob.seal("alice", bc.cert, "Received. 3 shelters open.", Date.now());
  await j("/deliver", "POST", { mbx: aIntro.id, uak: null, body: back });
  q = await j("/collect/" + aIntro.id, "GET", undefined, { "X-Owner": aIntro.tok });
  const out = await S.sealedSenderDecryptMessage(ub(q[0].body), S.PublicKey.deserialize(ub(trust)), Date.now(), null, "alice", 1, sess, ident, pks, spks, kpks);
  check("the PC opens the browser device's reply, from bob", Buffer.from(out.message()).toString() === "Received. 3 shelters open." && out.senderUuid() === "bob");
  // the device's keys and sessions survive an export and a restore (what the page keeps, encrypted, between visits)
  const bob2 = W.Device.restore(bob.export());
  check("the restored device has the same identity", JSON.parse(bob2.bundle()).identity === JSON.parse(bob.bundle()).identity);
  const env2 = await S.sealedSenderEncryptMessage(Buffer.from("One more after the restore."), S.ProtocolAddress.new("bob", 1), S.SenderCertificate.deserialize(ub(ac.cert)), sess, ident);
  const got2 = JSON.parse(bob2.open(trust, b64(env2), Date.now()));
  check("the restored device opens the PC's next message on the same session", got2.sender === "alice" && got2.text === "One more after the restore.", got2);
  const back2 = bob2.seal("alice", bc.cert, "Still here.", Date.now());
  const out2 = await S.sealedSenderDecryptMessage(ub(back2), S.PublicKey.deserialize(ub(trust)), Date.now(), null, "alice", 1, sess, ident, pks, spks, kpks);
  check("and the PC opens its reply", Buffer.from(out2.message()).toString() === "Still here.");
  check("a broken saved state is refused", (() => { try { W.Device.restore("{}"); return false; } catch { return true; } })());
  // the device's signature is what the relay checks for account requests
  const pth = "/channels?member=bob", ts2 = String(Date.now());
  const ch = await fetch(R + pth, { headers: { "X-Zenos-Auth": `bob ${ts2} ${bob.sign(`GET ${pth} ${ts2} ${sha("")}`)}` } });
  check("the relay accepts a request signed by the browser device", ch.status === 200, ch.status);
  finish(fail ? 1 : 0);
})().catch((e) => { console.error(e); finish(1); });

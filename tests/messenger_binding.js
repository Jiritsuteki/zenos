// Messenger device binding: the first key registered for an account wins; a new device takes the account over only
// by verifying the number already registered to it; unsigned, foreign-key and replayed requests are refused.
//   node tests/messenger_binding.js      (needs messenger/node_modules: cd messenger && npm ci)
const path = require("path"), os = require("os"), { spawn } = require("child_process");
const MSG = path.join(__dirname, "..", "messenger");
const S = (() => { try { return require(require.resolve("@signalapp/libsignal-client", { paths: [MSG] })); } catch { return require("@signalapp/libsignal-client"); } })();
const crypto = require("crypto"), fs = require("fs");
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "zbind-")), PORT = 18300 + Math.floor(Math.random() * 500);
const R = `http://127.0.0.1:${PORT}`, OUT = path.join(HOME, ".local/share/zenos/msg/relay/sms-outbox.log");
const relay = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(PORT) }, stdio: "ignore" });
const ready = async () => { for (let i = 0; i < 50; i++) { try { await fetch(R + "/trust"); return; } catch { await new Promise((r) => setTimeout(r, 100)); } } throw new Error("relay did not start"); };
const finish = (code) => { relay.kill(); fs.rmSync(HOME, { recursive: true, force: true }); process.exit(code); };
const sha = (x) => crypto.createHash("sha256").update(String(x)).digest("hex");
const b64 = (u) => Buffer.from(u).toString("base64");
async function rq(key, acc, method, p, obj) {
  const raw = obj ? JSON.stringify(obj) : ""; const h = { "Content-Type": "application/json" };
  if (key) { const ts = String(Date.now()); h["X-Zenos-Auth"] = `${acc} ${ts} ${b64(key.privateKey.sign(Buffer.from(`${method} ${p} ${ts} ${sha(raw)}`)))}`; }
  const r = await fetch(R + p, { method, headers: h, body: raw || undefined }); return [r.status, await r.json()];
}
const lastCode = () => fs.readFileSync(OUT, "utf8").trim().split("\n").pop().match(/code: (\d{6})/)[1];
let fail = 0; const check = (name, cond, got) => { console.log((cond ? "ok   " : "FAIL ") + name, cond ? "" : JSON.stringify(got)); if (!cond) fail++; };
(async () => {
  await ready();
  const A = S.IdentityKeyPair.generate(), B = S.IdentityKeyPair.generate(), acc = "acme", phone = "+15555550142";
  const bundle = (k, name) => ({ name, identity: b64(k.publicKey.serialize()) });
  let r = await rq(null, acc, "POST", `/keys/${acc}`, bundle(A, "Acme A")); check("first device registers", r[0] === 200, r);
  r = await rq(null, acc, "POST", `/keys/${acc}`, bundle(B, "evil")); check("second key refused", r[0] === 409, r);
  r = await rq(A, acc, "POST", "/register/start", { phone, id: acc }); check("device A starts number", r[0] === 200, r);
  r = await rq(A, acc, "POST", "/register/verify", { phone, id: acc, code: lastCode() }); check("device A verifies number", r[1].ok && !r[1].rebind, r);
  r = await rq(null, acc, "POST", "/register/start", { phone: "+15555550199", id: acc }); check("other number refused for unsigned", r[0] === 403, r);
  r = await rq(B, acc, "POST", "/register/start", { phone, id: acc }); check("new device: code to the account's number", r[0] === 200, r);
  r = await rq(B, acc, "POST", "/register/verify", { phone, id: acc, code: lastCode() }); check("new device verified -> rebind", r[1].ok && r[1].rebind, r);
  r = await rq(B, acc, "POST", `/keys/${acc}`, bundle(B, "Acme B")); check("new device publishes its key", r[0] === 200, r);
  r = await rq(A, acc, "GET", `/phone/${acc}`); check("old device now refused", r[0] === 403, r);
  r = await rq(B, acc, "GET", `/phone/${acc}`); check("new device accepted", r[0] === 200 && r[1].phone === phone, r);
  const ts = String(Date.now()), sig = b64(B.privateKey.sign(Buffer.from(`GET /phone/${acc} ${ts} ${sha("")}`)));
  const once = async () => (await fetch(R + `/phone/${acc}`, { headers: { "X-Zenos-Auth": `${acc} ${ts} ${sig}` } })).status;
  const s1 = await once(), s2 = await once(); check("replayed request refused", s1 === 200 && s2 === 403, [s1, s2]);
  r = await rq(null, acc, "POST", `/keys/${acc}`, bundle(A, "back")); check("old key cannot come back", r[0] === 409, r);
  // the relay keeps running on a broken or oversized body, and does not take a bundle's word for its clearance
  const rawPost = async (p, raw) => { const x = await fetch(R + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: raw }); return x.status; };
  check("a body that is not JSON is refused, and the relay keeps running", (await rawPost("/deliver", "{not json")) === 400 && (await fetch(R + "/trust")).ok);
  check("a body over 1 MiB is refused", (await rawPost("/deliver", "x".repeat((1 << 20) + 10))) === 413 && (await fetch(R + "/trust")).ok);
  const M = S.IdentityKeyPair.generate();
  r = await rq(null, "mallory", "POST", "/keys/mallory", { name: "Director", level: 5, org: "ZENOS Gov", identity: b64(M.publicKey.serialize()) });
  const listed = (await (await fetch(R + "/accounts")).json()).find((a) => a.id === "mallory");
  check("an unlisted account is L1 with no organization, whatever it claims", r[0] === 200 && listed.level === 1 && listed.org === "" && listed.name === "Director", listed);
  const T = S.IdentityKeyPair.generate(); await rq(null, "tanaka", "POST", "/keys/tanaka", { name: "x", level: 1, identity: b64(T.publicKey.serialize()) });
  const tk = (await (await fetch(R + "/accounts")).json()).find((a) => a.id === "tanaka");
  check("a listed account gets the directory's clearance and organization", tk.level === 5 && tk.org === "ZENOS Gov", tk);
  r = await rq(M, "mallory", "POST", "/channels", { id: "secret-room", name: "#x", level: 3, members: ["mallory", "tanaka"], by: "mallory" });
  check("a channel above the creator's clearance is refused", r[0] === 403, r);
  r = await rq(M, "mallory", "POST", "/channels", { id: "open-room", name: "#x", level: 1, members: ["mallory", "tanaka"], by: "mallory" });
  const [, chs] = await rq(T, "tanaka", "GET", "/channels?member=tanaka");
  check("a new channel holds only its creator; others come in through invite", r[0] === 200 && !chs.some((c) => c.id === "open-room"), chs);
  // a relay that registers new accounts only with an administrator's enrollment code
  const port2 = PORT + 1, R2 = `http://127.0.0.1:${port2}`, HOME2 = fs.mkdtempSync(path.join(os.tmpdir(), "zbind-"));
  const relay2 = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME: HOME2, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(port2), ZENOS_RELAY_ENROLL: "1" }, stdio: "ignore" });
  for (let i = 0; i < 50; i++) { try { await fetch(R2 + "/trust"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  const post = async (p, obj, hdr) => { const r = await fetch(R2 + p, { method: "POST", headers: { "Content-Type": "application/json", ...(hdr || {}) }, body: JSON.stringify(obj) }); return [r.status, await r.json()]; };
  const admin = fs.readFileSync(path.join(HOME2, ".local/share/zenos/msg/relay/admin.token"), "utf8").trim();
  const C = S.IdentityKeyPair.generate(), cb = { name: "New", identity: b64(C.publicKey.serialize()) };
  r = await post("/keys/newbie", cb); check("enrolling relay: no code, refused", r[0] === 403, r);
  r = await post("/enroll", { account: "newbie" }); check("code not issued without admin token", r[0] === 403, r);
  r = await post("/enroll", { account: "newbie" }, { "X-Zenos-Admin": admin }); const code = r[1].code; check("admin issues a code", r[0] === 200 && !!code, r);
  r = await post("/keys/newbie", { ...cb, enroll: "0000000000" }); check("wrong code refused", r[0] === 403, r);
  r = await post("/keys/other", { ...cb, enroll: code }); check("code only for its account", r[0] === 403, r);
  r = await post("/keys/newbie", { ...cb, enroll: code }); check("right code registers", r[0] === 200, r);
  const kept = JSON.parse(fs.readFileSync(path.join(HOME2, ".local/share/zenos/msg/relay/bundles.json"), "utf8")).newbie;
  check("code is not stored with the bundle", kept && kept.enroll === undefined, kept);
  relay2.kill(); fs.rmSync(HOME2, { recursive: true, force: true });
  console.log(fail ? `${fail} FAILED` : "ALL OK"); finish(fail ? 1 : 0);
})().catch((e) => { console.error(e); finish(2); });

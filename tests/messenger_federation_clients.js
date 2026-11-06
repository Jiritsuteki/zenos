// Two ZENOS Messages clients at two organizations (client.js, unchanged UI): a message to "account@organization"
// goes through both relays and comes back as a reply, end to end (Signal protocol, sealed sender). A file crosses
// too (the ciphertext fetched from the sender's relay, the key only in the sealed message), and a room with people
// at both organizations carries messages and files both ways.
//   node tests/messenger_federation_clients.js   (needs messenger/node_modules and zenos-decide built)
const path = require("path"), os = require("os"), fs = require("fs"), crypto = require("crypto"), { spawn } = require("child_process");
const MSG = path.join(__dirname, "..", "messenger");
const F = require(path.join(MSG, "federation.js"));
const b64 = (u) => Buffer.from(u).toString("base64");
const ADMIN = crypto.randomBytes(12).toString("hex"), base = 19400 + Math.floor(Math.random() * 300);
const procs = [], homes = [];
const home = () => { const h = fs.mkdtempSync(path.join(os.tmpdir(), "zfedc-")); homes.push(h); return h; };
const run = (args, env) => { const p = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: "ignore" }); procs.push(p); return p; };
const finish = (code) => { for (const p of procs) p.kill(); for (const h of homes) fs.rmSync(h, { recursive: true, force: true }); process.exit(code); };
let fail = 0; const check = (n, c, g) => { console.log((c ? "ok   " : "FAIL ") + n, c ? "" : JSON.stringify(g)); if (!c) fail++; };
const j = async (url, method = "GET", obj, h = {}) => { const r = await fetch(url, { method, headers: { "Content-Type": "application/json", ...h }, body: obj ? JSON.stringify(obj) : undefined }); return r.json(); };
const wait = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { try { const v = await f(); if (v) return v; } catch {} await new Promise((z) => setTimeout(z, 250)); } return null; };
(async () => {
  const A = { url: `http://127.0.0.1:${base}`, HOME: home() }, B = { url: `http://127.0.0.1:${base + 1}`, HOME: home() };
  run([path.join(MSG, "relay.js")], { HOME: A.HOME, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(base), ZENOS_RELAY_ADMIN: ADMIN });
  run([path.join(MSG, "relay.js")], { HOME: B.HOME, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(base + 1), ZENOS_RELAY_ADMIN: ADMIN });
  for (const r of [A, B]) r.key = (await wait(() => j(r.url + "/.well-known/zenos-relay"))).key;
  const au = { ministry: crypto.generateKeyPairSync("ed25519"), prefecture: crypto.generateKeyPairSync("ed25519") };
  const raw = (kp) => b64(kp.publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const entry = (org, url, key, max_level) => { const e = { org, url, key, max_level, publish_only: false };
    e.sigs = Object.keys(au).map((w) => ({ by: w, sig: b64(crypto.sign(null, Buffer.from(F.entryText(e)), au[w].privateKey)) })); return e; };
  const members = { k: 2, authorities: Object.keys(au).map((id) => ({ id, key: raw(au[id]) })),
    entries: [entry("ministry.example", A.url, A.key, 5), entry("city.example", B.url, B.key, 3)] };
  await j(A.url + "/fed/config", "POST", { org: "ministry.example", url: A.url, members }, { "X-Zenos-Admin": ADMIN });
  await j(B.url + "/fed/config", "POST", { org: "city.example", url: B.url, members }, { "X-Zenos-Admin": ADMIN });
  const za = `http://127.0.0.1:${base + 10}`, zb = `http://127.0.0.1:${base + 20}`, ha = home(), hb = home();
  run([path.join(MSG, "client.js"), "zenos", String(base + 10)], { HOME: ha, ZENOS_RELAY: A.url });
  run([path.join(MSG, "client.js"), "sato", String(base + 20)], { HOME: hb, ZENOS_RELAY: B.url });
  // the local port wants the key that only this account can read; the test reads it as the PC's own window would
  const keyOf = (h, a) => { try { return fs.readFileSync(path.join(h, ".local/share/zenos/msg/store", a, "local.key"), "utf8"); } catch { return ""; } };
  const plain = globalThis.fetch;
  globalThis.fetch = (url, o = {}) => { const k = url.startsWith(za) ? keyOf(ha, "zenos") : url.startsWith(zb) ? keyOf(hb, "sato") : "";
    return plain(url, k ? { ...o, headers: { ...(o.headers || {}), "X-Zenos-Local": k } } : o); };
  await wait(() => keyOf(ha, "zenos"));
  await wait(async () => (await plain(za + "/api/me")).status);              // the port is listening
  check("the local port refuses a request without the key", (await plain(za + "/api/me")).status === 401);
  check("the local port refuses another site's page", (await fetch(za + "/api/send", { method: "POST", headers: { Origin: "http://evil.example" }, body: "{}" })).status === 403);
  check("the local port refuses another host name (DNS rebinding)", await new Promise((ok) => require("http").get({ host: "127.0.0.1", port: base + 10, path: "/api/me", headers: { Host: "evil.example:" + (base + 10), "X-Zenos-Local": keyOf(ha, "zenos") } }, (r) => ok(r.statusCode === 403)).on("error", () => ok(false))));
  // a linked phone that is not government-issued gets no drafts (they hold text typed in L3+ conversations)
  fs.writeFileSync(path.join(ha, ".local/share/zenos/msg/tunnel-url.zenos"), "https://phone.example");
  await fetch(za + "/api/local", { method: "POST", body: JSON.stringify({ drafts: { "c:secret-l4": "L4 draft text" } }) });
  const lk = await (await fetch(za + "/api/link/new", { method: "POST", body: "{}" })).json();
  const rp = `http://127.0.0.1:${base + 110}`;
  const lr = await plain(rp + "/link?t=" + new URL(lk.url).searchParams.get("t"), { redirect: "manual" });
  const sid = (lr.headers.get("set-cookie") || "").split(";")[0];
  const phoneLocal = await (await plain(rp + "/api/local", { headers: { Cookie: sid } })).text();
  check("a phone that is not government-issued cannot read drafts", sid.startsWith("zsid=") && !phoneLocal.includes("L4 draft"), phoneLocal);
  await plain(rp + "/api/local", { method: "POST", headers: { Cookie: sid }, body: JSON.stringify({ drafts: { "c:x": "from phone" }, dnd: true }) });
  const deskLocal = await (await fetch(za + "/api/local")).json();
  check("nor change them", deskLocal.drafts["c:secret-l4"] === "L4 draft text" && !deskLocal.drafts["c:x"] && !deskLocal.dnd, deskLocal);
  check("the key file is readable by this account only", (fs.statSync(path.join(ha, ".local/share/zenos/msg/store/zenos/local.key")).mode & 0o077) === 0);
  check("both clients start on their own organization's relay", !!(await wait(() => j(za + "/api/me"))) && !!(await wait(() => j(zb + "/api/me"))));
  await new Promise((z) => setTimeout(z, 1500));
  let r = await j(za + "/api/send", "POST", { to: "sato@city.example", text: "Please confirm the shelter list.", level: 2 });
  check("zenos at the ministry sends to sato@city.example", r.ok, r);
  const got = await wait(async () => (await j(zb + "/api/all")).find((m) => m.dir === "in" && m.from === "zenos@ministry.example"));
  check("sato reads it, from zenos@ministry.example", got && got.text === "Please confirm the shelter list.", got);
  r = await j(zb + "/api/send", "POST", { to: "zenos@ministry.example", text: "Confirmed, 3 shelters open.", level: 2 });
  check("sato replies", r.ok, r);
  const back = await wait(async () => (await j(za + "/api/all")).find((m) => m.dir === "in" && m.from === "sato@city.example"));
  check("zenos reads the reply, from sato@city.example", back && back.text === "Confirmed, 3 shelters open.", back);
  // a file across organizations
  const fileText = "School,Beds\nNorth,120\nSouth,80\n";
  r = await (await fetch(za + "/api/attach?to=sato@city.example&level=2&name=shelters.csv&mime=text/csv&text=" + encodeURIComponent("The list."), { method: "POST", body: fileText })).json();
  check("zenos sends a file to sato@city.example", r.ok, r);
  const fm = await wait(async () => (await j(zb + "/api/all")).find((m) => m.dir === "in" && m.att && m.att.name === "shelters.csv"));
  check("sato receives it, opened and checked (fingerprint)", fm && !fm.att.error && fm.att.size === fileText.length, fm);
  const fbody = fm ? await (await fetch(zb + "/api/att/" + fm.att.sha256 + "?dl")).text() : "";
  check("the file is what zenos sent", fbody === fileText, fbody);
  // a room with people at both organizations
  r = await j(za + "/api/rooms", "POST", { name: "Shelters (ministry + city)", members: ["sato@city.example"], level: 2 });
  check("zenos makes a room with sato@city.example", r.ok && /^room-/.test(r.room.id), r);
  const room = r.ok ? r.room.id : "";
  const rc = await wait(async () => (await j(zb + "/api/channels")).find((c) => c.id === room));
  check("the room appears at the city, with both members", rc && rc.members.includes("zenos@ministry.example") && rc.members.includes("sato@city.example"), rc);
  r = await j(za + "/api/channel-send", "POST", { ch: room, text: "Shelter 4 opens at 18:00.", level: 2 });
  check("zenos writes in the room", r.ok, r);
  const rm = await wait(async () => (await j(zb + "/api/channel-messages?ch=" + room)).find((m) => m.dir === "in" && m.text === "Shelter 4 opens at 18:00."));
  check("sato reads it in the room", rm && rm.from === "zenos@ministry.example", rm);
  r = await j(zb + "/api/channel-send", "POST", { ch: room, text: "Noted, staff on the way.", level: 2 });
  check("sato answers in the room", r.ok, r);
  const rb = await wait(async () => (await j(za + "/api/channel-messages?ch=" + room)).find((m) => m.dir === "in" && m.text === "Noted, staff on the way."));
  check("zenos reads the answer in the same room", rb && rb.from === "sato@city.example", rb);
  r = await (await fetch(zb + "/api/attach?ch=" + room + "&level=1&name=photo.txt&mime=text/plain", { method: "POST", body: "a file into the room" })).json();
  check("sato sends a file into the room", r.ok, r);
  const ra = await wait(async () => (await j(za + "/api/channel-messages?ch=" + room)).find((m) => m.dir === "in" && m.att && m.att.name === "photo.txt"));
  check("zenos receives the room's file from the city", ra && !ra.att.error, ra);
  // the ministry's relay gives a file's ciphertext only to a listed relay, within the level the sender gave it
  const up = async (lv) => (await (await fetch(A.url + "/blobs?level=" + lv, { method: "POST", body: "ciphertext" })).json()).id;
  const cityRelay = { org: "city.example", sign: F.signer(path.join(B.HOME, ".local/share/zenos/msg/relay/relay-key.pem")).sign };
  const asCity = async (id) => (await fetch(A.url + "/fed/blobs/" + id, { headers: (() => { const ts = String(Date.now()), p = "/fed/blobs/" + id;
    return { "X-Zenos-Relay": `city.example ${ts} ${cityRelay.sign(F.reqText("GET", p, ts, ""))}` }; })() })).status;
  check("an unsigned request for a file is refused", (await fetch(A.url + "/fed/blobs/" + (await up(1)))).status === 403);
  check("the city's relay gets an L2 file", (await asCity(await up(2))) === 200);
  check("the city's relay (listed up to L3) does not get an L4 file", (await asCity(await up(4))) === 403);
  r = await j(za + "/api/channel-send", "POST", { ch: room, text: "x", level: 3 });
  check("an L3 message in an L2 room is refused", !!r.error && /L2/.test(r.error), r);
  r = await j(za + "/api/send", "POST", { to: "sato@city.example", text: "x", level: 4 });
  check("L4 to the city (listed up to L3) refused", !!r.error && /level/.test(r.error), r);
  r = await j(za + "/api/send", "POST", { to: "someone@unlisted.example", text: "x", level: 1 });
  check("an unlisted organization is refused", !!r.error && /unlisted/.test(r.error), r);
  finish(fail ? 1 : 0);
})().catch((e) => { console.error(e); finish(1); });

// The same libsignal WebAssembly build in real browser engines (Chromium, WebKit as in Safari on iPhone, Firefox;
// headless, through Playwright): two devices
// in the page start a session from bundles, exchange sealed-sender messages both ways, and check the trust root.
// The sender certificates come from a real relay. Then the two guards for keys in a browser: the code is loaded only
// from a release signed by two release officers (zpin.js: one signature, a changed file and an older release are
// refused), and the device's keys are kept between visits only encrypted with the person's passphrase
// (zkeystore.js), and the sessions go on after they are restored.
// Build first: cd messenger/wasm && wasm-pack build --release --target web --out-dir pkg-web
//   node tests/messenger_wasm_browser.js
const path = require("path"), os = require("os"), fs = require("fs"), http = require("http"), { spawn } = require("child_process");
const pw = require("playwright"), ENGINE = process.env.ENGINE || "chromium";   // chromium, webkit (Safari's engine), firefox
const MSG = path.join(__dirname, "..", "messenger"), PKG = path.join(MSG, "wasm", "pkg-web"), WEB = path.join(MSG, "wasm", "web");
const SIGN = path.join(__dirname, "..", "tools", "sign_wasm_release.js"), { execFileSync } = require("child_process");
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "zwasmb-")), PORT = 20100 + Math.floor(Math.random() * 300), R = `http://127.0.0.1:${PORT}`;
const relay = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME, ZENOS_RELAY_DIRECTORY: path.join(__dirname, "fixtures", "msg-directory.json"), ZENOS_RELAY_PORT: String(PORT) }, stdio: "ignore" });
const types = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html", ".json": "application/json", ".sig": "application/json" };
// releases: two officers' keys, a third key nobody pinned; good (v2, two signatures), one (one signature), bad (a
// file changed after signing), old (v1, two signatures)
const REL = fs.mkdtempSync(path.join(os.tmpdir(), "zrel-")), key = (n) => execFileSync(process.execPath, [SIGN, "--new-key", path.join(REL, n + ".pem")]).toString().trim();
const KEYS = [key("officer1"), key("officer2")];
const rel = (name, version, signers, after) => {
  const d = path.join(REL, name); fs.mkdirSync(d);
  for (const f of fs.readdirSync(PKG)) if (/\.(js|wasm)$/.test(f)) fs.copyFileSync(path.join(PKG, f), path.join(d, f));
  execFileSync(process.execPath, [SIGN, d, String(version), ...signers.map((s) => path.join(REL, s + ".pem"))]);
  if (after) after(d);
};
rel("good", 2, ["officer1", "officer2"]);
rel("one", 3, ["officer1"]);
rel("bad", 3, ["officer1", "officer2"], (d) => fs.appendFileSync(path.join(d, "zenos_signal_wasm.js"), "\nfetch('https://example.invalid/'+1);\n"));
rel("old", 1, ["officer1", "officer2"]);
const page = `<!doctype html><meta charset="utf-8"><script type="module">import init, * as W from "/pkg/zenos_signal_wasm.js"; await init(); window.W = W; window.ready = true;</script>`;
const srv = http.createServer((q, r) => {
  if (q.url === "/") { r.writeHead(200, { "Content-Type": "text/html" }); return r.end(page); }
  const u = q.url.split("?")[0], parts = u.split("/").filter(Boolean);
  let f = null;
  if (parts[0] === "pkg" && parts.length === 2) f = path.join(PKG, parts[1]);
  else if (parts[0] === "web" && parts.length === 2) f = path.join(WEB, parts[1]);
  else if (parts[0] === "rel" && parts.length === 3 && /^[a-z]+$/.test(parts[1])) f = path.join(REL, parts[1], parts[2]);
  if (!f || f.endsWith(".pem") || !fs.existsSync(f)) { r.writeHead(404); return r.end(); }
  r.writeHead(200, { "Content-Type": types[path.extname(f)] || "application/octet-stream" }); r.end(fs.readFileSync(f));
}).listen(PORT + 1, "127.0.0.1");
let browser;
const finish = async (c) => { if (browser) await browser.close(); relay.kill(); srv.close(); fs.rmSync(HOME, { recursive: true, force: true }); fs.rmSync(REL, { recursive: true, force: true }); process.exit(c); };
let fail = 0; const check = (n, c, g) => { console.log((c ? "ok   " : "FAIL ") + n, c ? "" : JSON.stringify(g)); if (!c) fail++; };
const j = async (p, method = "GET", obj) => (await fetch(R + p, { method, headers: { "Content-Type": "application/json" }, body: obj && JSON.stringify(obj) })).json();
(async () => {
  for (let i = 0; i < 60; i++) { try { await fetch(R + "/trust"); break; } catch { await new Promise((z) => setTimeout(z, 100)); } }
  browser = await pw[ENGINE].launch();
  const ctx = await browser.newContext(), pg = await ctx.newPage();
  await pg.goto(`http://127.0.0.1:${PORT + 1}/`); await pg.waitForFunction(() => window.ready === true, null, { timeout: 30000 });
  check(`libsignal (WebAssembly) loads in ${ENGINE}`, true);
  const bundles = await pg.evaluate(() => { const n = Date.now(); window.a = new W.Device("alice", 11, 2, n); window.b = new W.Device("bob", 22, 2, n);
    return [a.bundle(), b.bundle()]; });
  const { trust } = await j("/trust");
  const certs = {};
  for (const [name, bj] of [["alice", bundles[0]], ["bob", bundles[1]]]) {
    await j("/keys/" + name, "POST", { ...JSON.parse(bj), name, level: 1 });
    certs[name] = (await j("/cert", "POST", { acc: name, identity: JSON.parse(bj).identity })).cert;
  }
  const bobBundle = JSON.stringify(await j("/keys/bob"));
  const res = await pg.evaluate(([bb, trust, certs]) => {
    const n = Date.now(); a.start_session("bob", bb, n);
    const m1 = JSON.parse(b.open(trust, a.seal("bob", certs.alice, "hello from the first browser device", n), n));
    const m2 = JSON.parse(a.open(trust, b.seal("alice", certs.bob, "and back", n), n));
    const m3 = JSON.parse(b.open(trust, a.seal("bob", certs.alice, "third, on the ratchet", n), n));
    let wrong = false; try { b.open(trust.replace(/^.{8}/, "BQAAAAAA"), a.seal("bob", certs.alice, "x", n), n); } catch { wrong = true; }
    return { m1, m2, m3, wrong };
  }, [bobBundle, trust, certs]);
  check("a sealed message from alice to bob, in the browser", res.m1.sender === "alice" && res.m1.text === "hello from the first browser device", res.m1);
  check("bob replies", res.m2.sender === "bob" && res.m2.text === "and back", res.m2);
  check("the ratchet goes on", res.m3.text === "third, on the ratchet", res.m3);
  check("a wrong trust root is refused in the browser", res.wrong);

  // the code: only from a release two release officers signed
  const pin = await pg.evaluate(async (KEYS) => {
    const Z = await import("/web/zpin.js"), out = {};
    const tryLoad = async (n) => { try { const { W, version } = await Z.loadSignal(`/rel/${n}/`, KEYS, 2); return { ok: true, version, works: !!new W.Device("x", 1, 1, Date.now()).bundle() }; } catch (e) { return { ok: false, err: String(e.message || e) }; } };
    out.none = await (async () => { try { await Z.loadSignal("/rel/good/", [], 2); return { ok: true }; } catch (e) { return { ok: false }; } })();
    out.one = await tryLoad("one"); out.bad = await tryLoad("bad"); out.good = await tryLoad("good"); out.old = await tryLoad("old");
    return out;
  }, KEYS);
  check("no pinned keys: nothing is loaded", !pin.none.ok, pin.none);
  check("a release signed by one officer is refused", !pin.one.ok && /1 of the 2/.test(pin.one.err), pin.one);
  check("a release whose file was changed after signing is refused", !pin.bad.ok && /not the file/.test(pin.bad.err), pin.bad);
  check("the release signed by two officers loads and works", pin.good.ok && pin.good.version === 2 && pin.good.works, pin.good);
  check("an older release after a newer one is refused (no rollback)", !pin.old.ok && /older/.test(pin.old.err), pin.old);

  // the keys: kept between visits only encrypted with the person's passphrase, and the sessions go on
  const ks = await pg.evaluate(async ([trust, certs]) => {
    const K = await import("/web/zkeystore.js"), n = Date.now(), out = {};
    const saved = a.export();
    out.hasPrivate = saved.length > 500;
    await K.save("alice", saved, "correct horse battery staple");
    try { await K.load("alice", "wrong passphrase!"); out.wrong = false; } catch { out.wrong = true; }
    try { await K.save("alice", saved, "short"); out.short = false; } catch { out.short = true; }
    const raw = await new Promise((ok) => { const r = indexedDB.open("zenos-keys", 1); r.onsuccess = () => { const g = r.result.transaction("kv").objectStore("kv").get("device:alice"); g.onsuccess = () => { ok(g.result); r.result.close(); }; }; });
    const asText = new TextDecoder("latin1").decode(raw.ct);
    out.encrypted = !asText.includes("identity") && !asText.includes(JSON.parse(saved).identity.slice(0, 24));
    const a2 = W.Device.restore(await K.load("alice", "correct horse battery staple"));
    const m4 = JSON.parse(a2.open(trust, b.seal("alice", certs.bob, "after the restore", n), n));
    const m5 = JSON.parse(b.open(trust, a2.seal("bob", certs.alice, "the restored device answers", n), n));
    out.m4 = m4; out.m5 = m5; out.same = JSON.parse(a2.bundle()).identity === JSON.parse(a.bundle()).identity;
    return out;
  }, [trust, certs]);
  check("the device's keys can be exported", ks.hasPrivate, ks);
  check("a wrong passphrase does not open the saved keys", ks.wrong, ks);
  check("a passphrase under 8 characters is refused", ks.short, ks);
  check("what the browser stores is ciphertext (no key in it)", ks.encrypted, ks);
  check("the restored device is the same identity", ks.same, ks);
  check("the restored device opens the next message on the same session", ks.m4.sender === "bob" && ks.m4.text === "after the restore", ks.m4);
  check("and its reply opens on the other side", ks.m5.sender === "alice" && ks.m5.text === "the restored device answers", ks.m5);
  const pg2 = await ctx.newPage();
  await pg2.goto(`http://127.0.0.1:${PORT + 1}/`); await pg2.waitForFunction(() => window.ready === true, null, { timeout: 30000 });
  const again = await pg2.evaluate(async () => { const K = await import("/web/zkeystore.js"); const s = await K.load("alice", "correct horse battery staple"); return !!(s && W.Device.restore(s).bundle()); });
  check("the saved keys are there on the next visit", again);
  const size = fs.statSync(path.join(PKG, "zenos_signal_wasm_bg.wasm")).size;
  console.log(`info the WebAssembly file is ${(size / 1024 / 1024).toFixed(2)} MB`);
  await finish(fail ? 1 : 0);
})().catch(async (e) => { console.error(e); await finish(1); });

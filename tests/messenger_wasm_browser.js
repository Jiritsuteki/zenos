// The same libsignal WebAssembly build in a real browser engine (Chromium, headless, through Playwright): two devices
// in the page start a session from bundles, exchange sealed-sender messages both ways, and check the trust root.
// The sender certificates come from a real relay. Build first: cd messenger/wasm && wasm-pack build --release --target web
//   node tests/messenger_wasm_browser.js
const path = require("path"), os = require("os"), fs = require("fs"), http = require("http"), { spawn } = require("child_process");
const { chromium } = require("playwright");
const MSG = path.join(__dirname, "..", "messenger"), PKG = path.join(MSG, "wasm", "pkg-web");
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "zwasmb-")), PORT = 20100 + Math.floor(Math.random() * 300), R = `http://127.0.0.1:${PORT}`;
const relay = spawn(process.execPath, [path.join(MSG, "relay.js")], { env: { ...process.env, HOME, ZENOS_RELAY_PORT: String(PORT) }, stdio: "ignore" });
const types = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html" };
const page = `<!doctype html><meta charset="utf-8"><script type="module">import init, * as W from "/pkg/zenos_signal_wasm.js"; await init(); window.W = W; window.ready = true;</script>`;
const srv = http.createServer((q, r) => {
  if (q.url === "/") { r.writeHead(200, { "Content-Type": "text/html" }); return r.end(page); }
  const f = path.join(PKG, path.basename(q.url));
  if (!q.url.startsWith("/pkg/") || !fs.existsSync(f)) { r.writeHead(404); return r.end(); }
  r.writeHead(200, { "Content-Type": types[path.extname(f)] || "application/octet-stream" }); r.end(fs.readFileSync(f));
}).listen(PORT + 1, "127.0.0.1");
let browser;
const finish = async (c) => { if (browser) await browser.close(); relay.kill(); srv.close(); fs.rmSync(HOME, { recursive: true, force: true }); process.exit(c); };
let fail = 0; const check = (n, c, g) => { console.log((c ? "ok   " : "FAIL ") + n, c ? "" : JSON.stringify(g)); if (!c) fail++; };
const j = async (p, method = "GET", obj) => (await fetch(R + p, { method, headers: { "Content-Type": "application/json" }, body: obj && JSON.stringify(obj) })).json();
(async () => {
  for (let i = 0; i < 60; i++) { try { await fetch(R + "/trust"); break; } catch { await new Promise((z) => setTimeout(z, 100)); } }
  browser = await chromium.launch();
  const pg = await (await browser.newContext()).newPage();
  await pg.goto(`http://127.0.0.1:${PORT + 1}/`); await pg.waitForFunction(() => window.ready === true, null, { timeout: 30000 });
  check("libsignal (WebAssembly) loads in Chromium", true);
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
  const size = fs.statSync(path.join(PKG, "zenos_signal_wasm_bg.wasm")).size;
  console.log(`info the WebAssembly file is ${(size / 1024 / 1024).toFixed(2)} MB`);
  await finish(fail ? 1 : 0);
})().catch(async (e) => { console.error(e); await finish(1); });

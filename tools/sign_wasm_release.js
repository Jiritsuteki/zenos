// Sign a release of the libsignal WebAssembly for phones' browsers (messenger/wasm/web/zpin.js checks it).
//   node tools/sign_wasm_release.js DIR VERSION KEY.pem [KEY.pem ...]
// DIR is wasm-pack's --target web output. Writes DIR/manifest.json (each file's SHA-256) and DIR/manifest.sig (one
// Ed25519 signature per key over the manifest's exact bytes). Each release officer signs with their own key; the
// keys never go into the repository.
//   node tools/sign_wasm_release.js --new-key FILE.pem     a new key (prints its public half for zpin.js)
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const a = process.argv.slice(2);
const pub = (k) => crypto.createPublicKey(k).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
if (a[0] === "--new-key") {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(a[1], privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  console.log(pub(privateKey));
  process.exit(0);
}
const [dir, version, ...keys] = a;
if (!dir || !version || !keys.length) { console.error("usage: sign_wasm_release.js DIR VERSION KEY.pem [KEY.pem ...]"); process.exit(2); }
const files = {};
for (const f of fs.readdirSync(dir).sort()) {
  if (!/\.(js|wasm)$/.test(f) || f.startsWith("manifest")) continue;
  files[f] = crypto.createHash("sha256").update(fs.readFileSync(path.join(dir, f))).digest("hex");
}
const m = Buffer.from(JSON.stringify({ name: "zenos-messages", version: Number(version), files }, null, 1) + "\n");
const sigs = keys.map((p) => { const k = crypto.createPrivateKey(fs.readFileSync(p)); return { key: pub(k), sig: crypto.sign(null, m, k).toString("base64") }; });
fs.writeFileSync(path.join(dir, "manifest.json"), m);
fs.writeFileSync(path.join(dir, "manifest.sig"), JSON.stringify({ sigs }, null, 1) + "\n");
console.log(`signed release ${version}: ${Object.keys(files).length} files, ${sigs.length} signatures`);

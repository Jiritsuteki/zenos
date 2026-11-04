// ZENOS Messages in a phone's browser: the code that holds the keys is accepted only when the release officers
// signed it, so a server (or someone who took it over) cannot swap it for code that sends the keys away.
//
// A release is a manifest: {"name", "version", "files": {"<file>": "<sha-256 hex>"}}. At least `need` of the
// release officers' Ed25519 keys (pinned in this file, not fetched) sign the manifest's exact bytes. The page
// loads the libsignal WebAssembly and its JavaScript only through verifiedLoad(): every file is fetched, hashed and
// compared with the signed manifest before it is used, and a release older than the newest one this browser has
// accepted is refused (no rollback to an older, weaker version). Anything that does not verify is refused: nothing
// runs. Limits: this file and the page that loads it come from the server on the first visit, and the browser
// re-fetches the service worker by itself; pinning protects the keys from swapped application code after that
// first visit, not from a swapped first visit.
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// the release officers' public keys (raw Ed25519, base64). Set at release; a page with none loads nothing.
export const RELEASE_KEYS = [];
export const NEED = 2;

const PIN_DB = "zenos-pin";
function idb() {
  return new Promise((ok, no) => {
    const r = indexedDB.open(PIN_DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
}
async function kv(mode, f) {
  const db = await idb();
  try {
    return await new Promise((ok, no) => {
      const t = db.transaction("kv", mode), r = f(t.objectStore("kv"));
      t.oncomplete = () => ok(r && r.result);
      t.onerror = () => no(t.error);
    });
  } finally { db.close(); }
}

// how many distinct pinned keys signed `bytes`
export async function signers(bytes, sigs, keys) {
  const ok = new Set();
  for (const s of sigs || []) {
    if (!keys.includes(s.key) || ok.has(s.key)) continue;
    try {
      const k = await crypto.subtle.importKey("raw", unb64(s.key), { name: "Ed25519" }, false, ["verify"]);
      if (await crypto.subtle.verify({ name: "Ed25519" }, k, unb64(s.sig), bytes)) ok.add(s.key);
    } catch { /* no Ed25519 in this browser, or a broken signature: it does not count */ }
  }
  return ok.size;
}

// fetch base/manifest.json and base/manifest.sig, check the signatures and every file; returns
// {version, files: Map(name -> Uint8Array)}; throws (and loads nothing) when anything does not verify
export async function verifiedLoad(base, keys = RELEASE_KEYS, need = NEED) {
  if (!keys.length || need < 1) throw new Error("no release keys are pinned: nothing is loaded");
  const get = async (p) => { const r = await fetch(base + p, { cache: "no-store" }); if (!r.ok) throw new Error(p + ": " + r.status); return new Uint8Array(await r.arrayBuffer()); };
  const mbytes = await get("manifest.json");
  const sig = JSON.parse(new TextDecoder().decode(await get("manifest.sig")));
  const n = await signers(mbytes, sig.sigs, keys);
  if (n < need) throw new Error(`the release is signed by ${n} of the ${need} release officers needed: refused`);
  const m = JSON.parse(new TextDecoder().decode(mbytes));
  if (!Number.isInteger(m.version) || m.version < 1) throw new Error("the release has no version: refused");
  const name = String(m.name || "zenos-messages");
  const seen = (await kv("readonly", (s) => s.get("version:" + name))) || 0;
  if (m.version < seen) throw new Error(`release ${m.version} is older than release ${seen} already accepted here: refused`);
  const files = new Map();
  for (const [f, want] of Object.entries(m.files || {})) {
    if (!/^[A-Za-z0-9._-]+$/.test(f)) throw new Error("a file name in the release is not allowed: " + f);
    const b = await get(f);
    if (hex(await crypto.subtle.digest("SHA-256", b)) !== String(want).toLowerCase())
      throw new Error(f + " is not the file the release officers signed: refused");
    files.set(f, b);
  }
  await kv("readwrite", (s) => s.put(m.version, "version:" + name));
  return { version: m.version, files };
}

// the libsignal module from a verified release (wasm-pack --target web output)
export async function loadSignal(base, keys = RELEASE_KEYS, need = NEED) {
  const { version, files } = await verifiedLoad(base, keys, need);
  const js = files.get("zenos_signal_wasm.js"), wasm = files.get("zenos_signal_wasm_bg.wasm");
  if (!js || !wasm) throw new Error("the release does not contain the libsignal module");
  const url = URL.createObjectURL(new Blob([js], { type: "text/javascript" }));
  try {
    const W = await import(url);
    await W.default({ module_or_path: wasm });
    return { W, version };
  } finally { URL.revokeObjectURL(url); }
}

export const _test = { hex, enc };

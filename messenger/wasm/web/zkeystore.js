// ZENOS Messages in a phone's browser: where the device's keys live between visits.
//
// The device's private keys and sessions (Device.export() of the WebAssembly libsignal) are kept in the browser's
// IndexedDB only encrypted: AES-GCM 256 with a key derived from the person's passphrase (PBKDF2-SHA-256, 600,000
// rounds, a random salt per device). The derived key is non-extractable: the page can use it but never read it.
// Nothing about the keys goes to the server. Without the passphrase, a copy of the browser's storage gives the
// ciphertext only; a wrong passphrase fails the AES-GCM check. Limits: a short passphrase can be guessed offline
// from a copy of the storage, and a page whose code was swapped could ask for the passphrase (zpin.js is the guard
// against swapped code).
const DB = "zenos-keys", ST = "kv", ROUNDS = 600000, enc = new TextEncoder(), dec = new TextDecoder();

function idb() {
  return new Promise((ok, no) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(ST);
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
}
function op(db, mode, f) {
  return new Promise((ok, no) => {
    const t = db.transaction(ST, mode), r = f(t.objectStore(ST));
    t.oncomplete = () => ok(r && r.result);
    t.onerror = () => no(t.error);
    t.onabort = () => no(t.error);
  });
}
async function derive(pass, salt) {
  if (!pass || pass.length < 8) throw new Error("the passphrase must be at least 8 characters");
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ROUNDS }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
const aad = (name) => enc.encode("zenos-device-v1\n" + name);

// keep `text` (Device.export()) for account `name`, encrypted with `pass`
export async function save(name, text, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await derive(pass, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(name) }, k, enc.encode(text)));
  const db = await idb();
  try { await op(db, "readwrite", (s) => s.put({ v: 1, salt, iv, ct, rounds: ROUNDS }, "device:" + name)); } finally { db.close(); }
}

// the text saved for `name`, or null when nothing is saved; throws on a wrong passphrase
export async function load(name, pass) {
  const db = await idb();
  let rec;
  try { rec = await op(db, "readonly", (s) => s.get("device:" + name)); } finally { db.close(); }
  if (!rec) return null;
  if (rec.v !== 1) throw new Error("unknown saved format");
  const k = await derive(pass, rec.salt);
  try {
    return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: rec.iv, additionalData: aad(name) }, k, rec.ct));
  } catch { throw new Error("wrong passphrase, or the saved keys were changed"); }
}

// remove the saved keys of `name` from this browser
export async function forget(name) {
  const db = await idb();
  try { await op(db, "readwrite", (s) => s.delete("device:" + name)); } finally { db.close(); }
}

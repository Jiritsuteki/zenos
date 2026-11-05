'use strict'
// ZENOS storage: encrypt then erasure-code (seal), and the reverse (open).
//
//   1. Encrypt with a fresh AES-256-GCM key per file (any change makes decryption fail)
//   2. Reed-Solomon the ciphertext into n shards (any k rebuild it)
//   3. A manifest records the SHA-256 of every shard
//   4. capability = fileId + key + hash of the manifest
//
// Storage nodes hold only ciphertext shards and the manifest (a list of hashes). The key exists only in
// the capability, so all the nodes together still cannot read the file.
//
// Not yet: issuing capabilities through the request-and-approval flow, bound to issued devices.
// Today ZENOS keeps each capability inside an index entry sealed at the file's level.

const crypto = require('crypto')
const rs = require('./rs')

const sha256 = b => crypto.createHash('sha256').update(b).digest()
const b64u = b => Buffer.from(b).toString('base64url')
const LEVEL = /^L[1-5]$/

// The uploader owns the file id: fileId = first 16 bytes of SHA-256(owner key || salt), and the manifest is signed
// with that key. A node keeps a manifest only when both hold, so nobody else can place a different manifest under
// that id first (and block the real one): they would need the owner's key, or a hash collision.
const ED_SPKI = Buffer.from('302a300506032b6570032100', 'hex')
const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex')
const ownedId = (ownerHex, salt) => sha256(Buffer.concat([Buffer.from(ownerHex, 'hex'), Buffer.from(salt, 'hex')])).subarray(0, 16).toString('hex')
const unsigned = m => Buffer.from(JSON.stringify({ ...m, sig: undefined }))
// a signer from a 32-byte Ed25519 seed (a Hyperswarm key pair's secretKey starts with it)
function signerFromSecret (secretKey) {
  const seed = Buffer.from(secretKey).subarray(0, 32)
  const priv = crypto.createPrivateKey({ key: Buffer.concat([ED_PKCS8, seed]), format: 'der', type: 'pkcs8' })
  const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(ED_SPKI.length)
  return { publicKey: pub.toString('hex'), sign: buf => crypto.sign(null, buf, priv) }
}
function ownerOk (m) {
  if (!/^[0-9a-f]{64}$/.test(m.owner || '') || !/^[0-9a-f]{32}$/.test(m.salt || '') || !/^[0-9a-f]{128}$/.test(m.sig || '')) return false
  if (ownedId(m.owner, m.salt) !== m.fileId) return false
  try {
    const pub = crypto.createPublicKey({ key: Buffer.concat([ED_SPKI, Buffer.from(m.owner, 'hex')]), format: 'der', type: 'spki' })
    return crypto.verify(null, unsigned(m), pub, Buffer.from(m.sig, 'hex'))
  } catch { return false }
}

function seal (plaintext, { k = 3, n = 5, level = 'L1', name = '', owner } = {}) {
  if (!LEVEL.test(level)) throw new Error(`invalid level: ${level}`)
  owner = owner || signerFromSecret(crypto.randomBytes(32))
  const key = crypto.randomBytes(32)
  const iv = crypto.randomBytes(12)
  const salt = crypto.randomBytes(16).toString('hex')
  const fileId = ownedId(owner.publicKey, salt)

  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  c.setAAD(Buffer.from(fileId)) // shards cannot be moved under another file id
  const blob = Buffer.concat([iv, c.update(plaintext), c.final(), c.getAuthTag()])

  const shards = rs.encode(blob, k, n)
  const manifest = {
    v: 1,
    fileId,
    level,
    name: String(name).slice(0, 128),
    k,
    n,
    length: blob.length,
    shardHashes: shards.map(s => sha256(s).toString('hex')),
    createdAt: new Date().toISOString(),
    owner: owner.publicKey,
    salt
  }
  manifest.sig = owner.sign(unsigned(manifest)).toString('hex')
  const manifestBuf = Buffer.from(JSON.stringify(manifest))
  const capability = ['zenos', '1', fileId, b64u(key), sha256(manifestBuf).toString('hex')].join(':')
  return { capability, manifest, manifestBuf, shards }
}

function parseCapability (cap) {
  const p = String(cap).trim().split(':')
  if (p.length !== 5 || p[0] !== 'zenos' || p[1] !== '1' || !/^[0-9a-f]{32}$/.test(p[2])) throw new Error('malformed capability')
  const key = Buffer.from(p[3], 'base64url')
  if (key.length !== 32) throw new Error('capability key has the wrong length')
  return { fileId: p[2], key, manifestHash: p[4] }
}

// Check a manifest against the capability and return it
function verifyManifest (cap, manifestBuf) {
  const { fileId, manifestHash } = parseCapability(cap)
  if (sha256(manifestBuf).toString('hex') !== manifestHash) throw new Error('manifest has been altered')
  const m = JSON.parse(manifestBuf)
  if (m.fileId !== fileId) throw new Error('manifest belongs to another file')
  return m
}

// Basic shape check for a manifest a node is asked to keep (it cannot check the capability hash)
function checkManifest (manifestBuf) {
  const m = JSON.parse(manifestBuf)
  if (m.v !== 1 || !/^[0-9a-f]{32}$/.test(m.fileId) || !LEVEL.test(m.level)) throw new Error('malformed manifest')
  if (!(Number.isInteger(m.k) && Number.isInteger(m.n) && m.k >= 1 && m.n > m.k && m.n <= 255)) throw new Error('malformed manifest')
  if (!Array.isArray(m.shardHashes) || m.shardHashes.length !== m.n || !m.shardHashes.every(h => /^[0-9a-f]{64}$/.test(h))) throw new Error('malformed manifest')
  if (!(Number.isInteger(m.length) && m.length > 0)) throw new Error('malformed manifest')
  if (!ownerOk(m)) throw new Error('the manifest is not signed by the owner of this file id')
  return m
}

// Does a shard match the manifest?
function shardOk (manifest, index, buf) {
  return manifest.shardHashes[index] === sha256(buf).toString('hex')
}

function open (cap, manifest, shardMap) {
  const { fileId, key } = parseCapability(cap)
  const blob = rs.decode(shardMap, manifest.k, manifest.n, manifest.length)
  const iv = blob.subarray(0, 12)
  const tag = blob.subarray(blob.length - 16)
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv)
  d.setAAD(Buffer.from(fileId))
  d.setAuthTag(tag)
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()])
}

module.exports = { seal, open, parseCapability, verifyManifest, checkManifest, shardOk, signerFromSecret }

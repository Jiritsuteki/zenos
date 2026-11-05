'use strict'
// ZENOS storage: certificates, who may do what, and where shards go.
//
// Certificate: { v: 2, role, key, clearance, zone, issuedAt, sig } signed with Ed25519 by the grid
// administrator. role is "node" (a storage node) or "client" (a ZENOS PC). key is the peer's Hyperswarm
// public key, so a certificate only works on the connection that proves that key (Noise handshake).
// Version 1 certificates (no role, field "node") are read as node certificates.
//
// On a grid with an administrator key:
//   - a peer without a valid certificate gets nothing: no reads, no writes, not even the peer list
//   - a peer may store or read a file only up to its own clearance
//   - shards go only to nodes cleared for the file's level
// Without an administrator key (development only) every peer declares its own clearance.
//
// Placement
//   1. A level Lx file goes only to nodes cleared for Lx or above
//   2. At most n-k shards per zone, so losing a whole zone still leaves k shards
//   3. One shard per node where possible; if there are too few nodes, shards double up (warning)

const crypto = require('crypto')

const LEVELS = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5']
const ROLES = ['node', 'client']
const HEX64 = /^[0-9a-f]{64}$/

function levelNum (l) {
  const i = LEVELS.indexOf(String(l))
  if (i < 0) throw new Error(`invalid level: ${l} (L1 to L5)`)
  return i
}

// ---- certificates ----

function createAdminKey () {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  return {
    publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex'),
    privateJwk: privateKey.export({ format: 'jwk' })
  }
}

function certPayload (c) {
  if (c.v === 1) return Buffer.from(JSON.stringify({ v: 1, node: c.node, clearance: c.clearance, zone: c.zone, issuedAt: c.issuedAt }))
  const p = { v: 2, role: c.role, key: c.key, clearance: c.clearance, zone: c.zone, issuedAt: c.issuedAt }
  if (c.expires !== undefined) p.expires = c.expires
  return Buffer.from(JSON.stringify(p))
}

function adminPub (adminPublicHex) {
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(adminPublicHex, 'hex').toString('base64url') },
    format: 'jwk'
  })
}

// days: how long the certificate is valid (default 365). Expired certificates are refused.
function signCert (privateJwk, { key, node, role = 'node', clearance, zone, days = 365 }) {
  key = key || node
  if (!HEX64.test(String(key))) throw new Error('invalid peer key (64 hex characters)')
  if (!ROLES.includes(role)) throw new Error(`invalid role: ${role} (node or client)`)
  levelNum(clearance)
  if (!zone) throw new Error('a zone name is required')
  if (!(Number(days) > 0)) throw new Error('days must be positive')
  const now = Date.now()
  const c = { v: 2, role, key, clearance, zone, issuedAt: new Date(now).toISOString(), expires: new Date(now + Number(days) * 86400000).toISOString() }
  c.sig = crypto.sign(null, certPayload(c), crypto.createPrivateKey({ key: privateJwk, format: 'jwk' })).toString('base64url')
  return c
}

// ---- revocation ----
// The administrator signs a list of revoked peer keys: { v: 1, issuedAt, revoked: [key...], sig }.
// Nodes and PCs keep the newest valid list they have seen and pass it on to every peer they meet, so a
// revocation reaches the whole grid without a central server.

const revocationPayload = r => Buffer.from(JSON.stringify({ v: 1, issuedAt: r.issuedAt, revoked: r.revoked }))

function signRevocations (privateJwk, revoked, issuedAt = new Date().toISOString()) {
  const keys = [...new Set(revoked)].sort()
  for (const k of keys) if (!HEX64.test(k)) throw new Error(`invalid key in the revocation list: ${k}`)
  const r = { v: 1, issuedAt, revoked: keys }
  r.sig = crypto.sign(null, revocationPayload(r), crypto.createPrivateKey({ key: privateJwk, format: 'jwk' })).toString('base64url')
  return r
}

function verifyRevocations (list, adminPublicHex) {
  try {
    if (!list || list.v !== 1 || !Array.isArray(list.revoked) || isNaN(Date.parse(list.issuedAt))) return null
    if (!crypto.verify(null, revocationPayload(list), adminPub(adminPublicHex), Buffer.from(String(list.sig), 'base64url'))) return null
    if (!list.revoked.every(k => HEX64.test(k))) return null
    return { issuedAt: list.issuedAt, revoked: new Set(list.revoked), raw: list }
  } catch { return null }
}

// The newer of two verified lists (null-safe)
function newerRevocations (a, b) {
  if (!a) return b
  if (!b) return a
  return Date.parse(b.issuedAt) > Date.parse(a.issuedAt) ? b : a
}

// Returns { role, clearance, zone } or null. revocations: a verified list (or null).
function verifyCert (cert, adminPublicHex, expectKey, revocations = null, now = Date.now()) {
  try {
    if (!cert || (cert.v !== 1 && cert.v !== 2)) return null
    const key = cert.v === 1 ? cert.node : cert.key
    const role = cert.v === 1 ? 'node' : cert.role
    if (!ROLES.includes(role)) return null
    if (expectKey && key !== expectKey) return null
    if (!crypto.verify(null, certPayload(cert), adminPub(adminPublicHex), Buffer.from(String(cert.sig), 'base64url'))) return null
    if (cert.expires !== undefined && !(Date.parse(cert.expires) > now)) return null
    if (revocations && revocations.revoked.has(key)) return null
    levelNum(cert.clearance)
    return { role, clearance: cert.clearance, zone: cert.zone, expires: cert.expires || null }
  } catch { return null }
}

// What a peer is allowed to be, from its hello answer and the key its connection proved.
//   with adminKey: the certificate decides; no valid certificate -> nothing (L0, uncertified)
//   without adminKey: the peer's own claim (development only)
function resolveTrust (hello, publicKey, adminKey, revocations = null) {
  if (adminKey) {
    const v = verifyCert(hello && hello.cert, adminKey, publicKey, revocations)
    return v ? { ...v, certified: true } : { role: null, clearance: 'L0', zone: null, certified: false }
  }
  const role = hello && hello.role === 'client' ? 'client' : 'node'
  // a peer that says nothing is the lowest level, not the highest
  const claimed = hello && LEVELS.includes(hello.clearance) ? hello.clearance : 'L1'
  return { role, clearance: claimed, zone: (hello && (hello.zone || hello.label)) || publicKey.slice(0, 8), certified: false }
}

// May this peer read or write a file at this level? (adminKey set: only certified peers.)
function mayAccess (trust, level, adminKey) {
  if (adminKey && !trust.certified) return false
  return levelNum(trust.clearance || 'L0') >= levelNum(level)
}

// ---- placement ----

const sha256hex = s => crypto.createHash('sha256').update(s).digest('hex')
function rank (fileId, peers) {
  const score = p => sha256hex(fileId + p.publicKey)
  return [...peers].sort((a, b) => (score(a) < score(b) ? -1 : 1))
}

function eligible (peer, level) {
  return peer.role !== 'client' && levelNum(peer.clearance || 'L0') >= levelNum(level)
}

function zoneCap (k, n) {
  return Math.max(1, n - k)
}

// Placement for a new file. Returns { targets: [peer...], warnings }.
function planPlacement ({ fileId, k, n, level }, peers) {
  const cands = rank(fileId, peers.filter(p => eligible(p, level)))
  if (!cands.length) throw new Error(`no storage node is cleared for ${level}`)
  const cap = zoneCap(k, n)
  const zones = new Set(cands.map(p => p.zone))
  if (zones.size * cap < n) {
    throw new Error(`only ${zones.size} zone(s) can hold ${level}; with at most ${cap} shard(s) per zone, ${n} shards do not fit (add zones or lower n)`)
  }
  const perZone = new Map()
  const perNode = new Map()
  const targets = []
  for (let i = 0; i < n; i++) {
    const ok = p => (perZone.get(p.zone) || 0) < cap
    const p = cands.find(c => ok(c) && !perNode.get(c.publicKey)) ||
              [...cands].filter(ok).sort((a, b) => (perNode.get(a.publicKey) || 0) - (perNode.get(b.publicKey) || 0))[0]
    targets.push(p)
    perZone.set(p.zone, (perZone.get(p.zone) || 0) + 1)
    perNode.set(p.publicKey, (perNode.get(p.publicKey) || 0) + 1)
  }
  const warnings = []
  const distinct = new Set(targets.map(t => t.publicKey)).size
  if (distinct < n) warnings.push(`only ${distinct} node(s) can hold ${level}, so the ${n} shards are not all on different nodes`)
  return { targets, warnings }
}

module.exports = {
  LEVELS, ROLES, levelNum, createAdminKey, signCert, verifyCert, resolveTrust, mayAccess, eligible, zoneCap, planPlacement, rank,
  signRevocations, verifyRevocations, newerRevocations
}

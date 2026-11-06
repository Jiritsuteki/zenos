'use strict'
// ZENOS storage node: keeps ciphertext shards and manifests. Never holds a key.
// One or more per site; each site is a "zone".
//
// On a grid with an administrator key, every request is checked against the certificate of the peer that
// sent it (the certificate names the key the Noise handshake proved):
//   - no valid certificate: every request is refused
//   - storing or reading a file needs a clearance at or above the file's level
//   - a node cleared below a file's level does not take it, whoever asks

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const Hyperswarm = require('hyperswarm')
const { Rpc } = require('./wire')
const { topicFor } = require('./topic')
const { repairFile } = require('./repair')
const { checkManifest } = require('./seal')
const { levelNum, verifyCert, resolveTrust, mayAccess, verifyRevocations, newerRevocations } = require('./policy')

const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/
const sha256hex = b => crypto.createHash('sha256').update(b).digest('hex')

function dirBytes (dir) {
  let total = 0
  if (!fs.existsSync(dir)) return 0
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    total += e.isDirectory() ? dirBytes(p) : fs.statSync(p).size
  }
  return total
}

class StorageNode {
  // adminKey + cert: the administrator's certificate sets this node's clearance and zone (production)
  // clearance / zone without adminKey: self-declared (development only)
  // maxBytes: refuse new shards once the store holds this much (0 = no limit)
  constructor ({ dir, grid = 'default', bootstrap, dht, seed, label, repairIntervalMs = 60000, log = () => {},
    clearance = 'L5', zone, adminKey, cert, maxBytes = 0, revocations } = {}) {
    if (!dir) throw new Error('dir (the storage folder) is required')
    this.dir = dir
    this.grid = grid
    this.label = String(label || path.basename(dir)).slice(0, 64)
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    const keyFile = path.join(dir, 'node.seed') // the node key stays with the store: same node after a restart
    if (!seed) {
      if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, crypto.randomBytes(32), { mode: 0o600 })
      seed = fs.readFileSync(keyFile)
    }
    this.swarm = new Hyperswarm(dht ? { seed, dht } : { seed, bootstrap })
    this.publicKey = this.swarm.keyPair.publicKey.toString('hex')
    this.repairIntervalMs = repairIntervalMs
    this.maxBytes = Number(maxBytes) || 0
    this.used = this.maxBytes ? dirBytes(path.join(dir, 'files')) : 0
    const seen = new Map() // the same message at most once every 10 minutes
    this.log = msg => {
      const now = Date.now()
      if (seen.has(msg) && now - seen.get(msg) < 600000) return
      seen.set(msg, now)
      log(msg)
    }
    this.adminKey = adminKey || null
    this.cert = cert || null
    this.revocations = null
    if (adminKey) {
      // the newest revocation list: the one this node kept, or a newer one it was given
      const kept = path.join(dir, 'revocations.json')
      if (fs.existsSync(kept)) this.adoptRevocations(JSON.parse(fs.readFileSync(kept, 'utf8')), { quiet: true })
      if (revocations) this.adoptRevocations(revocations, { quiet: true })
    }
    if (adminKey) {
      const v = verifyCert(cert, adminKey, this.publicKey, this.revocations)
      if (!v || v.role !== 'node') this.log(`[${this.label}] no valid node certificate: this node will not hold anything`)
      this.trust = v && v.role === 'node' ? { ...v, certified: true } : { role: 'node', clearance: 'L0', zone: null, certified: false }
    } else {
      levelNum(clearance)
      this.trust = { role: 'node', clearance, zone: zone || this.label, certified: false }
    }
    this.peers = new Map() // other storage nodes: publicKey -> { label, publicKey, request, ...trust }
    this.known = new Set() // nodes we have heard of, connected or not
    this.swarm.on('connection', (socket, info) => this._connection(socket, info))
    // this node is one of the peers too (material and target for repairs)
    this.self = { label: this.label, publicKey: this.publicKey, ...this.trust, request: async (h, b) => {
      const r = await this._handle(h, b || Buffer.alloc(0), { ...this.trust, certified: true, self: true })
      return { header: r?.header || {}, body: r?.body }
    } }
  }

  _connection (socket, info) {
    socket.on('error', () => {})
    const key = info.publicKey.toString('hex')
    let settle
    const trustP = new Promise(resolve => { settle = resolve })
    const rpc = new Rpc(socket, async (h, body) => {
      if (h.op === 'hello') return { header: this._hello() }
      const trust = await trustP // nothing is answered before the peer's certificate is checked
      if (h.op === 'revocations') return { header: { list: this.revocations ? this.revocations.raw : null } }
      return this._handle(h, body, this._stillValid(trust))
    })
    rpc.request({ op: 'hello' }, undefined, 5000).then(({ header }) => {
      const trust = { ...resolveTrust(header, key, this.adminKey, this.revocations), cert: header.cert, key }
      settle(trust)
      // pass revocations on in both directions: take theirs if newer (theirs reach us on the next exchange)
      rpc.request({ op: 'revocations' }, undefined, 5000).then(r => r.header.list && this.adoptRevocations(r.header.list)).catch(() => {})
      if (trust.role !== 'node' || (this.adminKey && !trust.certified)) return // clients and strangers are not repair partners
      const peer = { label: String(header.label || key.slice(0, 8)).slice(0, 64), publicKey: key, request: (hh, b) => rpc.request(hh, b), ...trust }
      this.peers.set(key, peer)
      socket.on('close', () => { if (this.peers.get(key) === peer) this.peers.delete(key) })
      this._exchange(peer)
    }).catch(() => settle({ role: null, clearance: 'L0', zone: null, certified: false }))
  }

  // A newer administrator-signed revocation list replaces the one held. Peers that are now revoked lose
  // their access at their next request. Returns true when the list was adopted.
  adoptRevocations (raw, { quiet = false } = {}) {
    if (!this.adminKey) return false
    const v = verifyRevocations(raw, this.adminKey)
    if (!v) return false
    const next = newerRevocations(this.revocations, v)
    if (next === this.revocations) return false
    this.revocations = next
    fs.writeFileSync(path.join(this.dir, 'revocations.json'), JSON.stringify(raw), { mode: 0o600 })
    if (this.peers) for (const k of [...this.peers.keys()]) if (next.revoked.has(k)) this.peers.delete(k)
    if (this.trust && this.trust.certified && next.revoked.has(this.publicKey)) {
      this.trust = { role: 'node', clearance: 'L0', zone: null, certified: false }
      this.self && Object.assign(this.self, this.trust)
      this.log(`[${this.label}] this node's own key has been revoked: it no longer holds anything new`)
    }
    if (!quiet) this.log(`[${this.label}] revocation list of ${next.issuedAt} adopted (${next.revoked.size} revoked)`)
    return true
  }

  // Is this peer still allowed? (certificates expire and keys get revoked while connections stay open)
  _stillValid (trust) {
    if (!this.adminKey) return trust
    if (trust.self) return trust
    return trust.certified && verifyCert(trust.cert, this.adminKey, trust.key, this.revocations) ? trust : { ...trust, certified: false }
  }

  _hello () {
    return { role: 'node', label: this.label, publicKey: this.publicKey, cert: this.cert, clearance: this.trust.clearance, zone: this.trust.zone }
  }

  async start () {
    const d = this.swarm.join(topicFor(this.grid), { server: true, client: true }) // nodes find each other too
    await d.flushed()
    if (this.repairIntervalMs > 0) {
      this.timer = setInterval(async () => {
        for (const p of this.peers.values()) this._exchange(p)
        this.repairAll().catch(e => this.log(`repair error: ${e.message}`))
      }, this.repairIntervalMs)
      this.timer.unref()
    }
    return this
  }

  async stop () {
    clearInterval(this.timer)
    await this.swarm.destroy()
  }

  // Peer exchange: ask a node which nodes it knows and connect to the ones we are not connected to
  // (a DHT lookup alone does not guarantee every node reaches every other node)
  async _exchange (peer) {
    try {
      const r = await peer.request({ op: 'revocations' })
      if (r.header.list) this.adoptRevocations(r.header.list)
    } catch {}
    try {
      const { header } = await peer.request({ op: 'peers' })
      for (const k of (header.keys || []).slice(0, 256)) {
        if (!HEX64.test(k) || k === this.publicKey) continue
        this.known.add(k)
        if (!this.peers.has(k)) this.swarm.joinPeer(Buffer.from(k, 'hex'))
      }
    } catch {}
  }

  allPeers () {
    return [this.self, ...this.peers.values()]
  }

  // Check every file this node holds and repair the ones it leads
  async repairAll ({ force = false } = {}) {
    if (this._repairing) return []
    this._repairing = true
    const reports = []
    try {
      const root = path.join(this.dir, 'files')
      if (!fs.existsSync(root)) return reports
      for (const fileId of fs.readdirSync(root)) {
        if (!HEX32.test(fileId)) continue
        try { // one bad file (unreadable, malformed, a peer that answers nonsense) never stops the others
          const mbuf = this._readManifest(fileId)
          if (!mbuf) continue
          const r = await repairFile(mbuf, this.allPeers(), {
            self: force ? null : this.self,
            log: s => this.log(`[${this.label}] ${s}`)
          })
          if (r && (r.rebuilt.length || r.copied.length || r.skipped)) reports.push(r)
        } catch (e) {
          this.log(`[${this.label}] repair of ${fileId} skipped: ${e.message}`)
        }
      }
    } finally {
      this._repairing = false
    }
    return reports
  }

  _fileDir (fileId) {
    if (!HEX32.test(String(fileId))) throw new Error('invalid fileId')
    return path.join(this.dir, 'files', fileId)
  }

  _readManifest (fileId) {
    const f = path.join(this._fileDir(fileId), 'manifest.json')
    return fs.existsSync(f) ? fs.readFileSync(f) : null
  }

  _levelOf (fileId) {
    const mbuf = this._readManifest(fileId)
    return mbuf ? { mbuf, m: JSON.parse(mbuf) } : null
  }

  _need (trust, level) {
    if (!mayAccess(trust, level, this.adminKey)) throw new Error(`not cleared for ${level}`)
  }

  async _handle (h, body, trust) {
    if (this.adminKey && !trust.certified) throw new Error('no valid certificate for this grid')
    switch (h.op) {
      case 'peers':
        return { header: { keys: [...this.peers.keys(), ...this.known].filter((v, i, a) => a.indexOf(v) === i).slice(0, 256) } }

      case 'put_manifest': {
        const m = checkManifest(body)
        // the last guard: never take a level above this node's own clearance, whoever asks
        if (levelNum(m.level) > levelNum(this.trust.clearance)) throw new Error(`${m.level} cannot be held by this node (cleared for ${this.trust.clearance})`)
        this._need(trust, m.level)
        const dir = this._fileDir(m.fileId)
        const existing = this._readManifest(m.fileId)
        if (existing && !existing.equals(body)) throw new Error('a different manifest is already held for this file') // never overwritten
        if (!existing) {
          // a manifest counts against the store's size like a shard: nobody fills the disk with manifests alone
          if (this.maxBytes && this.used + body.length > this.maxBytes) throw new Error('this node is full')
          fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
          const tmp = path.join(dir, `.manifest.${crypto.randomBytes(4).toString('hex')}`)
          fs.writeFileSync(tmp, body, { mode: 0o600 })
          fs.renameSync(tmp, path.join(dir, 'manifest.json'))
          this.used += body.length
        }
        return {}
      }

      case 'put_shard': {
        const f = this._levelOf(h.fileId)
        if (!f) throw new Error('no manifest for this file')
        this._need(trust, f.m.level)
        const i = Number(h.index)
        if (!Number.isInteger(i) || i < 0 || i >= f.m.n) throw new Error('invalid shard index')
        // checked on arrival: a broken or forged shard is never kept
        if (f.m.shardHashes[i] !== sha256hex(body)) throw new Error('shard does not match the manifest')
        const dest = path.join(this._fileDir(h.fileId), `${i}.shard`)
        if (fs.existsSync(dest)) return {}
        if (this.maxBytes && this.used + body.length > this.maxBytes) throw new Error('this node is full')
        const tmp = `${dest}.${crypto.randomBytes(4).toString('hex')}.part`
        fs.writeFileSync(tmp, body, { mode: 0o600 })
        fs.renameSync(tmp, dest)
        this.used += body.length
        return {}
      }

      case 'get_manifest': {
        const f = this._levelOf(h.fileId)
        if (!f) throw new Error('no manifest for this file')
        this._need(trust, f.m.level)
        return { body: f.mbuf }
      }

      case 'list_shards': {
        const f = this._levelOf(h.fileId)
        if (!f) return { header: { indices: [] } }
        this._need(trust, f.m.level)
        const indices = fs.readdirSync(this._fileDir(h.fileId))
          .filter(x => /^\d+\.shard$/.test(x))
          .map(x => Number(x.split('.')[0]))
        return { header: { indices } }
      }

      case 'get_shard': {
        const f = this._levelOf(h.fileId)
        if (!f) throw new Error('no manifest for this file')
        this._need(trust, f.m.level)
        const i = Number(h.index)
        if (!Number.isInteger(i) || i < 0 || i >= f.m.n) throw new Error('invalid shard index')
        const p = path.join(this._fileDir(h.fileId), `${i}.shard`)
        if (!fs.existsSync(p)) throw new Error('shard not held here')
        return { body: fs.readFileSync(p) }
      }

      default:
        throw new Error('unknown operation')
    }
  }
}

module.exports = { StorageNode }

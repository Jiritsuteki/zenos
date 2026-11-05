'use strict'
// ZENOS storage client: seal a file across the nodes, gather it back with the capability.
//
// On a grid with an administrator key the client needs its own certificate (role "client"): nodes refuse
// every request from a peer without one, and serve a file only up to the client's clearance.
// The client also uses only nodes whose certificate checks out.

const Hyperswarm = require('hyperswarm')
const { Rpc } = require('./wire')
const { topicFor } = require('./topic')
const { seal, open, parseCapability, verifyManifest, shardOk, signerFromSecret } = require('./seal')
const { resolveTrust, planPlacement, verifyRevocations, newerRevocations } = require('./policy')

const HEX64 = /^[0-9a-f]{64}$/

class ZenosClient {
  // adminKey: the grid administrator's public key (production). seed + cert: this client's identity.
  constructor ({ grid = 'default', bootstrap, dht, adminKey, seed, cert, revocations } = {}) {
    this.grid = grid
    this.adminKey = adminKey || null
    this.cert = cert || null
    this.revocations = null
    if (revocations) this.adoptRevocations(revocations)
    const o = seed ? { seed } : {}
    this.swarm = new Hyperswarm(dht ? { ...o, dht } : { ...o, bootstrap })
    this.publicKey = this.swarm.keyPair.publicKey.toString('hex')
    this.peers = new Map() // publicKey -> { rpc, label, ...trust }
    this.swarm.on('connection', async (socket, info) => {
      socket.on('error', () => {})
      const key = info.publicKey.toString('hex')
      const rpc = new Rpc(socket, h => {
        if (h.op === 'hello') return { header: { role: 'client', cert: this.cert } }
        if (h.op === 'revocations') return { header: { list: this.revocations ? this.revocations.raw : null } }
        throw new Error('a client does not serve requests')
      })
      const peer = { rpc, label: key.slice(0, 8), publicKey: key }
      this.peers.set(key, peer)
      socket.on('close', () => { if (this.peers.get(key) === peer) this.peers.delete(key) })
      try {
        const { header } = await rpc.request({ op: 'hello' }, undefined, 5000)
        if (header.role !== 'node') return
        peer.label = String(header.label || peer.label).slice(0, 64)
        try {
          const r = await rpc.request({ op: 'revocations' }, undefined, 5000)
          if (r.header.list) this.adoptRevocations(r.header.list)
        } catch {}
        Object.assign(peer, resolveTrust(header, key, this.adminKey, this.revocations))
        if (this.adminKey && !peer.certified) return // a node without a valid certificate is never used
        peer.ready = true
        const r = await rpc.request({ op: 'peers' }, undefined, 5000) // reach the nodes this node knows
        for (const k of (r.header.keys || []).slice(0, 256)) {
          if (HEX64.test(k) && !this.peers.has(k)) this.swarm.joinPeer(Buffer.from(k, 'hex'))
        }
      } catch {}
    })
  }

  async connect ({ minPeers = 1, timeoutMs = 15000 } = {}) {
    const d = this.swarm.join(topicFor(this.grid), { server: false, client: true })
    await d.flushed()
    await this.swarm.flush()
    const t0 = Date.now()
    while (this.livePeers().length < minPeers) {
      if (Date.now() - t0 > timeoutMs) throw new Error(`storage nodes not found (${this.livePeers().length}/${minPeers})`)
      await new Promise(r => setTimeout(r, 100))
    }
    return this
  }

  adoptRevocations (raw) {
    if (!this.adminKey) return false
    const v = verifyRevocations(raw, this.adminKey)
    const next = newerRevocations(this.revocations, v)
    if (!v || next === this.revocations) return false
    this.revocations = next
    for (const p of this.peers.values()) if (next.revoked.has(p.publicKey)) p.ready = false
    return true
  }

  livePeers () {
    return [...this.peers.values()].filter(p => p.ready && !p.rpc.closed)
  }

  async close () {
    await this.swarm.destroy()
  }

  async put (plaintext, opts = {}) {
    const peers = this.livePeers()
    if (!peers.length) throw new Error('no storage node connected')
    const { capability, manifest, manifestBuf, shards } = seal(plaintext, { ...opts, owner: signerFromSecret(this.swarm.keyPair.secretKey) })
    const plan = planPlacement(manifest, peers) // nothing is sent if the placement rules cannot be met
    const targets = [...new Set(plan.targets)]

    // the manifest goes only to the nodes that get a shard: others never see the name or the level
    const sent = await Promise.allSettled(targets.map(p => p.rpc.request({ op: 'put_manifest' }, manifestBuf)))
    const refused = sent.map((r, i) => r.status === 'rejected' ? `${targets[i].label}: ${r.reason.message}` : null).filter(Boolean)

    const placement = []
    const results = await Promise.allSettled(shards.map((s, i) => {
      const p = plan.targets[i]
      placement.push({ index: i, node: p.label, zone: p.zone })
      return p.rpc.request({ op: 'put_shard', fileId: manifest.fileId, index: i }, s)
    }))
    const stored = results.filter(r => r.status === 'fulfilled').length
    if (stored < manifest.k) throw new Error(`fewer than k shards were stored (${stored}/${manifest.k})${refused.length ? ': ' + refused[0] : ''}`)

    const warnings = [...plan.warnings]
    if (stored < manifest.n) warnings.push(`${manifest.n - stored} shard(s) could not be stored`)
    return { capability, fileId: manifest.fileId, k: manifest.k, n: manifest.n, stored, placement, warnings }
  }

  // Which node holds which shard (for checks; no key needed)
  async locate (fileId) {
    const map = new Map()
    await Promise.all(this.livePeers().map(async p => {
      try {
        const { header } = await p.rpc.request({ op: 'list_shards', fileId }, undefined, 5000)
        for (const i of header.indices) {
          if (!map.has(i)) map.set(i, [])
          map.get(i).push(p.label)
        }
      } catch {}
    }))
    return map
  }

  async get (capability, { log = () => {} } = {}) {
    const { fileId } = parseCapability(capability)
    const peers = this.livePeers()
    if (!peers.length) throw new Error('no storage node connected')

    // 1) the manifest: only one whose hash matches the capability
    let manifest = null
    for (const p of peers) {
      try {
        const { body } = await p.rpc.request({ op: 'get_manifest', fileId })
        manifest = verifyManifest(capability, body)
        break
      } catch (e) { log(`  manifest from ${p.label} not used: ${e.message}`) }
    }
    if (!manifest) throw new Error('no node holds a valid manifest for this file (or this client is not cleared for it)')

    // 2) which node holds which shard
    const holdings = await Promise.all(peers.map(async p => {
      try {
        const { header } = await p.rpc.request({ op: 'list_shards', fileId })
        return { p, indices: header.indices }
      } catch { return { p, indices: [] } }
    }))

    // 3) gather k shards whose hashes match
    const got = new Map()
    const rejected = []
    for (const { p, indices } of holdings) {
      for (const i of indices) {
        if (got.size >= manifest.k) break
        if (got.has(i)) continue
        try {
          const { body } = await p.rpc.request({ op: 'get_shard', fileId, index: i })
          if (shardOk(manifest, i, body)) {
            got.set(i, body)
            log(`  shard ${i} from ${p.label}`)
          } else {
            rejected.push({ index: i, node: p.label })
            log(`  shard ${i} from ${p.label} does not match its hash: discarded`)
          }
        } catch (e) { log(`  shard ${i} from ${p.label} failed: ${e.message}`) }
      }
    }
    if (got.size < manifest.k) throw new Error(`not enough shards to restore (${got.size}/${manifest.k})`)

    const data = open(capability, manifest, got)
    return { data, manifest, used: [...got.keys()], rejected }
  }
}

module.exports = { ZenosClient }

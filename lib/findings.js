'use strict'

const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

function sigKey(sig) {
  return crypto.createHash('sha1').update(sig).digest('hex').slice(0, 12)
}

class FindingStore {
  constructor({ dir }) {
    this.dir = dir
    fs.mkdirSync(dir, { recursive: true })
    this.seen = new Map()
    this.indexPath = path.join(dir, 'index.json')
    if (fs.existsSync(this.indexPath)) {
      try {
        const idx = JSON.parse(fs.readFileSync(this.indexPath, 'utf8'))
        for (const k of Object.keys(idx)) this.seen.set(k, idx[k])
      } catch {
        /* ignore */
      }
    }
  }

  has(signature) {
    return this.seen.has(sigKey(signature))
  }

  record({ probe, steps, signature, kind, logHits, minimized }) {
    const key = sigKey(signature)
    if (this.seen.has(key)) {
      const e = this.seen.get(key)
      e.count++
      e.lastSeen = Date.now()
      this._writeIndex()
      return e
    }
    const entry = {
      key,
      kind,
      signature,
      probe,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      count: 1,
    }
    this.seen.set(key, entry)
    const file = path.join(this.dir, `${key}.json`)
    const payload = {
      ...entry,
      steps: serializeSteps(steps),
      minimized: minimized ? serializeSteps(minimized) : null,
      logHits,
    }
    fs.writeFileSync(file, JSON.stringify(payload, null, 2))
    this._writeIndex()
    return entry
  }

  _writeIndex() {
    const out = {}
    for (const [k, v] of this.seen) out[k] = v
    fs.writeFileSync(this.indexPath, JSON.stringify(out, null, 2))
  }

  summary() {
    return [...this.seen.values()].sort((a, b) => b.count - a.count)
  }
}

function serializeSteps(steps) {
  if (!steps) return null
  return steps.map((s) => {
    if (s.type === 'raw') return { type: 'raw', bytesHex: Buffer.from(s.bytes).toString('hex') }
    return { ...s }
  })
}

module.exports = { FindingStore, sigKey }

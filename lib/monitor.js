'use strict'

const fs = require('node:fs')
const readline = require('node:readline')
const { EventEmitter } = require('node:events')

// Patterns we treat as suspicious in maillog. The capture group becomes the
// "signature" so two findings with the same root cause dedupe to one entry.
const SUSPICIOUS = [
  { name: 'uncaughtException', re: /(uncaught\s*exception[^\n]*)/i },
  { name: 'unhandledRejection', re: /(unhandled\s*rejection[^\n]*)/i },
  { name: 'TypeError', re: /(TypeError:[^\n]*)/ },
  { name: 'RangeError', re: /(RangeError:[^\n]*)/ },
  { name: 'ReferenceError', re: /(ReferenceError:[^\n]*)/ },
  { name: 'AssertionError', re: /(AssertionError[^\n]*)/ },
  { name: 'plugin-error', re: /\[(?:CRIT|ERROR)\][^\n]*?(plugin[^\n]*)/i },
  { name: 'stack-frame', re: /^\s*at\s+([^\s(]+)\s*\(/m },
  { name: 'panic', re: /(PANIC[^\n]*)/i },
  { name: 'FATAL', re: /(FATAL[^\n]*)/ },
  { name: 'segfault', re: /(segmentation fault[^\n]*)/i },
  // Haraka-specific: connections terminated abnormally
  { name: 'connection-error', re: /connection\s+(reset|aborted|closed unexpectedly)[^\n]*/i },
]

class MailLogMonitor extends EventEmitter {
  constructor({ path = '/var/log/maillog', windowMs = 2000 } = {}) {
    super()
    this.path = path
    this.windowMs = windowMs
    this.tail = null
    this.recent = [] // rolling buffer of {t, line, hits}
    this.position = 0
    this.stopped = false
  }

  async start() {
    const stat = await fs.promises.stat(this.path)
    this.position = stat.size
    this._loop()
  }

  stop() {
    this.stopped = true
  }

  _classify(line) {
    const hits = []
    for (const sig of SUSPICIOUS) {
      const m = line.match(sig.re)
      if (m) hits.push({ name: sig.name, signature: (m[1] || m[0]).trim().slice(0, 240) })
    }
    return hits
  }

  async _loop() {
    while (!this.stopped) {
      try {
        const stat = await fs.promises.stat(this.path)
        if (stat.size < this.position) {
          // file rotated/truncated
          this.position = 0
        }
        if (stat.size > this.position) {
          const stream = fs.createReadStream(this.path, {
            start: this.position,
            end: stat.size - 1,
            encoding: 'utf8',
          })
          const rl = readline.createInterface({ input: stream, crlfDelay: Infinity })
          for await (const line of rl) {
            const now = Date.now()
            const hits = this._classify(line)
            const entry = { t: now, line, hits }
            this.recent.push(entry)
            // Trim to a generous window
            const cutoff = now - Math.max(10_000, this.windowMs * 5)
            while (this.recent.length && this.recent[0].t < cutoff) this.recent.shift()
            if (hits.length) this.emit('finding', entry)
            this.emit('line', entry)
          }
          this.position = stat.size
        }
      } catch (err) {
        this.emit('error', err)
      }
      await new Promise((r) => setTimeout(r, 100))
    }
  }

  // Return findings observed within `windowMs` after `sinceTs`.
  collectAfter(sinceTs, windowMs = this.windowMs) {
    const deadline = sinceTs + windowMs
    return this.recent.filter((e) => e.hits.length && e.t >= sinceTs && e.t <= deadline)
  }

  // Quiesce: wait until no new lines arrive for `quietMs` (capped at `maxMs`).
  async waitQuiet({ quietMs = 250, maxMs = 2000 } = {}) {
    return await new Promise((resolve) => {
      let last = Date.now()
      const onLine = () => {
        last = Date.now()
      }
      this.on('line', onLine)
      const start = Date.now()
      const tick = () => {
        if (this.stopped) return done()
        if (Date.now() - last >= quietMs) return done()
        if (Date.now() - start >= maxMs) return done()
        setTimeout(tick, 50)
      }
      const done = () => {
        this.off('line', onLine)
        resolve()
      }
      tick()
    })
  }
}

module.exports = { MailLogMonitor, SUSPICIOUS }

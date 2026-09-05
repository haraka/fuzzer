'use strict'

const path = require('node:path')
const { Worker } = require('node:worker_threads')

const WORKER_PATH = path.join(__dirname, 'worker.js')

class TargetHarness {
  constructor({ targetPath, timeoutMs = 1000 }) {
    this.targetPath = path.resolve(targetPath)
    this.timeoutMs = timeoutMs
    this.worker = null
    this.nextId = 0
    this.pending = null
    this.died = false
  }

  async start() {
    await this._spawn()
  }

  _spawn() {
    return new Promise((resolve, reject) => {
      this.died = false
      this.worker = new Worker(WORKER_PATH, { workerData: { targetPath: this.targetPath } })
      const onMsg = (msg) => {
        if (msg.type === 'ready') {
          this.worker.off('message', onMsg)
          this._attachHandlers()
          resolve()
        } else if (msg.type === 'init-error') {
          this.worker.terminate()
          reject(new Error(`worker init failed: ${msg.message}`))
        }
      }
      this.worker.on('message', onMsg)
      this.worker.on('error', (err) => {
        this.died = true
        if (this.pending) {
          const p = this.pending
          this.pending = null
          p.reject(err)
        }
      })
      this.worker.on('exit', () => {
        this.died = true
        if (this.pending) {
          const p = this.pending
          this.pending = null
          p.resolve({ ok: false, crashed: true, name: 'WorkerExit', message: 'worker exited' })
        }
      })
    })
  }

  _attachHandlers() {
    this.worker.on('message', (msg) => {
      if (msg.type !== 'result') return
      if (!this.pending || this.pending.id !== msg.id) return
      const p = this.pending
      this.pending = null
      clearTimeout(p.timer)
      p.resolve(msg)
    })
  }

  async call(input) {
    if (this.died || !this.worker) await this._spawn()
    const id = ++this.nextId
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input)
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(async () => {
        if (this.pending && this.pending.id === id) {
          this.pending = null
          try {
            await this.worker.terminate()
          } catch {
            /* ignore */
          }
          this.died = true
          resolve({ ok: false, hung: true, name: 'Hang', message: `>${this.timeoutMs}ms`, durationNs: this.timeoutMs * 1_000_000 })
        }
      }, this.timeoutMs)
      this.pending = { id, resolve, reject, timer }
      try {
        this.worker.postMessage({ type: 'input', id, input: buf })
      } catch (err) {
        clearTimeout(timer)
        this.pending = null
        resolve({ ok: false, crashed: true, name: 'PostFailed', message: err.message })
      }
    })
  }

  async stop() {
    if (this.worker) {
      try {
        await this.worker.terminate()
      } catch {
        /* ignore */
      }
      this.worker = null
    }
  }
}

module.exports = { TargetHarness }

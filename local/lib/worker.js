'use strict'

const { parentPort, workerData } = require('node:worker_threads')

// Suppress the haraka-config / iconv-lite chatter that some targets emit on load.
const _origLog = console.log
const _origInfo = console.info
const _origWarn = console.warn
console.log = console.info = console.warn = () => {}

;(async () => {
  let target, mod
  try {
    target = require(workerData.targetPath)
    mod = target.setup ? await target.setup() : null
    if (target.ready) await target.ready(mod)
  } catch (err) {
    parentPort.postMessage({ type: 'init-error', name: err.name, message: err.message, stack: err.stack })
    return
  }
  console.log = _origLog
  console.info = _origInfo
  console.warn = _origWarn
  parentPort.postMessage({ type: 'ready' })

  parentPort.on('message', async (msg) => {
    if (msg.type !== 'input') return
    const t0 = process.hrtime.bigint()
    let memBefore = 0
    try {
      memBefore = process.memoryUsage().heapUsed
    } catch {
      /* ignore */
    }
    try {
      await target.run(mod, Buffer.from(msg.input))
      const dur = Number(process.hrtime.bigint() - t0)
      const memDelta = process.memoryUsage().heapUsed - memBefore
      parentPort.postMessage({ type: 'result', id: msg.id, ok: true, durationNs: dur, memDelta })
    } catch (err) {
      const dur = Number(process.hrtime.bigint() - t0)
      parentPort.postMessage({
        type: 'result',
        id: msg.id,
        ok: false,
        durationNs: dur,
        name: err.name || 'Error',
        message: err.message || String(err),
        stack: err.stack || '',
      })
    }
  })
})()

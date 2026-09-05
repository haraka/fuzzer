'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { TargetHarness } = require('../lib/harness.js')

// Build a tiny synthetic target on disk so we can exercise the harness behaviors
// in isolation, without depending on any haraka module.
function writeTempTarget(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-harness-'))
  const file = path.join(dir, 'target.js')
  fs.writeFileSync(file, body)
  return file
}

test('harness returns ok for normal target', async () => {
  const tgt = writeTempTarget(`
    module.exports = {
      name: 'tiny',
      seeds: [''],
      async run(_m, _input) { /* noop */ },
    }
  `)
  const h = new TargetHarness({ targetPath: tgt, timeoutMs: 1000 })
  await h.start()
  const r = await h.call(Buffer.from('hi'))
  assert.equal(r.ok, true)
  await h.stop()
})

test('harness captures thrown TypeError', async () => {
  const tgt = writeTempTarget(`
    module.exports = {
      name: 'tiny',
      seeds: [''],
      async run(_m, _input) { (null).oops },
    }
  `)
  const h = new TargetHarness({ targetPath: tgt, timeoutMs: 1000 })
  await h.start()
  const r = await h.call(Buffer.from('x'))
  assert.equal(r.ok, false)
  assert.equal(r.name, 'TypeError')
  await h.stop()
})

test('harness flags a hang and recovers for the next call', async () => {
  const tgt = writeTempTarget(`
    module.exports = {
      name: 'tiny',
      seeds: [''],
      async run(_m, input) {
        // Hang only on a specific marker; otherwise return promptly.
        if (input.toString() === 'HANG') {
          await new Promise(() => {}) // never resolves
        }
      },
    }
  `)
  const h = new TargetHarness({ targetPath: tgt, timeoutMs: 200 })
  await h.start()
  const r1 = await h.call(Buffer.from('HANG'))
  assert.equal(r1.hung, true)
  // After a hang the harness should respawn the worker transparently
  const r2 = await h.call(Buffer.from('ok'))
  assert.equal(r2.ok, true)
  await h.stop()
})

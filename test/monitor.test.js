'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { MailLogMonitor } = require('../lib/monitor.js')

async function settle(ms = 200) {
  return new Promise((r) => setTimeout(r, ms))
}

test('detects TypeError lines appended to the log', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-mon-'))
  const file = path.join(dir, 'maillog')
  fs.writeFileSync(file, '')
  const mon = new MailLogMonitor({ path: file, windowMs: 500 })
  const findings = []
  mon.on('finding', (e) => findings.push(e))
  await mon.start()
  await settle(150)
  fs.appendFileSync(file, '2026-05-13 12:00:00 normal line\n')
  fs.appendFileSync(file, '2026-05-13 12:00:01 TypeError: undefined is not a function at /a/b.js:1\n')
  await settle(400)
  mon.stop()
  assert.ok(findings.length >= 1)
  assert.equal(findings[0].hits[0].name, 'TypeError')
})

test('handles file rotation (truncate)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-mon-'))
  const file = path.join(dir, 'maillog')
  fs.writeFileSync(file, 'first line\n')
  const mon = new MailLogMonitor({ path: file, windowMs: 500 })
  const lines = []
  mon.on('line', (e) => lines.push(e.line))
  await mon.start()
  await settle(200)
  // rotate: truncate (let monitor observe empty state), then append
  fs.writeFileSync(file, '')
  await settle(200)
  fs.appendFileSync(file, 'after rotation\n')
  await settle(400)
  mon.stop()
  assert.ok(lines.some((l) => l.includes('after rotation')))
})

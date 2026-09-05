'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')

const { ddmin, minimize } = require('../lib/minimize.js')

test('ddmin reduces to minimal item set that satisfies oracle', async () => {
  // Oracle says "yes" iff the set contains the marker 'X'
  const items = ['a', 'b', 'X', 'c', 'd', 'e', 'f']
  const oracle = async (cand) => cand.includes('X')
  const reduced = await ddmin(items, oracle)
  assert.deepEqual(reduced, ['X'])
})

test('minimize shrinks steps containing the crash trigger', async () => {
  const steps = [
    { type: 'cmd', line: 'EHLO a' },
    { type: 'cmd', line: 'NOOP' },
    { type: 'cmd', line: 'BOOM trigger here' },
    { type: 'cmd', line: 'NOOP' },
  ]
  const replay = async (cand) => {
    const hit = cand.some((s) => s.type === 'cmd' && /BOOM/.test(s.line))
    return { hit, signature: hit ? 'BOOM-sig' : null }
  }
  const out = await minimize(steps, replay, 'BOOM-sig')
  assert.equal(out.length, 1)
  assert.match(out[0].line, /BOOM/)
})

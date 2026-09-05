'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')

const { mutate, mkRng, MUTATORS } = require('../lib/mutate.js')

test('mkRng is deterministic for a given seed', () => {
  const a = mkRng(42)
  const b = mkRng(42)
  for (let i = 0; i < 100; i++) assert.equal(a(), b())
})

test('mutate produces a Buffer and never throws on small inputs', () => {
  const rng = mkRng(1)
  for (let i = 0; i < 200; i++) {
    const out = mutate(Buffer.from('EHLO fuzz.local\r\n'), { rng, useRadamsa: false })
    assert.ok(Buffer.isBuffer(out))
  }
})

test('mutate tolerates empty input', () => {
  const out = mutate(Buffer.alloc(0), { rng: mkRng(7), useRadamsa: false })
  assert.ok(Buffer.isBuffer(out))
})

test('each built-in mutator returns a Buffer', () => {
  const rng = mkRng(99)
  const seed = Buffer.from('MAIL FROM:<a@b> SIZE=10\r\n')
  for (const name of Object.keys(MUTATORS)) {
    const out = MUTATORS[name](seed, rng)
    assert.ok(Buffer.isBuffer(out), `${name} returned non-Buffer`)
  }
})

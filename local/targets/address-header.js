'use strict'

// @haraka/email-address header grammar (the `address` target covers only the
// envelope). Plain Error is a clean rejection.

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const ROOT = path.join(__dirname, '..', '..', '..', 'email-address')

// headers plugin retries a strict failure with allowCommaInDisplayName
const OPTION_SETS = [undefined, { postel: true }, { allowCommaInDisplayName: true }]

const CTRL_RE = /[\x00-\x1f\x7f]/

function corpusSeeds() {
  try {
    return fs
      .readFileSync(path.join(ROOT, 'test', 'header-corpus.txt'), 'utf8')
      .split(/\n\n+/)
      .map((block) => block.split('\n').find((l) => l.length && !l.startsWith('#')))
      .filter(Boolean)
  } catch {
    return []
  }
}

const SMALL_LEN = 32 * 1024
const GROWTH = 8
const SUPERLINEAR_RATIO = GROWTH * 3
const SUPERLINEAR_FLOOR_MS = 40
const AMPLIFY_MAX_INPUT = 1024

function hash(s) {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619)
  return h >>> 0
}

function amplifier(s) {
  // hash-picked, not random, so a finding replays and minimizes
  const h = hash(s)
  const start = h % s.length
  const span = 1 + ((h >>> 8) % Math.min(16, s.length - start))
  const prefix = s.slice(0, start)
  const mid = s.slice(start, start + span)
  const suffix = s.slice(start + span)
  const reps = Math.ceil(SMALL_LEN / mid.length)
  return (growth) => prefix + mid.repeat(reps * growth) + suffix
}

function parseMs(parseHeader, s, opts) {
  const t0 = process.hrtime.bigint()
  try {
    parseHeader(s, opts)
  } catch {
    /* only timing matters here */
  }
  return Number(process.hrtime.bigint() - t0) / 1e6
}

function assertLinear(parseHeader, s, opts) {
  const build = amplifier(s)
  const small = build(1)
  const big = build(GROWTH)
  const bigMs = parseMs(parseHeader, big, opts)
  if (bigMs < SUPERLINEAR_FLOOR_MS) return
  // best of two, so one GC pause can't fake a spike
  const smallMs = Math.min(parseMs(parseHeader, small, opts), parseMs(parseHeader, small, opts))
  const confirmedBigMs = Math.min(bigMs, parseMs(parseHeader, big, opts))
  const ratio = confirmedBigMs / Math.max(smallMs, 0.05)
  assert.ok(
    confirmedBigMs < SUPERLINEAR_FLOOR_MS || ratio < SUPERLINEAR_RATIO,
    `superlinear parse (${JSON.stringify(opts ?? {})}): ${small.length}B ${smallMs.toFixed(1)}ms -> ${big.length}B ${confirmedBigMs.toFixed(1)}ms`,
  )
}

function checkFormatted(parseHeader, item, opts) {
  const formatted = item.format()
  assert.ok(!CTRL_RE.test(formatted), `control char in ${item.constructor.name}.format(): ${JSON.stringify(formatted)}`)
  let reparsed
  try {
    reparsed = parseHeader(formatted, opts)
  } catch (err) {
    assert.fail(`${item.constructor.name}.format() does not re-parse: ${JSON.stringify(formatted)}: ${err.message}`)
  }
  assert.equal(reparsed.length, 1, `format() re-parses to ${reparsed.length} items: ${JSON.stringify(formatted)}`)
  JSON.stringify(item)
  item.name()
}

module.exports = {
  name: 'address-header',
  // assertLinear parses ~256KB per option set and catches superlinear parses itself: on a slow runner that alone
  // passes --slow. Under the 1000ms hang timeout
  slowMs: 800,
  seeds: [
    ...corpusSeeds(),
    'Friends: a@example.com, "x y" <b@example.com>;',
    '"a\\"b" (c (d)) <e@[1.2.3.4]>',
    'Doe, John <j@example.com>',
    'δοκιμή <δ@παράδειγμα.gr>',
    '"a:b" : x@example.com;',
    '"evil\\\r\\\nBcc: x@example.com" : a@example.com;',
    'x@example.com.',
    'a.b.c.d <x@example.com>',
    'a@example.com, b@example.com, c@example.com',
    `x@${'b.'.repeat(130)}com`,
  ],
  setup() {
    return require(ROOT)
  },
  run(mod, input) {
    const s = (Buffer.isBuffer(input) ? input : Buffer.from(input)).toString('utf8')
    for (const opts of OPTION_SETS) {
      let items
      try {
        items = mod.parseHeader(s, opts)
      } catch (err) {
        if (err.constructor !== Error) throw err
        items = []
      }
      for (const item of items) checkFormatted(mod.parseHeader, item, opts)
      if (s.length && s.length <= AMPLIFY_MAX_INPUT) assertLinear(mod.parseHeader, s, opts)
    }
  },
}

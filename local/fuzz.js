#!/usr/bin/env node
'use strict'

const { parseArgs } = require('node:util')
const fs = require('node:fs')
const path = require('node:path')

const { TargetHarness } = require('./lib/harness.js')
const { mutate, mkRng, HAS_RADAMSA } = require('../lib/mutate.js')
const { FindingStore } = require('../lib/findings.js')
const { ddmin } = require('../lib/minimize.js')

const TARGETS_DIR = path.join(__dirname, 'targets')

const { values: opts } = parseArgs({
  options: {
    targets: { type: 'string', default: 'all' },
    iters: { type: 'string', default: '500' }, // mutated inputs per target
    out: { type: 'string', default: './findings-local' },
    seed: { type: 'string' },
    timeout: { type: 'string', default: '1000' }, // ms per call before declared a hang
    slow: { type: 'string', default: '200' }, // ms; over this is a "slow" finding
    minimize: { type: 'boolean', default: true },
    'no-minimize': { type: 'boolean' },
    quiet: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
})

if (opts.help) {
  process.stdout.write(`Usage: node local/fuzz.js [options]

  --targets        Comma-separated target names, or "all" (default all)
  --iters          Mutated inputs per target (default 500)
  --out            Findings dir (default ./findings-local)
  --seed           PRNG seed (omit for random)
  --timeout        ms before a call is declared hung (default 1000)
  --slow           ms above which a call counts as a "slow" finding (default 200)
  --no-minimize    Skip ddmin
  --quiet          Suppress per-iteration output

Available targets: ${listTargets().join(', ')}
`)
  process.exit(0)
}

function listTargets() {
  return fs.readdirSync(TARGETS_DIR).filter((f) => f.endsWith('.js')).map((f) => f.replace(/\.js$/, ''))
}

const iters = parseInt(opts.iters, 10)
const timeoutMs = parseInt(opts.timeout, 10)
const slowMs = parseInt(opts.slow, 10)
const seed = opts.seed ? parseInt(opts.seed, opts.seed.startsWith('0x') ? 16 : 10) : undefined
const doMinimize = opts['no-minimize'] ? false : opts.minimize
const log = (...a) => {
  if (!opts.quiet) console.log(...a)
}

function pickTargets() {
  const all = listTargets()
  if (opts.targets === 'all') return all
  const wanted = opts.targets.split(',').map((s) => s.trim())
  const unknown = wanted.filter((w) => !all.includes(w))
  if (unknown.length) {
    console.error(`unknown targets: ${unknown.join(', ')}\navailable: ${all.join(', ')}`)
    process.exit(2)
  }
  return wanted
}

// Plain `Error` is typically a parser/library cleanly rejecting bad input.
// Real bugs surface as JS-builtin error subclasses, hangs, or crashes.
const BUG_ERROR_NAMES = new Set(['TypeError', 'RangeError', 'ReferenceError', 'AssertionError', 'SyntaxError', 'URIError'])

function signatureFor(target, res) {
  if (res.hung) return `${target.name}:HANG`
  if (res.crashed) return `${target.name}:CRASH:${res.name || ''}`
  if (!res.ok) {
    const errName = res.name || 'Error'
    const accept = target.acceptableErrors
    if (accept && accept(res)) return null
    if (!BUG_ERROR_NAMES.has(errName) && !target.flagPlainErrors) return null
    // Pull the first stack frame that is NOT inside the worker or this fuzzer
    const frame = (res.stack || '')
      .split('\n')
      .slice(1)
      .find((l) => !/worker\.js|fuzzer\/lib/.test(l)) || ''
    const cleaned = frame.trim().replace(/\(.*\)/, '').slice(0, 120)
    return `${target.name}:${errName}:${cleaned}`
  }
  if (res.durationNs / 1e6 > slowMs) {
    return `${target.name}:SLOW`
  }
  return null
}

const MIN_INPUT_MAX = 4096 // skip minimize for inputs larger than this
const MIN_BUDGET_MS = 10_000 // wall-clock budget per finding

async function minimizeInput(harness, input, target, sig) {
  if (input.length > MIN_INPUT_MAX) return null
  const deadline = Date.now() + MIN_BUDGET_MS
  const oracle = async (bytesArr) => {
    if (Date.now() > deadline) throw new Error('minimize-budget-exceeded')
    const trial = Buffer.from(bytesArr)
    try {
      const r = await harness.call(trial)
      return signatureFor(target, r) === sig
    } catch {
      return false
    }
  }
  try {
    const minimized = await ddmin(Array.from(input), oracle)
    return Buffer.from(minimized)
  } catch (err) {
    if (err.message === 'minimize-budget-exceeded') return null
    throw err
  }
}

async function fuzzTarget(name, store, rng) {
  const targetPath = path.join(TARGETS_DIR, `${name}.js`)
  const target = require(targetPath)
  const harness = new TargetHarness({ targetPath, timeoutMs })
  try {
    await harness.start()
  } catch (err) {
    log(`[${name}] harness failed to start: ${err.message}`)
    return
  }
  log(`[${name}] start (radamsa=${HAS_RADAMSA ? 'yes' : 'no'})`)

  let total = 0
  let newFindings = 0

  const tryInput = async (input, source) => {
    total++
    const res = await harness.call(input)
    const sig = signatureFor(target, res)
    if (!sig) return
    if (store.has(sig)) return
    newFindings++
    log(`[${name}] FINDING ${sig.slice(0, 140)} (${source}, ${input.length}B)`)
    let minimized = null
    if (doMinimize && (res.hung || !res.ok)) {
      try {
        minimized = await minimizeInput(harness, input, target, sig)
        if (minimized) log(`[${name}] minimized: ${input.length}B -> ${minimized.length}B`)
        else log(`[${name}] minimize skipped (input ${input.length}B over cap or budget)`)
      } catch (err) {
        log(`[${name}] minimize error: ${err.message}`)
      }
    }
    store.record({
      probe: { kind: 'local', name },
      steps: [{ type: 'raw', bytes: input }],
      signature: sig,
      kind: res.hung ? 'HANG' : res.crashed ? 'CRASH' : !res.ok ? res.name : 'SLOW',
      logHits: [
        {
          t: Date.now(),
          line: res.message || `${(res.durationNs / 1e6).toFixed(1)}ms`,
          stack: res.stack || null,
        },
      ],
      minimized: minimized ? [{ type: 'raw', bytes: minimized }] : null,
    })
  }

  // 1. Run seed corpus verbatim
  for (const seed of target.seeds || []) {
    const buf = Buffer.isBuffer(seed) ? seed : Buffer.from(seed)
    await tryInput(buf, 'seed')
  }
  // 2. Run mutated inputs
  const seedBufs = (target.seeds || []).map((s) => (Buffer.isBuffer(s) ? s : Buffer.from(s)))
  for (let i = 0; i < iters; i++) {
    const base = seedBufs[Math.floor(rng() * seedBufs.length)] || Buffer.alloc(0)
    const mutated = mutate(base, { rng, maxLen: 16384 })
    await tryInput(mutated, `mut#${i}`)
    if (i > 0 && i % 100 === 0) log(`[${name}] ${i}/${iters} (${newFindings} new findings)`)
  }
  log(`[${name}] done: ${total} inputs, ${newFindings} new findings`)
  await harness.stop()
}

async function main() {
  const store = new FindingStore({ dir: path.resolve(opts.out) })
  const rng = mkRng(seed)
  const targets = pickTargets()
  log(`[local-fuzzer] targets=${targets.join(',')} iters=${iters} timeout=${timeoutMs}ms slow=${slowMs}ms`)
  for (const name of targets) await fuzzTarget(name, store, rng)
  log(`[local-fuzzer] summary:`)
  for (const e of store.summary()) {
    log(`  ${e.count}x  ${e.signature.slice(0, 100)}  (${e.key})`)
  }
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(1)
})

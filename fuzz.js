#!/usr/bin/env node
'use strict'

const { parseArgs } = require('node:util')
const path = require('node:path')

const { SmtpRawClient } = require('./lib/client.js')
const { MailLogMonitor } = require('./lib/monitor.js')
const { FindingStore } = require('./lib/findings.js')
const { minimize } = require('./lib/minimize.js')
const { mkRng, HAS_RADAMSA } = require('./lib/mutate.js')

const protocolProbes = require('./probes/protocol.js')
const authProbes = require('./probes/auth.js')
const starttlsProbes = require('./probes/starttls.js')
const bodyProbes = require('./probes/body.js')

const { values: opts } = parseArgs({
  options: {
    host: { type: 'string', default: '127.0.0.1' },
    port: { type: 'string', default: '25' },
    maillog: { type: 'string', default: '/var/log/maillog' },
    out: { type: 'string', default: './findings' },
    scope: { type: 'string', default: 'all' }, // all|protocol|auth|tls|body
    seed: { type: 'string' },
    duration: { type: 'string', default: '0' }, // seconds; 0 = run all probes once
    timeout: { type: 'string', default: '5000' },
    minimize: { type: 'boolean', default: true },
    'no-minimize': { type: 'boolean' },
    window: { type: 'string', default: '2000' }, // ms after probe to attribute findings
    quiet: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
})

if (opts.help) {
  process.stdout.write(`Usage: node fuzz.js [options]

  --host           Target SMTP host (default 127.0.0.1)
  --port           Target SMTP port (default 25)
  --maillog        Path to maillog (default /var/log/maillog)
  --out            Findings directory (default ./findings)
  --scope          Comma-separated: protocol,auth,tls,body  (default all)
  --seed           PRNG seed (hex/dec); omit for random
  --duration       Seconds to run (0 = single pass)
  --timeout        Per-socket timeout in ms (default 5000)
  --window         ms after each probe to attribute log findings (default 2000)
  --no-minimize    Skip delta-debug minimization
  --quiet          Suppress per-probe logging
`)
  process.exit(0)
}

const port = parseInt(opts.port, 10)
const timeout = parseInt(opts.timeout, 10)
const windowMs = parseInt(opts.window, 10)
const durationSec = parseInt(opts.duration, 10)
const seed = opts.seed ? parseInt(opts.seed, opts.seed.startsWith('0x') ? 16 : 10) : undefined
const rng = mkRng(seed)
const doMinimize = opts['no-minimize'] ? false : opts.minimize
const scopes = opts.scope === 'all' ? ['protocol', 'auth', 'tls', 'body'] : opts.scope.split(',').map((s) => s.trim())

const log = (...a) => {
  if (!opts.quiet) console.log(...a)
}

async function executeSteps(steps, { host, port, timeout }) {
  const client = new SmtpRawClient({ host, port, timeout })
  try {
    const banner = await client.connect()
    if (banner.code !== 220 && banner.code !== 0) {
      // Some probes intentionally hit a server in bad state; carry on
    }
    for (const step of steps) {
      try {
        if (step.type === 'cmd') await client.cmd(step.line)
        else if (step.type === 'raw') await client.sendRaw(step.bytes)
        else if (step.type === 'tls') await client.upgradeTls()
        else if (step.type === 'sleep') await new Promise((r) => setTimeout(r, step.ms))
        else if (step.type === 'expect') await client._readResponse()
      } catch {
        break // socket likely closed
      }
    }
  } finally {
    client.close()
  }
  return client.transcript
}

// A probe may declare oracle(transcript) -> string | null. The maillog oracle only
// sees exceptions; an AUTH bypass answers 235 and a smuggled transaction answers
// 250, so protocol-level findings need the probe to say what a bad reply looks like.
function semanticFinding(probe, transcript) {
  if (typeof probe.oracle !== 'function') return null
  try {
    return probe.oracle(transcript) || null
  } catch (err) {
    return `oracle-threw:${err.message}`
  }
}

function* allProbes() {
  if (scopes.includes('protocol')) yield* withKind('protocol', protocolProbes.all(rng))
  if (scopes.includes('auth')) yield* withKind('auth', authProbes.all(rng))
  if (scopes.includes('tls')) yield* withKind('tls', starttlsProbes.all())
  if (scopes.includes('body')) yield* withKind('body', bodyProbes.all(rng))
}

function* withKind(kind, gen) {
  for (const p of gen) yield { ...p, kind }
}

async function main() {
  const findings = new FindingStore({ dir: path.resolve(opts.out) })
  const monitor = new MailLogMonitor({ path: opts.maillog, windowMs })
  monitor.on('error', (err) => log('[monitor] error:', err.message))
  await monitor.start()
  log(`[fuzzer] target=${opts.host}:${port} scope=${scopes.join(',')} radamsa=${HAS_RADAMSA ? 'yes' : 'no'}`)

  const stopAt = durationSec > 0 ? Date.now() + durationSec * 1000 : null
  let probeCount = 0
  let findingCount = 0

  const runOnce = async () => {
    for (const probe of allProbes()) {
      if (stopAt && Date.now() > stopAt) return
      probeCount++
      const t0 = Date.now()
      let transcript = []
      try {
        transcript = await executeSteps(probe.steps, { host: opts.host, port, timeout })
      } catch (err) {
        log(`[probe ${probe.name}] exec error:`, err.message)
      }
      const semantic = semanticFinding(probe, transcript)
      if (semantic) {
        const sig = `${probe.kind}/${probe.name}:SEMANTIC:${semantic}`
        if (!findings.has(sig)) {
          findingCount++
          log(`[FINDING] ${probe.kind}/${probe.name}: semantic :: ${semantic.slice(0, 120)}`)
          findings.record({
            probe: { kind: probe.kind, name: probe.name },
            steps: probe.steps,
            signature: sig,
            kind: 'semantic',
            logHits: transcript.filter((t) => t.dir === 'S').map((t) => ({ t: t.t, line: JSON.stringify(t.reply).slice(0, 200) })),
            minimized: null,
          })
        }
      }
      await monitor.waitQuiet({ quietMs: 250, maxMs: windowMs })
      const hits = monitor.collectAfter(t0, windowMs)
      if (hits.length) {
        const flat = hits.flatMap((h) => h.hits)
        const targetSig = flat[0].signature
        const targetKind = flat[0].name
        if (!findings.has(targetSig)) {
          findingCount++
          log(`[FINDING] ${probe.kind}/${probe.name}: ${targetKind} :: ${targetSig.slice(0, 120)}`)
          let minimized = null
          if (doMinimize) {
            try {
              minimized = await minimizeWithOracle(probe, targetSig, targetKind)
              log(`[minimized] ${probe.name}: ${probe.steps.length} -> ${minimized.length} steps`)
            } catch (err) {
              log(`[minimize] error:`, err.message)
            }
          }
          findings.record({
            probe: { kind: probe.kind, name: probe.name },
            steps: probe.steps,
            signature: targetSig,
            kind: targetKind,
            logHits: hits.map((h) => ({ t: h.t, line: h.line })),
            minimized,
          })
        }
      }
      if (probeCount % 25 === 0) log(`[fuzzer] probes=${probeCount} findings=${findingCount}`)
    }
  }

  const minimizeWithOracle = async (probe, targetSig, targetKind) => {
    const replay = async (candidateSteps) => {
      const t0 = Date.now()
      try {
        await executeSteps(candidateSteps, { host: opts.host, port, timeout })
      } catch {
        /* ignore */
      }
      await monitor.waitQuiet({ quietMs: 200, maxMs: windowMs })
      const hits = monitor.collectAfter(t0, windowMs)
      const flat = hits.flatMap((h) => h.hits)
      const hit = flat.find((h) => h.signature === targetSig && h.name === targetKind)
      return { hit: !!hit, signature: hit ? hit.signature : null }
    }
    return await minimize(probe.steps, replay, targetSig)
  }

  if (durationSec > 0) {
    while (Date.now() < stopAt) await runOnce()
  } else {
    await runOnce()
  }

  log(`[fuzzer] done. probes=${probeCount} new-findings=${findingCount}`)
  log(`[fuzzer] summary:`)
  for (const entry of findings.summary()) {
    log(`  ${entry.count}x  ${entry.kind}  ${entry.signature.slice(0, 80)}  (${entry.key})`)
  }
  monitor.stop()
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(1)
})

'use strict'

// Delta-debugging minimizer for probes.
//
// A probe is a sequence of "steps", where each step is either:
//   { type: 'cmd', line: string }      // send line + CRLF, read reply
//   { type: 'raw', bytes: Buffer }     // send raw bytes, do not read
//   { type: 'expect', code: number }   // read a reply, no-op if no match
//   { type: 'tls' }                    // upgradeTls()
//   { type: 'sleep', ms: number }
//
// minimize() tries to shrink (a) the step list and (b) the bytes inside each
// surviving step, while preserving a finding signature matcher.
//
// The `replay(steps)` callback is async and resolves to { signature, hit }.

const ddmin = async (items, oracle) => {
  // Classic Zeller ddmin over a list of items; oracle returns boolean.
  let chunks = 2
  let current = items.slice()
  while (current.length >= 2) {
    const size = Math.ceil(current.length / chunks)
    let reduced = false
    for (let i = 0; i < current.length; i += size) {
      const complement = current.slice(0, i).concat(current.slice(i + size))
      if (complement.length === 0) continue
      // try complement first (removing chunk i)
      if (await oracle(complement)) {
        current = complement
        chunks = Math.max(chunks - 1, 2)
        reduced = true
        break
      }
    }
    if (!reduced) {
      if (chunks >= current.length) break
      chunks = Math.min(chunks * 2, current.length)
    }
  }
  return current
}

async function minimizeSteps(steps, replay, targetSig) {
  const oracle = async (candidate) => {
    try {
      const r = await replay(candidate)
      return r && r.hit && r.signature === targetSig
    } catch {
      return false
    }
  }
  return await ddmin(steps, oracle)
}

async function minimizeBytes(step, steps, replay, targetSig) {
  const field = step.type === 'cmd' ? 'line' : step.type === 'raw' ? 'bytes' : null
  if (!field) return step
  const original = field === 'line' ? Buffer.from(step.line, 'utf8') : Buffer.from(step.bytes)
  const idx = steps.indexOf(step)
  if (idx < 0) return step

  const oracle = async (bytesArr) => {
    const trial = Buffer.from(bytesArr)
    const replaced = { ...step }
    if (field === 'line') replaced.line = trial.toString('utf8')
    else replaced.bytes = trial
    const trialSteps = steps.slice()
    trialSteps[idx] = replaced
    try {
      const r = await replay(trialSteps)
      return r && r.hit && r.signature === targetSig
    } catch {
      return false
    }
  }
  const minimized = await ddmin(Array.from(original), oracle)
  const out = { ...step }
  if (field === 'line') out.line = Buffer.from(minimized).toString('utf8')
  else out.bytes = Buffer.from(minimized)
  return out
}

async function minimize(steps, replay, targetSig) {
  // First shrink step list
  const shrunkSteps = await minimizeSteps(steps, replay, targetSig)
  // Then shrink bytes inside each step
  const finalSteps = []
  for (const step of shrunkSteps) {
    if (step.type === 'cmd' || step.type === 'raw') {
      finalSteps.push(await minimizeBytes(step, shrunkSteps, replay, targetSig))
    } else {
      finalSteps.push(step)
    }
  }
  return finalSteps
}

module.exports = { minimize, minimizeSteps, minimizeBytes, ddmin }

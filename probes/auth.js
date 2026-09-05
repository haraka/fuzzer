'use strict'

const { mutate, HOSTILE_TOKENS } = require('../lib/mutate.js')

const cmd = (line) => ({ type: 'cmd', line })
const raw = (bytes) => ({ type: 'raw', bytes: Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes) })

const greet = cmd('EHLO fuzz.local')

function b64(s) {
  return Buffer.from(s, 'binary').toString('base64')
}

function* plain() {
  // RFC 4616: \0user\0pass
  const cases = [
    ['empty', ''],
    ['only-nulls', '\0\0'],
    ['trailing-nulls', 'user\0pass\0\0\0'],
    ['embedded-cr', 'user\rpass\0pw'],
    ['embedded-lf', 'user\npass\0pw'],
    ['oversize-user', '\0' + 'A'.repeat(4096) + '\0pw'],
    ['oversize-pass', '\0u\0' + 'B'.repeat(1 << 16)],
    ['utf8', '\0u\u{1f4a9}\0p\u{4e2d}'],
    ['bad-base64', null], // sentinel: send a non-base64 string as the AUTH PLAIN arg
    ['no-padding', null],
    ['unicode-null-look', '␀u␀p'],
  ]
  for (const [name, payload] of cases) {
    if (name === 'bad-base64') {
      yield { name: `plain-bad-b64`, steps: [greet, cmd('AUTH PLAIN !!!!not_base64!!!!')] }
      continue
    }
    if (name === 'no-padding') {
      yield { name: `plain-no-padding`, steps: [greet, cmd('AUTH PLAIN ' + b64('\0u\0p').replace(/=+$/, ''))] }
      continue
    }
    yield { name: `plain-${name}`, steps: [greet, cmd('AUTH PLAIN ' + b64(payload))] }
  }
  // initial response sent on a second line
  yield {
    name: 'plain-twoline',
    steps: [greet, cmd('AUTH PLAIN'), cmd(b64('\0user\0pass'))],
  }
  // empty second line
  yield {
    name: 'plain-twoline-empty',
    steps: [greet, cmd('AUTH PLAIN'), cmd('')],
  }
}

function* login() {
  yield { name: 'login-basic', steps: [greet, cmd('AUTH LOGIN'), cmd(b64('user')), cmd(b64('pass'))] }
  yield { name: 'login-empty-user', steps: [greet, cmd('AUTH LOGIN'), cmd(''), cmd(b64('pass'))] }
  yield { name: 'login-cancel', steps: [greet, cmd('AUTH LOGIN'), cmd('*')] }
  yield { name: 'login-oversize', steps: [greet, cmd('AUTH LOGIN'), cmd(b64('A'.repeat(1 << 14))), cmd(b64('B'.repeat(1 << 14)))] }
  yield { name: 'login-bad-b64', steps: [greet, cmd('AUTH LOGIN'), cmd('@@@'), cmd('@@@')] }
  yield { name: 'login-with-arg', steps: [greet, cmd('AUTH LOGIN ' + b64('user')), cmd(b64('pass'))] }
}

function* cram() {
  yield { name: 'cram-md5-stage', steps: [greet, cmd('AUTH CRAM-MD5'), cmd(b64('user 00000000000000000000000000000000'))] }
  yield { name: 'cram-md5-cancel', steps: [greet, cmd('AUTH CRAM-MD5'), cmd('*')] }
  yield { name: 'cram-md5-binary', steps: [greet, cmd('AUTH CRAM-MD5'), raw(Buffer.from([0xff, 0xfe, 0x00, 0x0d, 0x0a])) ] }
}

function* mechanismFuzz(rng) {
  const mechs = ['PLAIN', 'LOGIN', 'CRAM-MD5', 'XOAUTH2', 'SCRAM-SHA-1', 'GSSAPI', 'EXTERNAL', 'XX', '']
  for (const m of mechs) {
    yield { name: `mech-${m || 'empty'}`, steps: [greet, cmd(`AUTH ${m}`)] }
  }
  // Mutated AUTH lines
  for (let i = 0; i < 10; i++) {
    const buf = mutate(Buffer.from('AUTH PLAIN AGFAYWRtaW4AcGFzcw==\r\n'), { rng })
    yield { name: `auth-mutated-${i}`, steps: [greet, raw(buf)] }
  }
}

// The AUTH username is raw client input that is never address-validated, so it
// reaches a bare object lookup verbatim. A name that aliases Object.prototype
// yields a truthy "account" whose toString() is a constant an attacker knows,
// which is an open relay if the server hands it back as the password.
// No account exists for these names, so any 235 is an authentication bypass
// (GHSA-xf4w-8v5p-24pc), whatever the server logged.
const noAuthSuccess = (transcript) => {
  const ok = transcript.find((t) => t.dir === 'S' && t.reply?.code === 235)
  return ok ? `235 granted to an inherited-member username` : null
}

function* hostileNames() {
  for (const tok of HOSTILE_TOKENS) {
    yield {
      name: `plain-hostile-${tok}`,
      steps: [greet, cmd('AUTH PLAIN ' + b64(`\0${tok}\0[object Object]`))],
      oracle: noAuthSuccess,
    }
    yield {
      name: `login-hostile-${tok}`,
      steps: [greet, cmd('AUTH LOGIN'), cmd(b64(tok)), cmd(b64('[object Object]'))],
      oracle: noAuthSuccess,
    }
    yield {
      name: `cram-hostile-${tok}`,
      steps: [greet, cmd('AUTH CRAM-MD5'), cmd(b64(`${tok} 00000000000000000000000000000000`))],
      oracle: noAuthSuccess,
    }
    // the same name with whitespace/case padding, which normalisation may strip
    yield {
      name: `plain-hostile-padded-${tok}`,
      steps: [greet, cmd('AUTH PLAIN ' + b64(`\0 ${tok} \0pw`))],
      oracle: noAuthSuccess,
    }
    yield {
      name: `plain-hostile-domain-${tok}`,
      steps: [greet, cmd('AUTH PLAIN ' + b64(`\0user@${tok}\0pw`))],
      oracle: noAuthSuccess,
    }
  }
}

function* all(rng) {
  yield* plain()
  yield* login()
  yield* cram()
  yield* hostileNames()
  yield* mechanismFuzz(rng)
}

module.exports = { all }

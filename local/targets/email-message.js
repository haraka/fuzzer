'use strict'

const path = require('node:path')

const MAX_BYTES = 2 << 20 // 2 MiB cap; bigger inputs are slow without surfacing real bugs

const SEED_SIMPLE = [
  'Subject: hi',
  'From: a@b',
  'To: c@d',
  '',
  'Hello world',
].join('\n') + '\n'

const SEED_MULTI = [
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b"',
  '',
  '--b',
  'Content-Type: text/plain',
  '',
  'A',
  '--b',
  'Content-Type: application/octet-stream',
  'Content-Disposition: attachment; filename="x.bin"',
  'Content-Transfer-Encoding: base64',
  '',
  'SGVsbG8gV29ybGQ=',
  '--b--',
  '',
].join('\n')

const SEED_NESTED = [
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="A"',
  '',
  '--A',
  'Content-Type: multipart/alternative; boundary="B"',
  '',
  '--B',
  'Content-Type: text/plain',
  '',
  'plain',
  '--B',
  'Content-Type: text/html',
  '',
  '<b>html</b>',
  '--B--',
  '--A--',
  '',
].join('\n')

// Shapes that byte mutation cannot reach: prototype-aliasing field names, the
// SMTP terminator as a header line, dot-stuffed and folded variants, several
// physical lines bundled into one element, and a lone CR splitting a field.
const SEED_HOSTILE = [
  '__proto__: polluted',
  'constructor: polluted',
  'prototype: polluted',
  'toString: x',
  '.',
  '..',
  '.: v',
  '__proto__ : spaced',
  '.\t',
  'X-Fold: a',
  ' .',
  'Subject: safe\rBcc: victim@example.test',
  'From: a@b',
  '',
  'body',
].join('\n') + '\n'

const SEED_BUNDLED = 'X: a\n.\nY: b\n__proto__: z\n\nbody\n'

const UNSAFE_NAMES = ['__proto__', 'constructor', 'prototype', '.', '..']

module.exports = {
  name: 'email-message',
  seeds: [SEED_SIMPLE, SEED_MULTI, SEED_NESTED, SEED_HOSTILE, SEED_BUNDLED],
  setup() {
    return require(path.join(__dirname, '..', '..', '..', 'email-message'))
  },
  async run(mod, input) {
    if (input.length > MAX_BYTES) input = input.subarray(0, MAX_BYTES)
    const text = input.toString('utf8')
    // Split headers from body on first blank line
    const lines = text.split(/\r?\n/).map((l) => l + '\n')
    let blank = -1
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] === '\n') {
        blank = i
        break
      }
    }
    const headerLines = blank >= 0 ? lines.slice(0, blank + 1) : lines
    const bodyLines = blank >= 0 ? lines.slice(blank + 1) : []

    const header = new mod.Header()
    header.parse(headerLines)

    const body = new mod.Body(header)
    body.on('attachment_start', (_ct, _fn, _part, stream) => {
      stream.on('data', () => {})
      stream.on('error', () => {})
    })
    body.on('error', () => {})
    for (const line of bodyLines) body.parse_more(line)
    body.parse_end()

    // Oracles. Every bug in this class failed silently, so crash-only detection
    // is blind to it: assert the invariants instead.
    for (const entry of header.header_list) {
      const [first] = entry.split('\n', 1)
      const [name] = first.replace(/\r$/, '').split(':', 1)
      if (UNSAFE_NAMES.includes(name.trim().toLowerCase())) {
        throw new TypeError(`unsafe header name retained: ${JSON.stringify(name)}`)
      }
    }
    if (header.toString().split(/\r\n|\r|\n/).some((l) => l === '.' || l === '..')) {
      throw new TypeError('serialised header block contains a bare SMTP terminator line')
    }
    if ({}.polluted !== undefined || Object.keys(Object.prototype).length) {
      throw new TypeError('prototype pollution')
    }
  },
}

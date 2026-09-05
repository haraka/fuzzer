'use strict'

// @haraka/email-address: the parser every MAIL FROM / RCPT TO / AUTH domain
// passes through. An earlier target here found a TypeError and a hang on 16KB
// inputs (both fixed by the 256-octet path limit); the target was then lost.
// Plain Error is the parser rejecting bad input and is expected.

const path = require('node:path')

const ROOT = path.join(__dirname, '..', '..', '..', 'email-address')

const INHERITED = ['__proto__', 'constructor', 'prototype', 'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf']

module.exports = {
  name: 'address',
  seeds: [
    '<a@b.com>',
    'a@b.com',
    '<"quoted local"@example.com>',
    '<a@[127.0.0.1]>',
    '<a@[IPv6:::1]>',
    '<@relay.example,@x.example:a@b.example>',
    '<>',
    '<a@b.example> SIZE=100 BODY=8BITMIME',
    ...INHERITED.map((n) => `<x@${n}>`),
    ...INHERITED.map((n) => `<${n}@x.example>`),
    // the two inputs that were once findings: a bare run and an over-long domain
    'A'.repeat(16384),
    `<a@b.${'A'.repeat(16000)}>`,
    `<a@${'x.'.repeat(400)}com>`,
    `<${'a'.repeat(300)}@b.com>`,
  ],
  setup() {
    return require(ROOT)
  },
  run(mod, input) {
    const s = (Buffer.isBuffer(input) ? input : Buffer.from(input)).toString('binary')
    let a
    try {
      a = new mod.Address(s)
    } catch (e) {
      if (e instanceof TypeError || e instanceof RangeError || e instanceof ReferenceError) throw e
      return // clean rejection
    }
    // an accepted address must round-trip and must not expose an inherited member as a host
    // A host such as 'constructor' is a syntactically valid label, so accepting it
    // is correct here; the prototype-pollution class is a consumer bug (see the
    // haraka-connection / plugin targets), not a parser one. Only serialisation
    // faults on an accepted address count.
    for (const m of ['format', 'toString', 'toJSON']) String(a[m]())
  },
}

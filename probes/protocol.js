'use strict'

const { mutate } = require('../lib/mutate.js')

// A probe generator yields { name, steps[] }.
// Steps shape is documented in lib/minimize.js.

const cmd = (line) => ({ type: 'cmd', line })
const raw = (bytes) => ({ type: 'raw', bytes: Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes) })
const sleep = (ms) => ({ type: 'sleep', ms })

const baseGreet = [cmd('EHLO fuzz.local')]
const baseEnvelope = [cmd('MAIL FROM:<a@b>'), cmd('RCPT TO:<c@d>')]

function* stateMachineProbes() {
  // commands before greeting
  yield { name: 'cmd-before-ehlo', steps: [cmd('MAIL FROM:<x@y>')] }
  yield { name: 'data-before-envelope', steps: [...baseGreet, cmd('DATA')] }
  yield { name: 'rcpt-before-mail', steps: [...baseGreet, cmd('RCPT TO:<x@y>')] }
  yield { name: 'double-ehlo', steps: [cmd('EHLO a'), cmd('EHLO b')] }
  yield { name: 'double-mail', steps: [...baseGreet, cmd('MAIL FROM:<a@b>'), cmd('MAIL FROM:<c@d>')] }
  yield { name: 'rset-everywhere', steps: [...baseGreet, cmd('RSET'), cmd('RSET'), cmd('MAIL FROM:<a@b>'), cmd('RSET')] }
  yield {
    name: 'pipelined-burst',
    steps: [cmd('EHLO fuzz.local'), raw('MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nRCPT TO:<e@f>\r\nDATA\r\n')],
  }
  yield {
    name: 'quit-then-cmd',
    steps: [...baseGreet, cmd('QUIT'), cmd('NOOP')],
  }
}

function* commandSyntaxProbes() {
  const verbs = ['HELO', 'EHLO', 'MAIL FROM:', 'RCPT TO:', 'DATA', 'NOOP', 'RSET', 'VRFY', 'EXPN', 'HELP', 'STARTTLS', 'AUTH']
  for (const v of verbs) {
    yield { name: `bare-${v.replace(/\W+/g, '_')}`, steps: [cmd(v)] }
    yield { name: `padded-${v.replace(/\W+/g, '_')}`, steps: [cmd('   ' + v + '   ')] }
    yield { name: `tabs-${v.replace(/\W+/g, '_')}`, steps: [cmd('\t' + v + '\t')] }
  }
  // Long lines / arguments
  yield { name: 'long-ehlo', steps: [cmd('EHLO ' + 'a'.repeat(8192))] }
  yield { name: 'huge-ehlo', steps: [cmd('EHLO ' + 'a'.repeat(1 << 17))] }
  yield { name: 'long-mail', steps: [...baseGreet, cmd('MAIL FROM:<' + 'a'.repeat(4096) + '@b>')] }
  yield {
    name: 'long-rcpt-list',
    steps: [...baseGreet, cmd('MAIL FROM:<a@b>'), ...Array.from({ length: 200 }, (_, i) => cmd(`RCPT TO:<u${i}@b>`))],
  }
  // Verb case + whitespace
  yield { name: 'mixed-case-verb', steps: [cmd('eHLo fuzz')] }
  yield { name: 'no-space-arg', steps: [...baseGreet, cmd('MAIL FROM:<a@b>SIZE=1')] }
}

function* lineEndingProbes() {
  yield { name: 'lf-only', steps: [{ type: 'raw', bytes: Buffer.from('EHLO fuzz\n') }] }
  yield { name: 'cr-only', steps: [{ type: 'raw', bytes: Buffer.from('EHLO fuzz\r') }] }
  yield { name: 'crlfcrlf', steps: [{ type: 'raw', bytes: Buffer.from('EHLO fuzz\r\n\r\nNOOP\r\n') }] }
  yield { name: 'null-byte-in-cmd', steps: [{ type: 'raw', bytes: Buffer.from('EHLO fu\0zz\r\n') }] }
  yield { name: 'embedded-cr', steps: [{ type: 'raw', bytes: Buffer.from('EHLO fuzz\rEXTRA\r\n') }] }
  yield { name: 'utf8-bom', steps: [{ type: 'raw', bytes: Buffer.from('﻿EHLO fuzz\r\n', 'utf8') }] }
  yield { name: 'leading-crlf', steps: [{ type: 'raw', bytes: Buffer.from('\r\n\r\nEHLO fuzz\r\n') }] }
  yield {
    name: 'megaline',
    steps: [{ type: 'raw', bytes: Buffer.concat([Buffer.from('EHLO '), Buffer.alloc(1 << 16, 0x41), Buffer.from('\r\n')]) }],
  }
}

function* addressProbes() {
  // address-rfc2821 / address-rfc2822 are in the monorepo; exercise them
  const addrs = [
    'a@b',
    '<>',
    '<a@b>',
    '<@a:b@c>', // source route
    '<"quoted"@b>',
    '<a..b@c>',
    '<a@[127.0.0.1]>',
    '<a@[IPv6:::1]>',
    '<a@b.c.d.e.f.g.h.i.j.k.l>',
    '<a@' + 'b'.repeat(256) + '>',
    '<a@b>SIZE=99999999999999999999',
    '<a@b> SIZE=abc',
    '<a@b> BODY=8BITMIME RET=HDRS',
    '<a@b> SMTPUTF8',
    '<\u{1f4a9}@example>',
    '<a@b' + String.fromCharCode(0) + '>',
    '<a@b> ORCPT=rfc822;<x@y>',
  ]
  for (const a of addrs) {
    yield { name: `mail-${addrSlug(a)}`, steps: [...baseGreet, cmd(`MAIL FROM:${a}`)] }
    yield { name: `rcpt-${addrSlug(a)}`, steps: [...baseGreet, cmd('MAIL FROM:<a@b>'), cmd(`RCPT TO:${a}`)] }
  }
}

function addrSlug(s) {
  return s.replace(/[^a-z0-9]+/gi, '_').slice(0, 32)
}

function* mutatedProbes(rng) {
  // Seed corpus, mutate, send as raw bytes after greeting
  const seeds = [
    'EHLO fuzz.local\r\n',
    'MAIL FROM:<a@b> SIZE=10 BODY=8BITMIME\r\n',
    'RCPT TO:<a@b> NOTIFY=SUCCESS,FAILURE\r\n',
    'AUTH PLAIN AGFkbWluAGFkbWlu\r\n',
    'STARTTLS\r\n',
    'VRFY postmaster\r\n',
  ]
  for (let i = 0; i < 25; i++) {
    const seed = seeds[Math.floor(rng() * seeds.length)]
    const mutated = mutate(Buffer.from(seed), { rng })
    yield { name: `mutated-${i}`, steps: [raw(mutated + '\r\n')] }
  }
}

// After a real <CRLF>.<CRLF>, anything pipelined before the DATA reply must be
// refused (503) or the connection dropped -- never answered as a new transaction.
// After a bare-LF line the message must be refused (451), never accepted.
function* receiveSideProbes() {
  const legitData = [...baseGreet, ...baseEnvelope, cmd('DATA')]
  const smuggledTail = 'MAIL FROM:<forged@example.test>\r\nRCPT TO:<victim@example.test>\r\nDATA\r\n'
  const senderOk = (transcript, after) =>
    transcript.some((t, i) => i > after && t.dir === 'S' && t.reply?.code === 250 && /sender/i.test(t.reply?.text ?? ''))
  const indexOfDataReply = (transcript) => transcript.findIndex((t) => t.dir === 'S' && [250, 550, 451, 452, 554].includes(t.reply?.code) && /queued|denied|fail|reject|too many|received/i.test(t.reply?.text ?? ''))

  yield {
    name: 'post-data-pipelined-transaction',
    steps: [...legitData, raw(`Subject: x\r\n\r\nbody\r\n.\r\n${smuggledTail}`), sleep(300), { type: 'expect' }, { type: 'expect' }, { type: 'expect' }, { type: 'expect' }],
    oracle: (transcript) => {
      const i = indexOfDataReply(transcript)
      return i !== -1 && senderOk(transcript, i) ? 'pipelined MAIL FROM after end-of-DATA answered 250' : null
    },
  }
  for (const [name, term] of [
    ['lf-dot-crlf', 'body\n.\r\n'],
    ['crlf-dot-lf', 'body\r\n.\n'],
    ['lf-dot-lf', 'body\n.\n'],
  ]) {
    yield {
      name: `terminator-${name}`,
      steps: [...legitData, raw(`Subject: x\r\n\r\n${term}${smuggledTail}`), sleep(300), { type: 'expect' }, { type: 'expect' }],
      oracle: (transcript) => {
        const accepted = transcript.some((t) => t.dir === 'S' && t.reply?.code === 250 && /queued/i.test(t.reply?.text ?? ''))
        if (accepted) return 'message accepted with a bare-LF end-of-DATA sequence'
        const i = transcript.findIndex((t) => t.dir === 'S' && t.reply?.code === 451)
        return i !== -1 && senderOk(transcript, i) ? 'commands after a bare-LF 451 were executed' : null
      },
    }
  }
}

function* all(rng) {
  yield* receiveSideProbes()
  yield* stateMachineProbes()
  yield* commandSyntaxProbes()
  yield* lineEndingProbes()
  yield* addressProbes()
  yield* mutatedProbes(rng)
}

module.exports = { all, sleep }

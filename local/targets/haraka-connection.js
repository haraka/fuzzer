'use strict'

// Haraka's SMTP receive side: connection.js from DATA state through end-of-DATA.
// Every bug in the 3.3.4 smuggling work lived here, and none of them threw, so
// the oracles below encode the invariants as TypeErrors the harness can see.
//
// Each input is fed twice: as one chunk, then split at pseudo-random offsets
// derived from the bytes themselves. The outcome must not depend on how TCP
// happened to segment the stream.

const path = require('node:path')

const ROOT = path.join(__dirname, '..', '..', '..', 'Haraka')
const MAX_POST_DATA_BYTES = 8192 // mirrors connection.js

const COMMANDS = ['mail', 'rcpt', 'data', 'rset', 'noop', 'help', 'quit', 'vrfy', 'ehlo', 'helo', 'auth', 'starttls']

function fnv(buf) {
  let h = 2166136261
  for (const b of buf) h = Math.imul(h ^ b, 16777619)
  return h >>> 0
}

function chunkOffsets(buf) {
  // deterministic per input, so a finding replays
  let s = fnv(buf) || 1
  const rng = () => ((s ^= s << 13), (s ^= s >>> 17), (s ^= s << 5), (s >>> 0) / 4294967296)
  const n = 1 + Math.floor(rng() * Math.min(8, Math.max(1, buf.length)))
  const cuts = new Set([0, buf.length])
  while (cuts.size < n + 1 && buf.length > 1) cuts.add(1 + Math.floor(rng() * (buf.length - 1)))
  return [...cuts].sort((a, b) => a - b)
}

function drive(mod, buf, offsets) {
  const { connection, Server, states } = mod
  const seen = { replies: [], commands: [], stored: [], data_done: 0, flagAtEnd: undefined }
  const c = connection.createConnection(
    {
      remotePort: 1,
      remoteAddress: '203.0.113.9',
      localPort: 25,
      localAddress: '10.0.0.1',
      destroy() {},
      end() {},
      pause() {},
      resume() {},
      write(b) {
        const code = String(b).slice(0, 3)
        if (/^\d{3}$/.test(code)) seen.replies.push(Number(code))
      },
    },
    { ip_address: null, address: () => null },
    Server.cfg,
  )
  c.esmtp = true
  c.state = states.DATA
  c.transaction = {
    data_bytes: 0,
    notes: {},
    header: { get_all: () => [] },
    header_lines: [],
    add_header() {},
    add_data: (l) => seen.stored.push(Buffer.from(l).toString('binary')),
    end_data() {}, // async in reality; leaving its callback unfired holds the post-DATA window open
  }
  c.auth_results = () => ''
  c.auth_results_clean = () => {}
  const data_done = c.data_done.bind(c)
  c.data_done = () => {
    seen.data_done++
    data_done()
    seen.flagAtEnd = c.transaction?.notes?.data_line_length_exceeded
  }
  for (const cmd of COMMANDS) c[`cmd_${cmd}`] = (a) => seen.commands.push(`${cmd.toUpperCase()} ${a ?? ''}`.trim())

  for (let i = 0; i < offsets.length - 1; i++) {
    if (c.state >= states.DISCONNECTING) break
    c.process_data(buf.subarray(offsets[i], offsets[i + 1]))
  }
  return {
    seen,
    ended: seen.data_done > 0,
    disconnected: c.state >= states.DISCONNECTING,
    buffered: c.current_data?.length ?? 0,
    awaiting: c.awaiting_data_reply === true,
    flagNow: c.transaction?.notes?.data_line_length_exceeded,
  }
}

function check(r) {
  const { seen } = r
  // 1. Nothing pipelined after end-of-DATA may run before the reply. The reply is
  //    never sent in this harness, so no command handler may fire at all.
  if (seen.commands.length) throw new TypeError(`command executed inside DATA/post-DATA window: ${seen.commands[0]}`)
  // 2. A bare-LF line is refused and dropped, never stored as content.
  const bareLf = seen.stored.find((l) => l.endsWith('\n') && !l.endsWith('\r\n'))
  if (bareLf !== undefined) throw new TypeError('bare-LF line stored as message content')
  if (seen.replies.includes(451) && !r.disconnected) throw new TypeError('451 for bare LF did not drop the connection')
  // 3. Only <CRLF>.<CRLF> ends DATA: if DATA ended, the last stored line ended in CRLF.
  if (r.ended && seen.stored.length && !seen.stored.at(-1).endsWith('\r\n')) {
    throw new TypeError('end-of-DATA accepted after a line without CRLF')
  }
  // 4. Bytes after the terminator are commands, not body: the line-length flag
  //    must not change once end-of-DATA has been seen.
  if (r.ended && r.flagNow !== seen.flagAtEnd) throw new TypeError('post-DATA bytes flagged the finished transaction')
  // 5. The post-DATA buffer is capped.
  if (r.awaiting && r.buffered > MAX_POST_DATA_BYTES && !r.disconnected) {
    throw new TypeError(`post-DATA buffer ${r.buffered}B exceeds cap without disconnect`)
  }
}

const shape = (r) => JSON.stringify({ ended: r.ended, disc: r.disconnected, replies: r.seen.replies, stored: r.seen.stored.length, buffered: r.buffered })

module.exports = {
  name: 'haraka-connection',
  seeds: [
    'Subject: hi\r\n\r\nbody\r\n.\r\n',
    'body\r\n.\r\nMAIL FROM:<forged@example.com>\r\nRCPT TO:<v@y>\r\nDATA\r\n',
    'body\n.\r\nMAIL FROM:<forged@example.com>\r\nRCPT TO:<v@y>\r\nDATA\r\n',
    'body\r\n.\nMAIL FROM:<x@y>\r\n',
    'body\r.\rMAIL FROM:<x@y>\r\n',
    'From: a@b\r\n..\r\nMAIL FROM:<e@x>\r\nRCPT TO:<v@y>\r\nDATA\r\n\r\nouter\r\n.\r\n',
    `.\r\nMAIL FROM:<${'a'.repeat(600)}@x>\r\nRCPT TO:<v@y>\r\nDATA\r\n`,
    `.\r\n${'A'.repeat(9000)}`,
    `.\r\n${'A'.repeat(5000)}`,
    `${'B'.repeat(2000)}\r\n.\r\n`,
    '\r\n\r\n.\r\n',
    '.\r\n',
    '',
  ],
  setup() {
    // keep the worker quiet: Haraka logs every 451/503 at NOTICE
    try {
      const logger = require(path.join(ROOT, 'logger'))
      if (typeof logger.loglevel === 'number') logger.loglevel = 0
    } catch {
      /* logger shape differs; noise is harmless */
    }
    const constants = require(path.join(ROOT, 'node_modules', 'haraka-constants'))
    return {
      connection: require(path.join(ROOT, 'connection')),
      Server: require(path.join(ROOT, 'server')),
      states: constants.connection.state,
    }
  },
  run(mod, input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input)
    const whole = drive(mod, buf, [0, buf.length])
    check(whole)
    const split = drive(mod, buf, chunkOffsets(buf))
    check(split)
    // 6. TCP segmentation must not change the outcome.
    if (shape(whole) !== shape(split)) throw new TypeError(`outcome depends on TCP chunking: ${shape(whole)} vs ${shape(split)}`)
  },
}

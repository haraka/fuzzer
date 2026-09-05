'use strict'

const path = require('node:path')

// The ctor-header path: header_list holds logical (dot-unstuffed) values that
// pipe() re-serialises for an SMTP sink. A bare "." emitted there is an
// end-of-DATA terminator, so the relay output must carry exactly one.
const HOSTILE_CTOR_HEADERS = [
  'From: a@b\n',
  '.\n',
  '..weird: v\n',
  '.foo: bar\n',
  'Subject: safe\rBcc: victim@example.test\n',
]

function relayRoundTrip(MessageStream, input) {
  return new Promise((resolve, reject) => {
    const ms = new MessageStream({ main: {} }, 'fuzz', [...HOSTILE_CTOR_HEADERS])
    const chunks = []
    const sink = new (require('node:stream').Writable)({
      write(c, _e, cb) {
        chunks.push(c)
        cb()
      },
    })
    sink.on('finish', () => {
      // The real invariant is positional: a bare "." may only be the final line.
      // An interior one is a smuggled end-of-DATA. Degenerate inputs legitimately
      // emit none, so counting is the wrong test.
      const lines = Buffer.concat(chunks).toString('binary').split('\r\n')
      const lastContent = lines.findLastIndex((l) => l.length > 0)
      const interior = lines.some((l, i) => l === '.' && i !== lastContent)
      if (interior) {
        return reject(new TypeError('relay emitted an interior end-of-DATA terminator'))
      }
      resolve()
    })
    ms.pipe(sink, { dot_stuffed: false, ending_dot: true, end: true })
    // Stored content is dot-stuffed by contract (transaction.js does this before
    // add_line), so stuff it here too. Otherwise arbitrary mutated bytes would
    // "fail" the terminator oracle for merely violating the input contract.
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input)
    for (const line of buf.toString('binary').split(/(?<=\n)/)) {
      if (!line.length) continue
      ms.add_line(Buffer.from(line.startsWith('.') ? `.${line}` : line, 'binary'))
    }
    ms.add_line_end()
  })
}

module.exports = {
  name: 'message-stream',
  seeds: [
    'Subject: hi\r\nFrom: a@b\r\nTo: c@d\r\n\r\nHello world',
    'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nA\r\n--b--',
    Buffer.alloc(1024, 0x41).toString('binary'),
    '',
    '\r\n\r\n\r\n',
    // dot-stuffed content, the shape that must survive a relay re-stuffed
    'Subject: hi\r\n\r\nbefore\r\n..\r\nafter\r\n',
    'Subject: hi\r\n\r\n..\r\n...\r\n....\r\n',
  ],
  setup() {
    return require(path.join(__dirname, '..', '..', '..', 'message-stream'))
  },
  async run(mod, input) {
    await relayRoundTrip(mod, input)
    return await new Promise((resolve, reject) => {
      const c = new mod.ChunkEmitter()
      c.on('data', () => {})
      c.on('error', reject)
      c.on('end', resolve)
      // Feed in unpredictable-sized chunks to exercise buffering
      const buf = Buffer.isBuffer(input) ? input : Buffer.from(input)
      let off = 0
      const step = Math.max(1, Math.min(buf.length, 17))
      while (off < buf.length) {
        c.fill(buf.subarray(off, off + step))
        off += step
      }
      c.end()
      // Some implementations don't emit 'end'; resolve on next tick as fallback
      setImmediate(resolve)
    })
  },
}

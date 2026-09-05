'use strict'

const cmd = (line) => ({ type: 'cmd', line })
const raw = (bytes) => ({ type: 'raw', bytes: Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes) })
const tlsUpgrade = () => ({ type: 'tls' })

const greet = cmd('EHLO fuzz.local')

function* all() {
  yield {
    name: 'starttls-then-plain',
    steps: [greet, cmd('STARTTLS'), cmd('EHLO not-tls.local')], // send plain bytes where TLS is expected
  }
  yield {
    name: 'starttls-then-garbage',
    steps: [greet, cmd('STARTTLS'), raw(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef]))],
  }
  yield {
    name: 'starttls-then-many-bytes',
    steps: [greet, cmd('STARTTLS'), raw(Buffer.alloc(8192, 0xa5))],
  }
  yield {
    name: 'starttls-with-arg',
    steps: [greet, cmd('STARTTLS foo')],
  }
  yield {
    name: 'double-starttls-plain',
    steps: [greet, cmd('STARTTLS'), cmd('STARTTLS')],
  }
  yield {
    name: 'starttls-mid-mail',
    steps: [greet, cmd('MAIL FROM:<a@b>'), cmd('STARTTLS')],
  }
  yield {
    name: 'starttls-mid-data',
    steps: [
      greet,
      cmd('MAIL FROM:<a@b>'),
      cmd('RCPT TO:<c@d>'),
      cmd('DATA'),
      raw(Buffer.from('Subject: x\r\n\r\nbody\r\nSTARTTLS\r\n.\r\n')),
    ],
  }
  yield {
    name: 'tls-then-double-starttls',
    steps: [greet, cmd('STARTTLS'), tlsUpgrade(), cmd('EHLO secure.local'), cmd('STARTTLS')],
  }
  yield {
    name: 'tls-then-noop-flood',
    steps: [
      greet,
      cmd('STARTTLS'),
      tlsUpgrade(),
      cmd('EHLO secure.local'),
      ...Array.from({ length: 50 }, () => cmd('NOOP')),
    ],
  }
}

module.exports = { all }

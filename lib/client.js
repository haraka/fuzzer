'use strict'

const net = require('node:net')
const tls = require('node:tls')
const { EventEmitter } = require('node:events')

const CRLF = '\r\n'

class SmtpRawClient extends EventEmitter {
  constructor({ host, port, timeout = 5000, tlsOpts = {} } = {}) {
    super()
    this.host = host
    this.port = port
    this.timeout = timeout
    this.tlsOpts = { rejectUnauthorized: false, ...tlsOpts }
    this.sock = null
    this.buf = Buffer.alloc(0)
    this.transcript = []
    this.connectedAt = null
    this.closedAt = null
    this.closeReason = null
  }

  connect() {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: this.host, port: this.port })
      sock.setTimeout(this.timeout)
      this._attach(sock)
      const onErr = (err) => {
        this.closeReason = `connect:${err.code || err.message}`
        reject(err)
      }
      sock.once('error', onErr)
      sock.once('connect', () => {
        sock.off('error', onErr)
        this.connectedAt = Date.now()
        resolve(this._readResponse())
      })
    })
  }

  _attach(sock) {
    this.sock = sock
    sock.on('data', (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk])
      this.emit('data', chunk)
    })
    sock.on('timeout', () => {
      this.closeReason = 'timeout'
      sock.destroy(new Error('socket timeout'))
    })
    sock.on('close', () => {
      this.closedAt = Date.now()
      this.emit('close')
    })
    sock.on('error', (err) => {
      if (!this.closeReason) this.closeReason = `error:${err.code || err.message}`
    })
  }

  // Send raw bytes; caller is responsible for CRLF
  sendRaw(bytes) {
    if (!this.sock || this.sock.destroyed) {
      throw new Error('socket not open')
    }
    const payload = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)
    this.transcript.push({ dir: 'C', t: Date.now(), bytes: payload })
    return new Promise((resolve, reject) => {
      this.sock.write(payload, (err) => (err ? reject(err) : resolve()))
    })
  }

  // Send a command followed by CRLF and read one SMTP reply
  async cmd(line) {
    await this.sendRaw(line + CRLF)
    return this._readResponse()
  }

  // Read a multi-line SMTP reply (lines ending CRLF; continuation has "NNN-")
  _readResponse() {
    return new Promise((resolve, reject) => {
      const t0 = Date.now()
      const tryParse = () => {
        const text = this.buf.toString('utf8')
        const lines = text.split(CRLF)
        // Find a terminator line matching /^\d{3} /
        let end = -1
        for (let i = 0; i < lines.length - 1; i++) {
          if (/^\d{3} /.test(lines[i])) {
            end = i
            break
          }
        }
        if (end >= 0) {
          const reply = lines.slice(0, end + 1).join(CRLF)
          this.buf = Buffer.from(lines.slice(end + 1).join(CRLF), 'utf8')
          const code = parseInt(reply.slice(0, 3), 10)
          const result = { code, text: reply, latencyMs: Date.now() - t0 }
          this.transcript.push({ dir: 'S', t: Date.now(), reply: result })
          cleanup()
          resolve(result)
          return
        }
        // If socket closed without a complete reply
        if (!this.sock || this.sock.destroyed) {
          cleanup()
          resolve({ code: 0, text: this.buf.toString('utf8'), closed: true, latencyMs: Date.now() - t0 })
        }
      }
      const onData = () => tryParse()
      const onClose = () => tryParse()
      const onErr = (err) => {
        cleanup()
        reject(err)
      }
      const cleanup = () => {
        this.off('data', onData)
        this.off('close', onClose)
        if (this.sock) this.sock.off('error', onErr)
      }
      this.on('data', onData)
      this.on('close', onClose)
      if (this.sock) this.sock.on('error', onErr)
      tryParse()
    })
  }

  async upgradeTls() {
    if (!this.sock) throw new Error('no socket')
    const plain = this.sock
    plain.removeAllListeners('data')
    plain.removeAllListeners('timeout')
    plain.removeAllListeners('close')
    plain.removeAllListeners('error')
    this.buf = Buffer.alloc(0)
    return await new Promise((resolve, reject) => {
      const sock = tls.connect({ socket: plain, ...this.tlsOpts }, () => {
        this._attach(sock)
        resolve(sock)
      })
      sock.once('error', reject)
      sock.setTimeout(this.timeout)
    })
  }

  close() {
    if (this.sock && !this.sock.destroyed) {
      try {
        this.sock.end()
      } catch {
        /* ignore */
      }
      this.sock.destroy()
    }
  }
}

module.exports = { SmtpRawClient, CRLF }

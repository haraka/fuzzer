'use strict'

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const ROOT = path.join(__dirname, '..', '..', '..', 'haraka-config')

const SEED_INI = [
  '[main]',
  'host=mail.example.com',
  'port=25',
  'reject=true',
  '',
  '[users]',
  'matt=test',
  'list[]=a',
  'list[]=b',
  '; comment',
  'long = value \\',
  '  continued',
  '',
].join('\n')

const SEED_YAML = ['main:', '  host: mail.example.com', '  ports: [25, 587]', 'users: &u', '  matt: test', 'again: *u', ''].join(
  '\n',
)

const SEED_JSON = JSON.stringify({ main: { host: 'mail.example.com', port: 25 }, '!smtp.ini': { main: { x: 1 } } }, null, 2)

const SEED_LIST = ['# hosts', 'mx1.example.com', '', '  mx2.example.com  ', ''].join('\n')

const SEED_HOSTILE_INI = [
  '[__proto__]',
  'polluted=yes',
  '[users]',
  '__proto__=x',
  'constructor=x',
  'prototype=x',
  '.=x',
  '..=x',
  'toString=x',
  '[constructor]',
  'polluted=yes',
  '',
].join('\n')

const INHERITED = [
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
]

// a parser cleanly rejecting bad input
const isParseError = (e) =>
  e instanceof SyntaxError || /YAML/.test(e.name) || (e instanceof ReferenceError && /alias|anchor/i.test(e.message))

module.exports = {
  name: 'haraka-config',
  seeds: [SEED_INI, SEED_YAML, SEED_JSON, SEED_LIST, SEED_HOSTILE_INI],
  setup() {
    const ini = require(path.join(ROOT, 'lib', 'readers', 'ini'))
    const flat = require(path.join(ROOT, 'lib', 'readers', 'flat'))
    const structured = require(path.join(ROOT, 'lib', 'readers', 'structured'))
    ini.logger = structured.logger = () => {}
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-config-fuzz-')), 'input')
    return { ini, flat, structured, file }
  },
  async run(mod, input) {
    const text = input.toString('utf8')
    const parsed = mod.ini.parseIni('fuzz.ini', { booleans: ['+main.reject', '*.enabled', '-users.matt'] }, text)
    // Read-side oracle: a key that was never configured must not resolve to an
    // inherited Object.prototype member (the open-relay class in auth/flat_file).
    for (const section of Object.values(parsed)) {
      if (!section || typeof section !== 'object') continue
      for (const name of INHERITED) {
        if (!Object.hasOwn(section, name) && section[name] !== undefined) {
          throw new TypeError(`inherited member reachable on a config section: ${name}`)
        }
      }
    }
    for (const name of INHERITED) {
      if (!Object.hasOwn(parsed, name) && parsed[name] !== undefined) {
        throw new TypeError(`inherited member reachable on the config root: ${name}`)
      }
    }
    for (const type of ['value', 'list', 'data']) {
      mod.flat.parseValue('/etc/haraka/config/me', type, { booleans: ['true'] }, text)
    }
    fs.writeFileSync(mod.file, input)
    for (const type of ['json', 'yaml']) {
      try {
        mod.structured.load(mod.file, type)
      } catch (e) {
        if (!isParseError(e)) throw e
      }
    }
    if ({}.polluted !== undefined || Object.keys(Object.prototype).length) throw new TypeError('prototype pollution')
  },
}

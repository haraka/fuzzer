'use strict'

const path = require('node:path')

module.exports = {
  name: 'tld',
  seeds: [
    'example.com',
    'foo.bar.example.com',
    'a.b.c.d.e.f.g.h.i.j.k.l',
    'example.co.uk',
    'foo.gov.uk',
    'a.b.c.compute.amazonaws.com',
    'xn--80akhbyknj4f.xn--p1ai', // IDN
    '.com',
    'com.',
    '',
    '.',
    '..',
    '.example.com.',
    'localhost',
    'a'.repeat(256) + '.com',
    'sub.' + 'a'.repeat(60) + '.example.com',
  ],
  setup() {
    return require(path.join(__dirname, '..', '..', '..', 'tld'))
  },
  async ready(mod) {
    if (mod.ready) await mod.ready
  },
  async run(mod, input) {
    const s = input.toString('utf8')
    mod.split_hostname(s)
    mod.split_hostname(s, 2)
    mod.split_hostname(s, 3)
    mod.get_organizational_domain(s)
    mod.is_public_suffix(s)
  },
}

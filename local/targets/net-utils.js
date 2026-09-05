'use strict'

const path = require('node:path')

module.exports = {
  name: 'net-utils',
  seeds: [
    '127.0.0.1',
    '0.0.0.0',
    '255.255.255.255',
    '::1',
    'fe80::1%eth0',
    '2001:db8::1',
    '::ffff:192.0.2.1',
    '10.0.0.0/8',
    'not-an-ip',
    '1.2.3.4.5',
    '999.999.999.999',
    'fe80:0:0:0:0:0:0:0:0',
    '[::1]:25',
    '0.0.0.0:0',
    '',
    'a'.repeat(256),
  ],
  setup() {
    return require(path.join(__dirname, '..', '..', '..', 'net-utils'))
  },
  async run(mod, input) {
    const s = input.toString('utf8')
    // These classifiers are documented to return booleans / parsed values,
    // not throw. Any thrown exception below is the finding we care about.
    mod.is_ip_in_str(s, '127.0.0.1')
    mod.ip_to_long(s)
    mod.long_to_ip(parseInt(s, 10) >>> 0)
    mod.is_ip_literal(s)
    mod.is_ipv4_literal(s)
    mod.is_private_ip(s)
    mod.is_local_ip(s)
    mod.is_rfc1918(s)
    mod.ipv6_reverse(s)
    mod.ipv6_bogus(s)
    mod.octets_in_string(s, 1, 4)
    const re = mod.get_ipany_re()
    if (re && typeof re.exec === 'function') re.exec(s)
  },
}

const { Key } = require('js-crypto-key-utils')
const asn1def = require('js-crypto-key-utils/dist/asn1def')

const applyOptions = require('../help/apply_options')
const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const sign = require('../help/sign')

function checkKey (pem) {
  try {
    const key = new Key('pem', pem)
    const decoded = asn1def.KeyStructure.decode(Buffer.from(key._der))

    // Strip off first two bytes 0x04 0x20 https://tools.ietf.org/html/rfc8410#section-10.3
    const privateKey = decoded.value.privateKey.slice(2)
    return Buffer.from(privateKey)
  } catch (err) {
    throw new TypeError('v2.public signing key must be a private ed25519 key')
  }
}

module.exports = async function v2Sign (payload, key, { footer, ...options } = {}) {
  payload = checkPayload(payload)
  const f = checkFooter(footer)
  payload = applyOptions(options, payload)
  key = checkKey(key)
  return sign('v2.public.', payload, f, undefined, key, 64)
}

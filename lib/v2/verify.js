const { Key } = require('js-crypto-key-utils')
const asn1def = require('js-crypto-key-utils/dist/asn1def')

const assertPayload = require('../help/assert_payload')
const verify = require('../help/verify')

function checkKey (pem) {
  try {
    const key = new Key('pem', pem)
    const decoded = asn1def.KeyStructure.decode(Buffer.from(key._der))
    return decoded.value.subjectPublicKey.data
  } catch (err) {
    throw new TypeError('v2.public verify key must be a public ed25519 key')
  }
}

module.exports = async function v2Verify (token, key, { complete = false, ...options } = {}) {
  key = checkKey(key)

  const { payload, footer } = await verify('v2.public.', token, undefined, 64, key)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v2', purpose: 'public' }
  }

  return payload
}

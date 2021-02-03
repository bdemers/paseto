const { decode } = require('../help/base64url')
const { 'aes-256-ctr-hmac-sha-384-decrypt': decrypt } = require('../help/crypto_worker')
const { PasetoDecryptionFailed, PasetoInvalid } = require('../errors')
const assertPayload = require('../help/assert_payload')
const checkKey = require('../help/symmetric_key_check')
const parse = require('../help/parse_paseto_payload')

const h = 'v1.local.'

module.exports = async function v1Decrypt (token, key, { complete = false, ...options } = {}) {
  if (typeof token !== 'string') {
    throw new TypeError(`token must be a string, got: ${typeof token}`)
  }

  key = checkKey('v1.local', key)

  if (token.substr(0, h.length) !== h) {
    throw new PasetoInvalid('token is not a v1.local PASETO')
  }

  const { 0: b64, 1: b64f = '', length } = token.substr(h.length).split('.')
  if (length > 2) {
    throw new PasetoInvalid('token value is not a PASETO formatted value')
  }

  const f = decode(b64f)
  const raw = decode(b64)

  let payload = await decrypt(raw, f, key)
  if (!payload) {
    throw new PasetoDecryptionFailed('decryption failed')
  }

  payload = parse(payload)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer: f.length ? f : undefined, version: 'v1', purpose: 'local' }
  }

  return payload
}

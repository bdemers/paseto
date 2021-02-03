const applyOptions = require('../help/apply_options')
const checkFooter = require('../help/check_footer')
const checkKey = require('../help/symmetric_key_check')
const checkPayload = require('../help/check_payload')
const randomBytes = require('../help/random_bytes')
const { 'aes-256-ctr-hmac-sha-384-encrypt': encrypt } = require('../help/crypto_worker')

module.exports = async function v1Encrypt (payload, key, { footer, nonce, ...options } = {}) {
  payload = checkPayload(payload)
  key = checkKey('v1.local', key)
  const f = checkFooter(footer)
  payload = applyOptions(options, payload)

  const m = Buffer.from(JSON.stringify(payload), 'utf8')

  if ((nonce && process.env.NODE_ENV !== 'test') || !nonce) {
    nonce = await randomBytes(32)
  }

  return encrypt(m, f, key, nonce)
}

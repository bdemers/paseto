const {
  constants: {
    RSA_PKCS1_PSS_PADDING: padding,
    RSA_PSS_SALTLEN_DIGEST: saltLength
  }
} = require('crypto')
const { subtle } = require('../help/subtle')

const applyOptions = require('../help/apply_options')
const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const sign = require('../help/sign')

async function checkKey (key) {
  const pemHeader = '-----BEGIN PRIVATE KEY-----'
  const pemFooter = '-----END PRIVATE KEY-----'
  const pemContents = key.substring(pemHeader.length, key.length - pemFooter.length)
  const binaryDerString = Buffer.from(pemContents, 'base64')

  return subtle.importKey('pkcs8', Buffer.from(binaryDerString), { name: 'RSA-PSS', hash: { name: 'SHA-384' } }, false, ['sign'])
    // eslint-disable-next-line handle-callback-err
    .catch(() => {
      throw new TypeError('v1.public signing key must be a private RSA key')
    })
}

module.exports = async function v1Sign (payload, key, { footer, ...options } = {}) {
  payload = checkPayload(payload)
  const f = checkFooter(footer)
  payload = applyOptions(options, payload)
  key = await checkKey(key)
  return sign('v1.public.', payload, f, 'sha384', { key, padding, saltLength }, 256)
}

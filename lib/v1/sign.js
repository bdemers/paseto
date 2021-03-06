const {
  constants: {
    RSA_PKCS1_PSS_PADDING: padding,
    RSA_PSS_SALTLEN_DIGEST: saltLength
  },
  createPrivateKey,
  KeyObject
} = require('crypto')

const applyOptions = require('../help/apply_options')
const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const sign = require('../help/sign')

function checkKey (key) {
  if (!(key instanceof KeyObject)) {
    key = createPrivateKey(key)
  }

  if (key.type !== 'private' || key.asymmetricKeyType !== 'rsa') {
    throw new TypeError('v1.public signing key must be a private RSA key')
  }

  return key
}

module.exports = async function v1Sign (payload, key, { footer, ...options } = {}) {
  payload = checkPayload(payload)
  const f = checkFooter(footer)
  payload = applyOptions(options, payload)
  key = checkKey(key)
  return sign('v1.public.', payload, f, 'sha384', { key, padding, saltLength }, 256)
}

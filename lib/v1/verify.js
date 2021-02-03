const {
  constants: {
    RSA_PKCS1_PSS_PADDING: padding,
    RSA_PSS_SALTLEN_DIGEST: saltLength
  }
} = require('crypto')
const { subtle } = require('../help/subtle')

const assertPayload = require('../help/assert_payload')
const verify = require('../help/verify')

async function checkKey (key) {
  const pemHeader = '-----BEGIN PUBLIC KEY-----'
  const pemFooter = '-----END PUBLIC KEY-----'
  const pemContents = key.substring(pemHeader.length, key.length - pemFooter.length)
  const binaryDerString = Buffer.from(pemContents, 'base64')

  return subtle.importKey('spki', Buffer.from(binaryDerString), { name: 'RSA-PSS', hash: { name: 'SHA-384' } }, false, ['verify'])
    // eslint-disable-next-line handle-callback-err
    .catch(() => {
      throw new TypeError('v1.public verify key must be a public RSA key')
    })
}

module.exports = async function v1Verify (token, key, { complete = false, ...options } = {}) {
  key = await checkKey(key)

  const { payload, footer } = await verify('v1.public.', token, { name: 'RSA-PSS', saltLength: 48 }, 256, { key, padding, saltLength })

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v1', purpose: 'public' }
  }

  return payload
}

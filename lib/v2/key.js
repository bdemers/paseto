// const crypto = require('crypto')
const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')
const randomBytes = require('../help/random_bytes')

const LOCAL_KEY_LENGTH = 32

if (crypto.generateKeyPair) {
  const generateKeyPair = promisify(crypto.generateKeyPair)

  // eslint-disable-next-line no-inner-declarations
  async function generateKey (purpose) {
    switch (purpose) {
      case 'local':
        return crypto.createSecretKey(await randomBytes(LOCAL_KEY_LENGTH))
      case 'public': {
        const { privateKey } = await generateKeyPair('ed25519')
        return privateKey
      }
      default:
        throw new PasetoNotSupported('unsupported v2 purpose')
    }
  }

  module.exports = generateKey
}

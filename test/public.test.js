const test = require('ava')
const crypto = require('crypto')
const { promisify } = require('util')
const generateKeyPair = promisify(crypto.generateKeyPair)

const { errors, V1, V2 } = require('../lib')

const v2PublicKeyPemA = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
-----END PUBLIC KEY-----`

const v2PublicKeyPemB = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAs0kXpQzWgdhugfWIYAR8gJZkZoBZKkQ0XgeI4eTyac0=
-----END PUBLIC KEY-----`

const v2PrivateKeyPemA = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0
-----END PRIVATE KEY-----`

const v2PrivateKeyPemB = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILE5cU4bMGOPg4AKATdkfcTsWvyURYg2hLLtkdhXnS2t
-----END PRIVATE KEY-----`

test('V1.sign needs a RSA key', async t => {
  return t.throwsAsync(
    V1.sign({}, v2PublicKeyPemA),
    { instanceOf: TypeError, message: 'v1.public signing key must be a private RSA key' }
  )
})

test('V1.sign needs a private key', async t => {
  const { publicKey } = await generateKeyPair('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  })

  return t.throwsAsync(
    V1.sign({}, publicKey),
    { instanceOf: TypeError, message: 'v1.public signing key must be a private RSA key' }
  )
})

test('V2.sign needs a ed25519 key', async t => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(
    V2.sign({}, privateKey),
    { instanceOf: TypeError, message: 'v2.public signing key must be a private ed25519 key' }
  )
})

test('V2.sign needs a private key', async t => {
  const { publicKey } = await generateKeyPair('ed25519')
  return t.throwsAsync(
    V2.sign({}, publicKey),
    { instanceOf: TypeError, message: 'v2.public signing key must be a private ed25519 key' }
  )
})

test('V1.verify invalid PEM', async t => {
  const invalidPem = '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n' +
    '-----END PUBLIC KEY-----'
  return t.throwsAsync(
    V1.verify({}, invalidPem),
    { instanceOf: TypeError, message: 'v1.public verify key must be a public RSA key' }
  )
})

test('V2.verify invalid PEM', async t => {
  const invalidPem = '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n' +
    '-----END PUBLIC KEY-----'
  return t.throwsAsync(
    V2.verify({}, invalidPem),
    { instanceOf: TypeError, message: 'v2.public verify key must be a public ed25519 key' }
  )
})

test('token must be a string', async t => {
  return t.throwsAsync(
    V2.verify(1, v2PublicKeyPemA),
    { instanceOf: TypeError, message: 'token must be a string' }
  )
})

test('token must be a a valid paseto', async t => {
  return t.throwsAsync(
    V2.verify('v2.public...', v2PublicKeyPemA),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token value is not a PASETO formatted value' }
  )
})

test('invalid RSA key length for v1.public', async t => {
  const { privateKey } = await generateKeyPair('rsa', {
    modulusLength: 1024,
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })
  await t.throwsAsync(
    V1.sign({}, privateKey),
    { instanceOf: TypeError, message: 'invalid v1.public signing key bit length' }
  )
})

test('v1 must validate with the right key', async t => {
  const { privateKey } = await generateKeyPair('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })
  const { publicKey } = await generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  })

  const token = await V1.sign({}, privateKey)

  return t.throwsAsync(
    V1.verify(token, publicKey),
    { instanceOf: errors.PasetoVerificationFailed, code: 'ERR_PASETO_VERIFICATION_FAILED', message: 'invalid signature' }
  )
})

test('v2 must validate with the right key', async t => {
  const k = v2PrivateKeyPemA
  const k2 = v2PublicKeyPemB

  const token = await V2.sign({}, k)

  return t.throwsAsync(
    V2.verify(token, k2),
    { instanceOf: errors.PasetoVerificationFailed, code: 'ERR_PASETO_VERIFICATION_FAILED', message: 'invalid signature' }
  )
})

test('v2 doesnt validate v1', async t => {
  const { privateKey } = await generateKeyPair('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })
  const k2 = v2PublicKeyPemB

  const token = await V1.sign({}, privateKey)

  return t.throwsAsync(
    V2.verify(token, k2),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token is not a v2.public token' }
  )
})

test('v1 doesnt validate v2', async t => {
  const { publicKey } = await generateKeyPair('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  })
  const k2 = v2PrivateKeyPemB

  const token = await V2.sign({}, k2)

  return t.throwsAsync(
    V1.verify(token, publicKey),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token is not a v1.public token' }
  )
})

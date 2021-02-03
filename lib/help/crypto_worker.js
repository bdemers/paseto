const crypto = require('crypto')
const sodium = require('libsodium-wrappers')
const { subtle } = require('./subtle')

const [major, minor] = process.version.substr(1).split('.').map((x) => parseInt(x, 10))
const supportsKeyObjectInPostMessage = major > 14 || (major === 14 && minor >= 5) || (major === 12 && minor >= 19)

const pae = require('./pae')
const hkdf = (key, length, salt, info) => {
  const prk = methods.hmac('sha384', key, salt)

  const u = Buffer.from(info)

  let t = Buffer.from('')
  let lb = Buffer.from('')
  let i

  for (let bi = 1; Buffer.byteLength(t) < length; ++i) {
    i = Buffer.from(String.fromCharCode(bi))
    const inp = Buffer.concat([lb, u, i])

    lb = methods.hmac('sha384', inp, prk)
    t = Buffer.concat([t, lb])
  }

  return Buffer.from(t).slice(0, length)
}

const pack = require('./pack')
const timingSafeEqual = require('./timing_safe_equal')

const methods = {
  'aes-256-ctr-hmac-sha-384-encrypt' (m, f, k, nonce) {
    let n = methods.hmac('sha384', m, nonce)
    n = n.slice(0, 32)
    f = Buffer.from(f)

    const salt = n.slice(0, 16)
    const ek = hkdf(k, 32, salt, 'paseto-encryption-key')
    const ak = hkdf(k, 32, salt, 'paseto-auth-key-for-aead')

    const c = methods.encrypt('aes-256-ctr', m, ek, n.slice(16))
    const preAuth = pae('v1.local.', n, c, f)
    const t = methods.hmac('sha384', preAuth, ak)

    return pack('v1.local.', [n, c, t], f)
  },
  'aes-256-ctr-hmac-sha-384-decrypt' (raw, f, k) {
    const n = raw.slice(0, 32)
    const t = raw.slice(-48)
    const c = raw.slice(32, -48)

    const salt = n.slice(0, 16)
    const ek = hkdf(k, 32, salt, 'paseto-encryption-key')
    const ak = hkdf(k, 32, salt, 'paseto-auth-key-for-aead')

    const preAuth = pae('v1.local.', n, c, f)

    const t2 = methods.hmac('sha384', preAuth, ak)
    const payload = methods.decrypt('aes-256-ctr', c, ek, n.slice(16))

    if (!timingSafeEqual(t, t2) || !payload) {
      return false
    }

    return payload
  },
  hmac (alg, payload, key) {
    const hmac = crypto.createHmac(alg, key)
    hmac.update(payload)
    return hmac.digest()
  },
  async verify (alg, payload, key, signature) {
    if (key.key) {
      return await subtle.verify(alg, key.key, signature, payload)
    } else {
      return sodium.crypto_sign_verify_detached(signature, payload, key)
    }
  },
  sign (alg, payload, key) {
    if (!supportsKeyObjectInPostMessage) {
      key.key = Buffer.from(key.key)
    }
    return crypto.sign(alg, payload, key)
  },
  encrypt (cipher, cleartext, key, iv) {
    const encryptor = crypto.createCipheriv(cipher, key, iv)
    return Buffer.concat([encryptor.update(cleartext), encryptor.final()])
  },
  decrypt (cipher, ciphertext, key, iv) {
    try {
      const decryptor = crypto.createDecipheriv(cipher, key, iv)
      return Buffer.concat([decryptor.update(ciphertext), decryptor.final()])
    } catch (err) {
      return false
    }
  },
  'xchacha20-poly1305-encrypt' (cleartext, nonce, key, footer) {
    const n = sodium.crypto_generichash(24, cleartext, nonce)
    const preAuth = pae('v2.local.', n, footer)
    try {
      const result = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cleartext, preAuth, undefined, n, key)
      return {
        n,
        c: result
      }
    } catch (err) {
      return false
    }
  },
  'xchacha20-poly1305-decrypt' (ciphertext, nonce, key, preAuth) {
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(undefined, ciphertext, preAuth, nonce, key)
    } catch (err) {
      return false
    }
  }
}

function wrapBuffer (buf) {
  return (buf) ? Buffer.from(buf) : buf
}

module.exports.sign = async function (...args) {
  await sodium.ready
  return Buffer.from(methods.sign(...args))
}

module.exports.verify = async function (...args) {
  await sodium.ready
  return methods.verify(...args)
}

module.exports['aes-256-ctr-hmac-sha-384-encrypt'] = async function (...args) {
  await sodium.ready
  return methods['aes-256-ctr-hmac-sha-384-encrypt'](...args)
}

module.exports['aes-256-ctr-hmac-sha-384-decrypt'] = async function (...args) {
  await sodium.ready
  return wrapBuffer(methods['aes-256-ctr-hmac-sha-384-decrypt'](...args))
}

module.exports['xchacha20-poly1305-encrypt'] = async function (...args) {
  await sodium.ready
  const result = methods['xchacha20-poly1305-encrypt'](...args)
  if (result) {
    result.n = wrapBuffer(result.n)
    result.c = wrapBuffer(result.c)
  }
  return result
}

module.exports['xchacha20-poly1305-decrypt'] = async function (...args) {
  await sodium.ready
  return wrapBuffer(methods['xchacha20-poly1305-decrypt'](...args))
}

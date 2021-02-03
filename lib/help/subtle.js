const crypto = require('crypto')

if (crypto.webcrypto) {
  const { subtle } = require('crypto').webcrypto
  module.exports.subtle = subtle
} else {
  module.exports.subtle = window.crypto.subtle
}

const paddedBuffer = (input, length) => {
  if (input.length === length) {
    return input
  }

  const buffer = Buffer.alloc(length)
  input.copy(buffer)
  return buffer
}

const timingSafeEqual = (a, b) => {
  const length = Math.max(a.length, b.length)

  const paddedA = paddedBuffer(a, length)
  const paddedB = paddedBuffer(b, length)

  let matches = 0
  for (let i = 0; i < length; i++) {
    matches |= paddedA[i] ^ paddedB[i]
  }
  return matches === 0
}

module.exports = timingSafeEqual

# paseto

> [PASETO](https://paseto.io): <strong>P</strong>latform-<strong>A</strong>gnostic <strong>SE</strong>curity <strong>TO</strong>kens for Node.js with minimal dependencies

**NOTE:** This is a fork of [panva/paseto](https://github.com/panva/paseto) which adds browser support 

## Documentation

- [API Documentation][documentation]
  - [PASETO Protocol Version v2][documentation-v2]
  - [PASETO Protocol Version v1][documentation-v1]

## Usage

For its improvements in the crypto module ⚠️ the minimal Node.js version required is **v15.5.0** ⚠️

Installing paseto

```console
npm install paseto
```

Usage
```js
const paseto = require('paseto')

// Generic (all versions) APIs
const { decode } = paseto

// PASETO Protocol Version v1 specific API
const { V1 } = paseto // { sign, verify, encrypt, decrypt, generateKey }

// PASETO Protocol Version v2 specific API
const { V2 } = paseto // { sign, verify, encrypt, decrypt, generateKey }

// errors utilized by paseto
const { errors } = paseto
```

#### Producing tokens

```js
const { V2: { encrypt, sign } } = paseto

(async () => {
  {
    const token = await encrypt({ sub: 'johndoe' }, secretKey)
    // v2.local.rRfHP25HDj5Pda40FwdTsGcsEMoQAKM6ElH6OhCon6YzG1Pzmj1ZPAHORhPaxKQo0XLM5LPYgaevWGrkEy2Os3N68Xee_Me9A0LmbMlV6MNVt-UZMos7ETha
  }
  {
    const token = await sign({ sub: 'johndoe' }, privateKey)
    // v2.public.eyJzdWIiOiJqb2huZG9lIiwiaWF0IjoiMjAxOS0wNy0wMVQxNToyMTozMS40OTJaIn0tpEwuwb-loL652KAZhmCYdDUNW8YbF6UYCFCYLk-fexhzs2ofL4AyHTqIk0HzIxawufEibT1ZyJ7MPBJUVpsF
  }
})()
```

#### Consuming tokens

```js
const { V2: { decrypt, verify } } = paseto

(async () => {
  {
    const payload = await decrypt(token, secretKey)
    // { sub: 'johndoe', iat: '2019-07-01T15:22:47.982Z' }
  }
  {
    const payload = await verify(token, publicKey)
    // { sub: 'johndoe', iat: '2019-07-01T15:22:47.982Z' }
  }
})()
```

#### Keys

TODO:


[documentation]: https://github.com/panva/paseto/blob/master/docs/README.md
[documentation-v2]: https://github.com/panva/paseto/blob/master/docs/README.md#v2-paseto-protocol-version-v2
[documentation-v1]: https://github.com/panva/paseto/blob/master/docs/README.md#v1-paseto-protocol-version-v1
[support-sponsor]: https://github.com/sponsors/panva

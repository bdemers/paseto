const test = require('ava')

const privateRsaKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJpOBO3nemHenk
YeDCgZbDPmFF9ZdJADTw0I7B7QUSAAtaiz0YKM0UJ3vbecIfEG03Wp3vgxKH+43z
wk8hvDEqF4OniTGjhgw3m2s9oXR70boGPU3TYedqfEUtb6CYtuBg79Jlh9YX8zzI
sFy7ljU63RnEMMNdL3AhBO0ETSd7dhvGBkkBlNTlerJDUPF3NjILmUXrIFpHlRC0
JhOdcAClVG5QjZJ3ovUTa+X1tIG6Znkik3GRGcDAgyN5MkH/QAgQuHSYTm/B2KE4
Jt1XpqVTKEoLX7XD8VbodZyn8kbWQoLwM8iJ1nvwFuq/1gXOQBs2eLl5IE6xdUEo
bvxmxzyjAgMBAAECggEAXbaMsNrfjIp2ezep93u2j4LcPmFHMBwyfoDO9/2pz5XJ
sQjpGeNMfENlYrkRqNI/j+xDXl7yK9STQmhZ0nnd94v6GdC/CxpvbyCCFKCGvEza
QbAYDVeA75JVrCom3xKO8T5D7//TVkorQ7IDRwMmNfcv1Gg9Q3+agx4A8XDSGqQU
SGbvYZJUIRjV5j5w5eYveJzGeyeVQP/9JL2rfdHEXbLmiJbV52pxGqFb/svXJgxv
EcVRzFaHxZTCOfUACGgI5TMXxkH7Rf88+H7WdiirrHCovRkoPCtDxIOFb+s0Mt47
2CJzmuXsR61FBFsW+xnjQB2xfbBT6VYVSQHjYCO6gQKBgQDnP8JeoMV9nwxcI8A5
66LzLkc0O27fRpH4c5ewEOdEjyG5ewY0PTgV+ZdHueSCGvTx8VUOYTg94pSTzXRg
lv4gAmjzCs5nTrzafrIQw7nyiaoqKf6IhRWs9ctIujkIKGurDYni+DOiXM/Dc3kj
wUl0uiZv0WStXzgf4i+I8jKXIQKBgQDfOfAAbb1BfoBMR8WkZU5yiCiscKe13ieJ
pYKrmd7mwUv4TAt5VzXMP3KPVrFwN6UgINnEJnKdTuQOetBwWRPRuMf+ALwmTe/t
dP2XVQMOoLVvuub9fnAUhn+uY1rWtVmEvWj+0rHm28zazInWr3m/s13KAUgQhb6p
sgptzpbPQwKBgGxRl1AP6rH/ECEQtffrgjZ6lOvIcxSuz60bKBBWup2Ilfl1wOAz
VNQmR1BXqMuwqM+zhW3o6BlEyue4syyTTZHczyAZDbmiTh/ifLIRnEYZadW6Ofnk
rNSJhaEZaaGCnXxQKShhrn39D2yz6ChxX2EH2P1Dje8PzRBSOIXjPQNBAoGALtdB
fVWJuQyKb3dACdcYNwBLSKP7DTaopUGNweRv2YwGHPwYDEY4i7tklp9ibGHAzJUY
HQjUVB4RzNgIlQqcFg3oKWyODpucFP/PlsnH8nHWoLNfdSHq8uOmNzmx/gvf1PLJ
7W7Y1dCZk/AHnH0F1ywUKidKr+zgrUsm1RPcoXECgYEA0ZxDyc5uLebjBE7IquQJ
ZxbEUUyenDG/Slbvbsef3C5o6zhRt6wKfCalwxN/MZQO7NhcK0CrakmXrgcbrCx2
RaaMFMkSmbpv2Js4E3eoVXbNDQfLIqUxbEi5VKP2A6jrWEXtQf1cHpHgdF2WkE64
huABZnjp2SP38cz2i90/QjI=
-----END PRIVATE KEY-----`

const { decode, V1 } = require('../../lib')

test('A.1.2.1.  Test Vector v1-S-1', async t => {
  const token = 'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw' +
                'iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5k' +
                'iAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEt' +
                'm2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJ' +
                'zVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96Sf' +
                'Q6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1' +
                'QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtp' +
                'flZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw'
  const pem = '-----BEGIN PUBLIC KEY-----\n' +
              'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n' +
              '5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd\n' +
              '74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g\n' +
              'mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU\n' +
              '5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5\n' +
              'IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc\n' +
              'p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB\n' +
              '-----END PUBLIC KEY-----'
  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V1.verify(token, pem, { ignoreExp: true }), expected)
  t.deepEqual(await V1.verify(await V1.sign(expected, privateRsaKey, { iat: false }), pem, { ignoreExp: true }), expected)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'public', version: 'v1', footer: undefined, payload: Buffer.from(JSON.stringify(expected)) })
})

test('A.1.2.2.  Test Vector v1-S-2', async t => {
  const token = 'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw' +
                'iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4mis' +
                'AuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X' +
                '8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S' +
                '1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthq' +
                'az7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJM' +
                'pixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C' +
                '0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJ' +
                'kWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVx' +
                'biJ9'
  const pem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p
5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd
74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g
mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU
5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5
IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc
p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB
-----END PUBLIC KEY-----`
  const expected = {
    payload: { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn' }), 'utf8'),
    version: 'v1',
    purpose: 'public'
  }

  t.deepEqual(await V1.verify(token, pem, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(await V1.verify(await V1.sign(expected.payload, privateRsaKey, { footer: expected.footer, iat: false }), pem, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'public', version: 'v1', footer: expected.footer, payload: Buffer.from(JSON.stringify(expected.payload)) })
})

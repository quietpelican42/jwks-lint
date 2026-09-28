# jwks-lint

Lint a JWKS (JSON Web Key Set) document's contents against RFC 7517, 7518, 8037, and 8812.

```ts
import { lint } from 'jwks-lint';

const findings = lint(jwksDocument);
// [{ rule: 'rsa-key-too-small', severity: 'error',
//    message: 'RSA modulus is 1024 bits; 2048 is the accepted minimum...',
//    rfc: 'RFC 7518 §6.3.1.1 (semantics per RFC 3447); NIST SP 800-131A',
//    keyIndex: 0, kid: '...' }, ...]
```

## Why

The npm ecosystem has JWKS *fetchers* (`jwks-rsa`, `get-jwks`, `jwks-client`),
*converters* (`jwk-to-pem`), and *mocks* (`mock-jwks`), and `jose` does encoding,
signing, and verification. None of them look at what a JWKS document actually
*contains*: whether a key that should be public carries a private exponent,
whether an RSA modulus is 1024 bits, whether two keys collide on `kid`, whether
`alg` and `crv` agree. A JWKS is machine-generated and rarely hand-read, so these
problems ship silently — until a client picks the wrong key, or a weak key gets
trusted for years because nothing ever looked at the set's contents.

Measured: `jwks-lint` against the 12 public JWKS endpoints below (fetched
2026-09-28; not committed to this repo — see Limitations).

```
apple                 clean
github-actions-oidc   clean
gitlab                clean
google                clean
line                  clean
linkedin              clean
microsoft (v1)        clean
microsoft (v2)        clean
paypal                clean
salesforce            clean
slack                 clean
yahoo                 4 errors: rsa-key-too-small (keys[0,1,4,5], 1024-bit RSA moduli)
```

11 of 12 endpoints were clean. Yahoo's `openid/v1/certs` endpoint publishes four
1024-bit RSA signing keys alongside two P-256 keys — independently confirmed by
decoding `n` and counting significant bits (129 bytes, leading zero byte, 1024
significant bits). Zero false positives across all 12 sets, which mix RSA, EC,
and OKP keys.

## Installation

```sh
npm install jwks-lint
```

Node >= 20.6. No runtime dependencies — key-size, curve-membership, and
certificate checks all run on `node:crypto`.

## Usage

### Lint a document you already have

```ts
import { lint } from 'jwks-lint';

const findings = lint(jwksDocument); // object or JSON string
for (const f of findings) {
  console.log(`[${f.severity}] ${f.rule}: ${f.message} (${f.rfc})`);
}
```

### Lint with an injected clock

`x5c` expiry checks use `Date.now()` by default; pass `now` to check against a
different point in time (tests, or "will this still be valid in 30 days"):

```ts
lint(jwksDocument, { now: new Date('2027-01-01') });
```

### From the command line

```sh
npx jwks-lint https://www.googleapis.com/oauth2/v3/certs
npx jwks-lint ./keys.json --format json
curl -s https://example.com/.well-known/jwks.json | npx jwks-lint -
```

## Reference

### `lint(jwks, options?) => Finding[]`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | `string` | — | Recorded on findings for context; not fetched by `lint` itself. |
| `now` | `Date` | `new Date()` | Clock used for `x5c` leaf-certificate expiry checks. |

Throws `JwksLintError` when the input cannot be analysed at all: invalid JSON,
or JSON without a `keys` array (RFC 7517 §5).

### `Finding`

| Field | Type | Description |
| --- | --- | --- |
| `rule` | `string` | Stable rule id, e.g. `rsa-key-too-small`. |
| `severity` | `'error' \| 'warning'` | |
| `message` | `string` | Specific to the offending value. |
| `rfc` | `string` | The RFC section the rule enforces or draws its threshold from. |
| `keyIndex` | `number?` | Index into `keys[]`; absent for set-level findings. |
| `kid` | `string?` | The key's `kid`, when it has one. |

### Rules

| Rule | Severity | RFC |
| --- | --- | --- |
| `unknown-kty` | error | RFC 7518 §6.1, RFC 8037 §2 |
| `missing-required-member` | error | RFC 7518 §6.2.1/§6.3.1/§6.4, RFC 8037 §2 |
| `base64url-invalid` | error | RFC 7518 §2 |
| `private-key-material` | error | RFC 7518 §6.2.2.1/§6.3.2/§6.4, RFC 8037 §2 |
| `duplicate-kid` | error (same kty+use) / warning (different kty or use) | RFC 7517 §4.5 |
| `missing-kid` | warning | RFC 7517 §4.5 |
| `rsa-key-too-small` | error (< 2048 bits) | RFC 7518 §6.3.1.1; NIST SP 800-131A |
| `rsa-exponent-unusual` | warning | RFC 7518 §6.3.1.2 |
| `ec-curve-unknown` | warning | RFC 7518 §6.2.1.1, RFC 8812 §3.1 |
| `ec-point-not-on-curve` | error | RFC 7518 §6.2.1 |
| `okp-curve-unknown` | warning | RFC 8037 §2/§3 |
| `okp-key-invalid` | error | RFC 8037 §2 |
| `alg-kty-mismatch` | error | RFC 7518 §3.1/§3.4, RFC 8037 §3.1, RFC 8812 §3.2 |
| `alg-deprecated` | warning (`none`, `RSA1_5`) | RFC 7518 §3.6/§4.2 |
| `use-key-ops-conflict` | warning (both present) / error (inconsistent) | RFC 7517 §4.3 |
| `key-ops-unrelated-combination` | error (duplicates) / warning (unrelated mix) | RFC 7517 §4.3 |
| `x5c-invalid` | error | RFC 7517 §4.7 |
| `x5t-mismatch` / `x5t-s256-mismatch` | error | RFC 7517 §4.8/§4.9 |
| `x5c-key-mismatch` | error | RFC 7517 §4.7 |
| `x5c-expired` | warning | RFC 7517 §4.7 |

### CLI

```
jwks-lint <file|url|-> [options]

  --format <fmt>      text (default), json, or github
  --timeout <ms>      URL fetch timeout. Default 5000.
  --max-bytes <n>     URL fetch size cap. Default 1048576 (1 MiB).
  --allow-http        Permit plain http:// URLs (https only by default).
  --now <iso-date>    Clock used for x5c expiry checks. Default: current time.
```

Exit codes: `0` no findings, `1` findings reported, `2` could not analyse the
input (invalid JSON, not a JWK Set, or the fetch itself failed).

## How it works

Each rule reads the members RFC 7517/7518/8037/8812 define for a key's `kty`
and checks a specific requirement from the text — a MUST that a structurally
broken key violates, or a SHOULD/threshold the RFCs leave to the application
(minimum RSA size, "unusual" exponent) drawn from the closest available
guidance and cited as such. Cryptographic validity — does this coordinate pair
actually sit on the named curve, does this certificate's public key match this
key's `n`/`e` or `x`/`y` — is checked with `node:crypto`'s `createPublicKey`
and `X509Certificate` rather than reimplemented: `createPublicKey({ format:
'jwk' })` rejects an EC point that doesn't satisfy the curve equation (verified
against a deliberately tampered, same-length coordinate), which is what makes
`ec-point-not-on-curve` a real check rather than a shape check.

## Limitations

- OKP (`Ed25519`/`Ed448`/`X25519`/`X448`) keys get length validation only.
  Node's JWK import checks encoded length for these curves but, unlike the
  Weierstrass curves EC uses, does not validate curve membership — confirmed
  by feeding it a length-correct, bit-flipped `x` that it accepted anyway.
  There is no `okp-point-not-on-curve` rule; the README's rule table does not
  list one, and neither should you expect one.
- `rsa-key-too-small` and `rsa-exponent-unusual` enforce thresholds the JOSE
  RFCs themselves don't set (they define encoding, not minimum size). The
  `rfc` field says so explicitly rather than citing a MUST that isn't there.
- `x5c`/`x5t` checks look only at the leaf certificate (`x5c[0]`): no chain
  validation, no revocation check, no comparison against a trust root.
- The real-world sample JWKS documents behind the Why section's numbers are
  fetched at measurement time and are not committed to this repository (they
  are live third-party data that rotates); rerun the URLs in that table to
  reproduce them.
- No streaming/incremental API — `lint` takes the whole document at once.

## Compatibility

Tested on Node 24.20.0 (darwin/arm64), the version this package was built and
run under. `engines` declares `>=20.6.0`; the CI workflow in this repository
runs the TypeScript suite on Node 24 and the built `dist/` smoke tests on Node
20.6, 22, and 24, but only the Node 24 run above was actually executed here.

## Development

```sh
npm install
npx tsc --noEmit
npm test                 # TypeScript suite via node --test, needs Node 24+
npm run build && npm run test:dist
```

`test/jwks-lint.test.ts` generates every fixture at test time with
`node:crypto`, `jose` (a devDependency), and, for the `x5c` tests, the local
`openssl` binary — those five tests skip loudly if `openssl` isn't on `PATH`.

## License

MIT. See [LICENSE](LICENSE).

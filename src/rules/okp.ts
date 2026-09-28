import { createPublicKey } from 'node:crypto';
import type { Finding, JsonWebKey } from '../types.ts';
import { isBase64url } from '../base64url.ts';
import { finding, KNOWN_OKP_CURVES, OKP_X_BYTES } from './util.ts';

/**
 * RFC 8037 §2/§3 define "crv" values "Ed25519", "Ed448" (signing) and "X25519",
 * "X448" (ECDH-ES). Unlike the Weierstrass curves in ec.ts, Node's JWK import for
 * Edwards/Montgomery curves validates only the encoded length, not curve membership —
 * confirmed by feeding it a length-correct but bit-flipped Ed25519 "x", which it
 * accepted. So this rule only checks the length RFC 8037/7748 require for each curve;
 * it does not claim to catch a malformed-but-right-length point the way ec.ts can.
 */
export function checkOkp(key: JsonWebKey, i: number): Finding[] {
  if (key['kty'] !== 'OKP') return [];
  const out: Finding[] = [];
  const crv = key['crv'];

  if (typeof crv !== 'string' || crv === '') return out;

  if (!KNOWN_OKP_CURVES.has(crv)) {
    out.push(finding('okp-curve-unknown', 'warning', `"crv" value "${crv}" is not one of Ed25519, Ed448, X25519, X448.`, 'RFC 8037 §2/§3', i, key));
    return out;
  }

  const x = key['x'];
  if (!isBase64url(x)) return out;

  const expected = OKP_X_BYTES[crv];
  if (expected !== undefined && Buffer.from(x, 'base64url').length !== expected) {
    out.push(
      finding(
        'okp-key-invalid',
        'error',
        `"x" is ${Buffer.from(x, 'base64url').length} bytes; ${crv} requires ${expected}.`,
        'RFC 8037 §2',
        i,
        key,
      ),
    );
    return out;
  }

  try {
    createPublicKey({ key: { kty: 'OKP', crv, x } as JsonWebKeyInput, format: 'jwk' });
  } catch (err) {
    out.push(
      finding('okp-key-invalid', 'error', `Key rejected by ${crv} import: ${err instanceof Error ? err.message : String(err)}.`, 'RFC 8037 §2', i, key),
    );
  }

  return out;
}

interface JsonWebKeyInput {
  [key: string]: unknown;
  kty: string;
  crv: string;
  x: string;
}

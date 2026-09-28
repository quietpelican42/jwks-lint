import { createPublicKey } from 'node:crypto';
import type { Finding, JsonWebKey } from '../types.ts';
import { isBase64url } from '../base64url.ts';
import { finding, KNOWN_EC_CURVES } from './util.ts';

const NODE_CURVE_NAME: Record<string, string> = {
  'P-256': 'P-256',
  'P-384': 'P-384',
  'P-521': 'P-521',
  secp256k1: 'secp256k1',
};

/**
 * RFC 7518 §6.2.1.1 registers "P-256", "P-384", "P-521"; RFC 8812 §3.1 adds
 * "secp256k1". Other values may be registered elsewhere (§6.2.1.1: "Additional 'crv'
 * values can be registered by other specifications"), so an unrecognized curve is a
 * warning, not an error. "x"/"y" not satisfying the curve equation is unambiguous:
 * Node's `crypto.createPublicKey` performs point validation on JWK import for named
 * Weierstrass curves and rejects a coordinate pair that is not actually on the curve
 * (verified against a deliberately tampered coordinate — same length, wrong point).
 */
export function checkEc(key: JsonWebKey, i: number): Finding[] {
  if (key['kty'] !== 'EC') return [];
  const out: Finding[] = [];
  const crv = key['crv'];

  if (typeof crv !== 'string' || crv === '') return out; // missing-required-member already covers this

  if (!KNOWN_EC_CURVES.has(crv)) {
    out.push(
      finding('ec-curve-unknown', 'warning', `"crv" value "${crv}" is not a curve this linter recognizes for kty EC.`, 'RFC 7518 §6.2.1.1, RFC 8812 §3.1', i, key),
    );
    return out; // nothing further to validate without a known curve
  }

  const x = key['x'];
  const y = key['y'];
  if (!isBase64url(x) || !isBase64url(y)) return out; // base64url-invalid already covers this

  try {
    createPublicKey({ key: { kty: 'EC', crv: NODE_CURVE_NAME[crv], x, y } as JsonWebKeyInput, format: 'jwk' });
  } catch (err) {
    out.push(
      finding(
        'ec-point-not-on-curve',
        'error',
        `"x"/"y" do not satisfy the curve equation for ${crv} (${err instanceof Error ? err.message : String(err)}).`,
        'RFC 7518 §6.2.1',
        i,
        key,
      ),
    );
  }

  return out;
}

// Minimal shape node:crypto's JWK import actually reads; avoids pulling in a DOM lib.
interface JsonWebKeyInput {
  [key: string]: unknown;
  kty: string;
  crv: string;
  x: string;
  y: string;
}

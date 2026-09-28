import type { Finding, JsonWebKey } from '../types.ts';
import { finding } from './util.ts';

/** What kty (and, for EC/OKP, which crv) a signature `alg` requires. */
interface AlgExpectation {
  kty: string;
  crv?: string[];
}

/**
 * RFC 7518 §3.1's alg table plus the curve each ECDSA alg is defined for (§3.4:
 * "ES256" with P-256, "ES384" with P-384, "ES512" with P-521); RFC 8037 §3.1
 * (EdDSA on OKP, Ed25519/Ed448 only — X25519/X448 "MUST NOT be used for signing");
 * RFC 8812 §3.2 (ES256K on secp256k1).
 */
const ALG_EXPECTATIONS: Record<string, AlgExpectation> = {
  HS256: { kty: 'oct' },
  HS384: { kty: 'oct' },
  HS512: { kty: 'oct' },
  RS256: { kty: 'RSA' },
  RS384: { kty: 'RSA' },
  RS512: { kty: 'RSA' },
  PS256: { kty: 'RSA' },
  PS384: { kty: 'RSA' },
  PS512: { kty: 'RSA' },
  RSA1_5: { kty: 'RSA' },
  ES256: { kty: 'EC', crv: ['P-256'] },
  ES384: { kty: 'EC', crv: ['P-384'] },
  ES512: { kty: 'EC', crv: ['P-521'] },
  ES256K: { kty: 'EC', crv: ['secp256k1'] },
  EdDSA: { kty: 'OKP', crv: ['Ed25519', 'Ed448'] },
};

const ALG_RFC: Record<string, string> = {
  ES256: 'RFC 7518 §3.4',
  ES384: 'RFC 7518 §3.4',
  ES512: 'RFC 7518 §3.4',
  ES256K: 'RFC 8812 §3.2',
  EdDSA: 'RFC 8037 §3.1',
};

/** RFC 7518 §3.1: "none" carries no protection. RFC 7518 §4.4/A.2: RSA1_5 (PKCS#1 v1.5 key wrap) is a legacy alg with known padding-oracle issues. */
const DEPRECATED_ALGS = new Set(['none', 'RSA1_5']);

/** RFC 7517 §4.3: sign/verify, encrypt/decrypt, wrapKey/unwrapKey are the only related pairs. */
const KEY_OPS_FAMILY: Record<string, 'sig' | 'enc'> = {
  sign: 'sig',
  verify: 'sig',
  encrypt: 'enc',
  decrypt: 'enc',
  wrapKey: 'enc',
  unwrapKey: 'enc',
};

export function checkAlgConsistency(key: JsonWebKey, i: number): Finding[] {
  const out: Finding[] = [];
  const alg = key['alg'];
  const kty = key['kty'];

  if (typeof alg === 'string' && alg !== '') {
    const expect = ALG_EXPECTATIONS[alg];
    if (expect && typeof kty === 'string') {
      if (kty !== expect.kty) {
        out.push(
          finding('alg-kty-mismatch', 'error', `"alg" is "${alg}", which requires kty "${expect.kty}", but kty is "${kty}".`, ALG_RFC[alg] ?? 'RFC 7518 §3.1', i, key),
        );
      } else if (expect.crv && typeof key['crv'] === 'string' && !expect.crv.includes(key['crv'])) {
        out.push(
          finding(
            'alg-kty-mismatch',
            'error',
            `"alg" is "${alg}", which requires crv ${expect.crv.join(' or ')}, but crv is "${key['crv']}".`,
            ALG_RFC[alg] ?? 'RFC 7518 §3.1',
            i,
            key,
          ),
        );
      }
    }

    if (DEPRECATED_ALGS.has(alg)) {
      const why = alg === 'none' ? 'produces unsecured JWSs with no integrity protection' : 'is a legacy PKCS#1 v1.5 key-wrap algorithm with known padding-oracle weaknesses';
      out.push(finding('alg-deprecated', 'warning', `"alg" is "${alg}", which ${why}.`, alg === 'none' ? 'RFC 7518 §3.6' : 'RFC 7518 §4.2', i, key));
    }
  }

  const use = key['use'];
  const keyOps = key['key_ops'];
  const hasUse = typeof use === 'string' && use !== '';
  const hasKeyOps = Array.isArray(keyOps) && keyOps.length > 0;

  if (hasUse && hasKeyOps) {
    out.push(
      finding('use-key-ops-conflict', 'warning', '"use" and "key_ops" are both present; RFC 7517 §4.3 says they SHOULD NOT be used together.', 'RFC 7517 §4.3', i, key),
    );
    const useFamily = use === 'sig' ? 'sig' : use === 'enc' ? 'enc' : undefined;
    if (useFamily) {
      const conflicting = (keyOps as unknown[]).filter((op) => typeof op === 'string' && KEY_OPS_FAMILY[op] && KEY_OPS_FAMILY[op] !== useFamily);
      if (conflicting.length > 0) {
        out.push(
          finding(
            'use-key-ops-conflict',
            'error',
            `"use" is "${use}" but "key_ops" includes ${conflicting.join(', ')}, which RFC 7517 §4.3 requires to be consistent.`,
            'RFC 7517 §4.3',
            i,
            key,
          ),
        );
      }
    }
  }

  if (hasKeyOps) {
    const ops = (keyOps as unknown[]).filter((op): op is string => typeof op === 'string');
    const seen = new Set<string>();
    const dupes = new Set<string>();
    for (const op of ops) {
      if (seen.has(op)) dupes.add(op);
      seen.add(op);
    }
    if (dupes.size > 0) {
      out.push(
        finding('key-ops-unrelated-combination', 'error', `"key_ops" contains duplicate value(s): ${[...dupes].join(', ')}.`, 'RFC 7517 §4.3', i, key),
      );
    }

    const families = new Set(ops.map((op) => KEY_OPS_FAMILY[op]).filter((f): f is 'sig' | 'enc' => f !== undefined));
    if (families.size > 1) {
      out.push(
        finding(
          'key-ops-unrelated-combination',
          'warning',
          `"key_ops" mixes unrelated operations (${ops.join(', ')}); RFC 7517 §4.3 permits only sign/verify, encrypt/decrypt, wrapKey/unwrapKey pairings.`,
          'RFC 7517 §4.3',
          i,
          key,
        ),
      );
    }
  }

  return out;
}

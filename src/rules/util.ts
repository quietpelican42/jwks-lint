import type { Finding, JsonWebKey, Severity } from '../types.ts';

export function finding(
  rule: string,
  severity: Severity,
  message: string,
  rfc: string,
  keyIndex: number,
  key: JsonWebKey,
): Finding {
  const f: Finding = { rule, severity, message, rfc, keyIndex };
  if (typeof key['kid'] === 'string') f.kid = key['kid'];
  return f;
}

/** Members every producer that actually holds the private half would set. */
export const RSA_PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as const;

export const KNOWN_EC_CURVES = new Set(['P-256', 'P-384', 'P-521', 'secp256k1']);
export const KNOWN_OKP_CURVES = new Set(['Ed25519', 'Ed448', 'X25519', 'X448']);

/** Expected byte length of the OKP `x` member per curve (RFC 8037 §2, RFC 7748). */
export const OKP_X_BYTES: Record<string, number> = {
  Ed25519: 32,
  X25519: 32,
  Ed448: 57,
  X448: 56,
};

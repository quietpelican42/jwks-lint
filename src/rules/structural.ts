import type { Finding, JsonWebKey } from '../types.ts';
import { isBase64url } from '../base64url.ts';
import { finding } from './util.ts';

const KNOWN_KTY = new Set(['RSA', 'EC', 'oct', 'OKP']);

/** Members whose value RFC 7518/8037 define as base64url(uint) or base64url(octets). */
const BASE64URL_MEMBERS: Record<string, string[]> = {
  RSA: ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'],
  EC: ['x', 'y', 'd'],
  OKP: ['x', 'd'],
  oct: ['k'],
};

/**
 * RFC 7517 §4.1: "kty" MUST be present. RFC 7518 §6.1 registers "EC", "RSA", "oct";
 * RFC 8037 §2 adds "OKP". Members required per type: RFC 7518 §6.2.1 (EC public),
 * §6.3.1 (RSA public), §6.4 (oct); RFC 8037 §2 (OKP).
 */
export function checkStructural(key: JsonWebKey, i: number): Finding[] {
  const out: Finding[] = [];
  const kty = key['kty'];

  if (typeof kty !== 'string' || kty === '') {
    out.push(finding('missing-required-member', 'error', '"kty" is REQUIRED and MUST be present in a JWK.', 'RFC 7517 §4.1', i, key));
    return out;
  }

  if (!KNOWN_KTY.has(kty)) {
    out.push(
      finding(
        'unknown-kty',
        'error',
        `"kty" value "${kty}" is not one of the registered key types RSA, EC, oct, OKP.`,
        'RFC 7518 §6.1, RFC 8037 §2',
        i,
        key,
      ),
    );
    return out;
  }

  const required: Record<string, string[]> = {
    RSA: ['n', 'e'],
    EC: ['crv', 'x', 'y'],
    OKP: ['crv', 'x'],
    oct: ['k'],
  };
  const rfcFor: Record<string, string> = {
    RSA: 'RFC 7518 §6.3.1',
    EC: 'RFC 7518 §6.2.1',
    OKP: 'RFC 8037 §2',
    oct: 'RFC 7518 §6.4',
  };
  for (const member of required[kty] ?? []) {
    if (!(member in key)) {
      out.push(
        finding(
          'missing-required-member',
          'error',
          `"${member}" is required for kty "${kty}" but is missing.`,
          rfcFor[kty] as string,
          i,
          key,
        ),
      );
    }
  }

  for (const member of BASE64URL_MEMBERS[kty] ?? []) {
    const v = key[member];
    if (v === undefined) continue;
    if (!isBase64url(v)) {
      out.push(
        finding(
          'base64url-invalid',
          'error',
          `"${member}" is not valid unpadded base64url (RFC 7518 §2 / RFC 4648 §5 alphabet, no "+", "/", or "=").`,
          'RFC 7518 §2',
          i,
          key,
        ),
      );
    }
  }

  return out;
}

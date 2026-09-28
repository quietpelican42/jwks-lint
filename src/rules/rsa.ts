import type { Finding, JsonWebKey } from '../types.ts';
import { base64urlDecode, isBase64url, uintBitLength } from '../base64url.ts';
import { finding } from './util.ts';

const MIN_BITS = 2048;
const F4 = 65537n; // 0x10001, the exponent RFC 7518's own examples use.

/**
 * RFC 7518 §6.3.1.1/§6.3.1.2 define "n" and "e" as Base64urlUInt-encoded values but
 * set no minimum modulus size — that comes from general cryptographic guidance (e.g.
 * NIST SP 800-131A / SP 800-57), not the JOSE RFCs, so the citation below names both.
 * The exponent check flags values that would make no producer's shortlist rather than
 * ones RFC 3447 forbids outright.
 */
export function checkRsa(key: JsonWebKey, i: number): Finding[] {
  if (key['kty'] !== 'RSA') return [];
  const out: Finding[] = [];

  const n = key['n'];
  if (isBase64url(n)) {
    const bits = uintBitLength(base64urlDecode(n));
    if (bits > 0 && bits < MIN_BITS) {
      out.push(
        finding(
          'rsa-key-too-small',
          'error',
          `RSA modulus is ${bits} bits; ${MIN_BITS} is the accepted minimum for keys issued or trusted today.`,
          'RFC 7518 §6.3.1.1 (semantics per RFC 3447); NIST SP 800-131A',
          i,
          key,
        ),
      );
    }
  }

  const e = key['e'];
  if (isBase64url(e)) {
    const eBuf = base64urlDecode(e);
    if (eBuf.length > 0) {
      const eVal = BigInt('0x' + eBuf.toString('hex'));
      if (eVal <= 1n) {
        out.push(
          finding('rsa-exponent-unusual', 'warning', `Public exponent is ${eVal}, which cannot be a valid RSA exponent.`, 'RFC 7518 §6.3.1.2', i, key),
        );
      } else if (eVal % 2n === 0n) {
        out.push(
          finding('rsa-exponent-unusual', 'warning', `Public exponent ${eVal} is even; a valid RSA exponent must be odd.`, 'RFC 7518 §6.3.1.2', i, key),
        );
      } else if (eVal !== F4) {
        out.push(
          finding(
            'rsa-exponent-unusual',
            'warning',
            `Public exponent is ${eVal}, not the near-universal 65537 (0x10001) RFC 7518's own examples use.`,
            'RFC 7518 §6.3.1.2',
            i,
            key,
          ),
        );
      }
    }
  }

  return out;
}

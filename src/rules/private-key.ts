import type { Finding, JsonWebKey } from '../types.ts';
import { finding, RSA_PRIVATE_MEMBERS } from './util.ts';

/**
 * A JWKS published for others to verify signatures or encrypt to should carry only
 * public material. RFC 7518 §6.3.2 lists "d", "p", "q", "dp", "dq", "qi", "oth" as the
 * RSA private-key members; §6.2.2.1 defines "d" for EC private keys; RFC 8037 §2
 * defines "d" for OKP private keys ("MUST NOT be present for public keys"). An "oct"
 * key's sole value, "k" (RFC 7518 §6.4), *is* the symmetric secret — there is no public
 * half, so any "oct" key in a published set is secret material by definition.
 */
export function checkPrivateKeyMaterial(key: JsonWebKey, i: number): Finding[] {
  const out: Finding[] = [];
  const kty = key['kty'];

  if (kty === 'RSA') {
    const present = RSA_PRIVATE_MEMBERS.filter((m) => m in key);
    if (present.length > 0) {
      out.push(
        finding(
          'private-key-material',
          'error',
          `RSA private-key member(s) present in a published key: ${present.join(', ')}.`,
          'RFC 7518 §6.3.2',
          i,
          key,
        ),
      );
    }
  } else if ((kty === 'EC' || kty === 'OKP') && 'd' in key) {
    out.push(
      finding(
        'private-key-material',
        'error',
        `"${kty}" private-key member "d" is present in a published key.`,
        kty === 'EC' ? 'RFC 7518 §6.2.2.1' : 'RFC 8037 §2',
        i,
        key,
      ),
    );
  } else if (kty === 'oct') {
    out.push(
      finding(
        'private-key-material',
        'error',
        '"oct" keys are symmetric secrets ("k" is the key value itself, not a public component); it has no place in a published JWKS.',
        'RFC 7518 §6.4',
        i,
        key,
      ),
    );
  }

  return out;
}

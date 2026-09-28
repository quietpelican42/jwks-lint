import type { Finding, JsonWebKey } from '../types.ts';
import { finding } from './util.ts';

/**
 * RFC 7517 §4.5: "kid" is OPTIONAL, and "When 'kid' values are used within a JWK Set,
 * different keys within the JWK Set SHOULD use distinct 'kid' values." The same
 * section then gives an explicit exception: keys with *different* "kty" that "are
 * considered to be equivalent alternatives by the application" may legitimately share
 * a kid. So a same-kid collision is only unambiguous — and therefore an error — when
 * the colliding keys also agree on "kty" and "use": nothing distinguishes which one a
 * consumer should pick. A collision across different "kty" or "use" is the case RFC
 * 7517 anticipates, and is downgraded to a warning.
 */
export function checkKidUniqueness(keys: JsonWebKey[]): Finding[] {
  const out: Finding[] = [];

  if (keys.length > 1) {
    keys.forEach((key, i) => {
      if (!('kid' in key) || typeof key['kid'] !== 'string' || key['kid'] === '') {
        out.push(
          finding(
            'missing-kid',
            'warning',
            'Key has no "kid" while the set has more than one key; selecting the right key is ambiguous without one.',
            'RFC 7517 §4.5',
            i,
            key,
          ),
        );
      }
    });
  }

  const byKid = new Map<string, number[]>();
  keys.forEach((key, i) => {
    const kid = key['kid'];
    if (typeof kid === 'string' && kid !== '') {
      const list = byKid.get(kid) ?? [];
      list.push(i);
      byKid.set(kid, list);
    }
  });

  for (const [kid, indices] of byKid) {
    if (indices.length < 2) continue;
    const shapes = new Set(indices.map((i) => `${keys[i]?.['kty']}\u0000${keys[i]?.['use'] ?? ''}`));
    const severity = shapes.size === 1 ? 'error' : 'warning';
    const message =
      shapes.size === 1
        ? `${indices.length} keys share kid "${kid}" with the same kty and use — selection between them is ambiguous.`
        : `${indices.length} keys share kid "${kid}" across different kty/use — allowed as "equivalent alternatives" per RFC 7517 §4.5, but confirm that is intentional.`;
    for (const i of indices) {
      out.push(finding('duplicate-kid', severity, message, 'RFC 7517 §4.5', i, keys[i] as JsonWebKey));
    }
  }

  return out;
}

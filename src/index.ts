import { JwksLintError } from './errors.ts';
import { checkStructural } from './rules/structural.ts';
import { checkPrivateKeyMaterial } from './rules/private-key.ts';
import { checkKidUniqueness } from './rules/kid.ts';
import { checkRsa } from './rules/rsa.ts';
import { checkEc } from './rules/ec.ts';
import { checkOkp } from './rules/okp.ts';
import { checkAlgConsistency } from './rules/alg-consistency.ts';
import { checkX5c } from './rules/x5c.ts';
import type { Finding, JsonWebKey, JsonWebKeySet, LintOptions } from './types.ts';

export * from './types.ts';
export { JwksLintError } from './errors.ts';

/**
 * Lint a JWK Set for content problems: leaked private/symmetric material, keys too
 * small or on unrecognized curves, kid collisions, alg/kty/use inconsistencies, and
 * x5c/x5t mismatches or expiry. Every finding names the RFC section it is enforcing.
 *
 * Throws `JwksLintError` when `jwks` cannot be analysed at all — invalid JSON, or JSON
 * that is not a JWK Set (RFC 7517 §5: "The JSON object MUST have a 'keys' member").
 */
export function lint(jwks: object | string, options: LintOptions = {}): Finding[] {
  const parsed = typeof jwks === 'string' ? parseJson(jwks) : jwks;
  const set = asJwksSet(parsed);
  const now = options.now ?? new Date();

  const findings: Finding[] = [];
  set.keys.forEach((key, i) => {
    findings.push(
      ...checkStructural(key, i),
      ...checkPrivateKeyMaterial(key, i),
      ...checkRsa(key, i),
      ...checkEc(key, i),
      ...checkOkp(key, i),
      ...checkAlgConsistency(key, i),
      ...checkX5c(key, i, now),
    );
  });
  findings.push(...checkKidUniqueness(set.keys));

  return findings;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new JwksLintError(`Input is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function asJwksSet(value: unknown): JsonWebKeySet {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new JwksLintError('Input is not a JSON object.');
  }
  const keys = (value as Record<string, unknown>)['keys'];
  if (!Array.isArray(keys)) {
    throw new JwksLintError('Input has no "keys" array (RFC 7517 §5: a JWK Set MUST have a "keys" member).');
  }
  for (const [i, k] of keys.entries()) {
    if (typeof k !== 'object' || k === null || Array.isArray(k)) {
      throw new JwksLintError(`keys[${i}] is not a JSON object.`);
    }
  }
  return { ...(value as Record<string, unknown>), keys: keys as JsonWebKey[] };
}

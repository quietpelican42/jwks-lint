import { X509Certificate, createHash } from 'node:crypto';
import type { Finding, JsonWebKey } from '../types.ts';
import { isBase64url } from '../base64url.ts';
import { finding } from './util.ts';

/**
 * RFC 7517 §4.7: "x5c" is a JSON array of base64-encoded (RFC 4648 §4 — *not*
 * base64url) DER certificates, "The key in the first certificate MUST match the
 * public key represented by other members of the JWK." §4.8/§4.9: "x5t"/"x5t#S256"
 * are base64url SHA-1/SHA-256 thumbprints of that same DER encoding, and "MUST match
 * the public key represented by other members" too (transitively, via the cert).
 */
export function checkX5c(key: JsonWebKey, i: number, now: Date): Finding[] {
  const out: Finding[] = [];
  const x5c = key['x5c'];
  if (!Array.isArray(x5c) || x5c.length === 0) return out;

  const leaf = x5c[0];
  if (typeof leaf !== 'string') {
    out.push(finding('x5c-invalid', 'error', '"x5c[0]" is not a string.', 'RFC 7517 §4.7', i, key));
    return out;
  }

  let der: Buffer;
  try {
    der = Buffer.from(leaf, 'base64');
    if (der.length === 0) throw new Error('decodes to zero bytes');
  } catch (err) {
    out.push(finding('x5c-invalid', 'error', `"x5c[0]" is not valid base64: ${err instanceof Error ? err.message : String(err)}.`, 'RFC 7517 §4.7', i, key));
    return out;
  }

  let cert: X509Certificate;
  try {
    cert = new X509Certificate(der);
  } catch (err) {
    out.push(finding('x5c-invalid', 'error', `"x5c[0]" does not parse as a DER certificate: ${err instanceof Error ? err.message : String(err)}.`, 'RFC 7517 §4.7', i, key));
    return out;
  }

  const x5t = key['x5t'];
  if (isBase64url(x5t)) {
    const actual = createHash('sha1').update(der).digest('base64url');
    if (actual !== x5t) {
      out.push(finding('x5t-mismatch', 'error', `"x5t" does not match the SHA-1 thumbprint of "x5c[0]" (got ${actual}).`, 'RFC 7517 §4.8', i, key));
    }
  }

  const x5tS256 = key['x5t#S256'];
  if (isBase64url(x5tS256)) {
    const actual = createHash('sha256').update(der).digest('base64url');
    if (actual !== x5tS256) {
      out.push(finding('x5t-s256-mismatch', 'error', `"x5t#S256" does not match the SHA-256 thumbprint of "x5c[0]" (got ${actual}).`, 'RFC 7517 §4.9', i, key));
    }
  }

  out.push(...checkCertKeyMatch(key, cert, i));

  const validTo = new Date(cert.validTo);
  const validFrom = new Date(cert.validFrom);
  if (!Number.isNaN(validTo.getTime()) && now > validTo) {
    out.push(finding('x5c-expired', 'warning', `"x5c[0]" expired ${cert.validTo}.`, 'RFC 7517 §4.7', i, key));
  } else if (!Number.isNaN(validFrom.getTime()) && now < validFrom) {
    out.push(finding('x5c-expired', 'warning', `"x5c[0]" is not yet valid (starts ${cert.validFrom}).`, 'RFC 7517 §4.7', i, key));
  }

  return out;
}

function checkCertKeyMatch(key: JsonWebKey, cert: X509Certificate, i: number): Finding[] {
  const kty = key['kty'];
  let certJwk: Record<string, unknown>;
  try {
    certJwk = cert.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  } catch {
    return []; // an unsupported key algorithm in the cert; nothing more to compare
  }

  if (kty === 'RSA') {
    if (certJwk['n'] !== key['n'] || certJwk['e'] !== key['e']) {
      return [finding('x5c-key-mismatch', 'error', 'The RSA public key in "x5c[0]" does not match this key\'s "n"/"e".', 'RFC 7517 §4.7', i, key)];
    }
  } else if (kty === 'EC') {
    if (certJwk['x'] !== key['x'] || certJwk['y'] !== key['y']) {
      return [finding('x5c-key-mismatch', 'error', 'The EC public key in "x5c[0]" does not match this key\'s "x"/"y".', 'RFC 7517 §4.7', i, key)];
    }
  }
  return [];
}

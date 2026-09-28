/**
 * base64url, as JWK members use it throughout RFC 7518 §6 ("Base64urlUInt-encoded",
 * or "the base64url encoding of the octet string"): RFC 4648 §5's alphabet, with
 * padding omitted (RFC 7515 §2 "Base64url Encoding" — no `+`, `/`, or `=`).
 */
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

/** True if `s` is a syntactically valid, unpadded base64url string. */
export function isBase64url(s: unknown): s is string {
  if (typeof s !== 'string') return false;
  if (!BASE64URL_RE.test(s)) return false;
  // 4n+1 characters can never decode to a whole number of octets.
  if (s.length % 4 === 1) return false;
  return true;
}

/** Decode a value already confirmed to be valid base64url. */
export function base64urlDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

/**
 * Bit length of a Base64urlUInt-encoded unsigned integer (RFC 7518 §2), i.e. the
 * modulus/exponent encoding used by RSA JWK members. Handles the leading zero-byte
 * some libraries emit for the top bit of an otherwise-full-width value (RFC 7518
 * §6.3.1.1: "some cryptographic libraries prefix an extra zero-valued octet").
 */
export function uintBitLength(buf: Buffer): number {
  let i = 0;
  while (i < buf.length && buf[i] === 0) i++;
  if (i === buf.length) return 0;
  const first = buf[i] as number;
  return (buf.length - i - 1) * 8 + (32 - Math.clz32(first));
}

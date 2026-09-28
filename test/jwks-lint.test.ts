import assert from 'node:assert/strict';
import { test, describe } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';

import { lint, JwksLintError } from '../src/index.ts';
import type { Finding } from '../src/types.ts';

function jwks(keys: Record<string, unknown>[]) {
  return { keys };
}

function rulesOf(findings: Finding[]): string[] {
  return findings.map((f) => f.rule);
}

function rsaJwk(bits = 2048, extra: Record<string, unknown> = {}) {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  return { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), ...extra };
}

function ecJwk(namedCurve: 'P-256' | 'P-384' | 'P-521' = 'P-256', extra: Record<string, unknown> = {}) {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve });
  return { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), ...extra };
}

function okpJwk(kind: 'ed25519' | 'x25519' = 'ed25519', extra: Record<string, unknown> = {}) {
  const { publicKey } = kind === 'ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('x25519');
  return { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), ...extra };
}

describe('input handling', () => {
  test('throws JwksLintError on invalid JSON', () => {
    assert.throws(() => lint('not json'), JwksLintError);
  });

  test('throws JwksLintError when "keys" is missing', () => {
    assert.throws(() => lint('{}'), JwksLintError);
  });

  test('throws JwksLintError when a key is not an object', () => {
    assert.throws(() => lint(JSON.stringify({ keys: ['nope'] })), JwksLintError);
  });

  test('accepts a JSON string or a parsed object identically', () => {
    const obj = jwks([rsaJwk()]);
    assert.deepEqual(lint(JSON.stringify(obj)), lint(obj));
  });

  test('a clean, real-shaped JWKS produces no findings', () => {
    const findings = lint(jwks([rsaJwk(2048, { kid: 'a', use: 'sig', alg: 'RS256' }), ecJwk('P-256', { kid: 'b', use: 'sig', alg: 'ES256' })]));
    assert.deepEqual(findings, []);
  });
});

describe('structural', () => {
  test('flags missing kty', () => {
    const findings = lint(jwks([{ n: 'x', e: 'AQAB' }]));
    assert.ok(rulesOf(findings).includes('missing-required-member'));
  });

  test('flags unknown kty', () => {
    const findings = lint(jwks([{ kty: 'DSA' }]));
    assert.deepEqual(rulesOf(findings), ['unknown-kty']);
  });

  test('flags a missing required member per kty', () => {
    const findings = lint(jwks([{ kty: 'RSA', n: 'AQAB' }])); // no "e"
    assert.ok(findings.some((f) => f.rule === 'missing-required-member' && f.message.includes('"e"')));
  });

  test('flags non-base64url member values', () => {
    const findings = lint(jwks([{ kty: 'RSA', n: 'not-base64url!!!', e: 'AQAB' }]));
    assert.ok(findings.some((f) => f.rule === 'base64url-invalid'));
  });

  test('accepts a structurally valid oct key format (still flagged as private material)', () => {
    const findings = lint(jwks([{ kty: 'oct', k: 'c2VjcmV0' }]));
    assert.deepEqual(rulesOf(findings), ['private-key-material']);
  });
});

describe('private-key-material', () => {
  test('flags RSA private members', () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const priv = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const findings = lint(jwks([priv]));
    const f = findings.find((x) => x.rule === 'private-key-material');
    assert.ok(f, 'expected private-key-material finding');
    assert.equal(f?.severity, 'error');
    for (const m of ['d', 'p', 'q', 'dp', 'dq', 'qi']) assert.ok(f?.message.includes(m), `message should mention ${m}`);
  });

  test('flags EC private "d"', () => {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const priv = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
    assert.deepEqual(rulesOf(lint(jwks([priv]))), ['private-key-material']);
  });

  test('flags OKP private "d"', () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const priv = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
    assert.deepEqual(rulesOf(lint(jwks([priv]))), ['private-key-material']);
  });

  test('flags any oct key as private material', () => {
    assert.deepEqual(rulesOf(lint(jwks([{ kty: 'oct', k: 'c2VjcmV0LXZhbHVl' }]))), ['private-key-material']);
  });

  test('does not flag a clean RSA public key', () => {
    assert.deepEqual(lint(jwks([rsaJwk()])), []);
  });

  test('does not flag a clean EC public key', () => {
    assert.deepEqual(lint(jwks([ecJwk()])), []);
  });

  test('does not flag a clean OKP public key', () => {
    assert.deepEqual(lint(jwks([okpJwk()])), []);
  });
});

describe('kid', () => {
  test('errors on same kid + same kty + same use', () => {
    const findings = lint(jwks([rsaJwk(2048, { kid: 'k1', use: 'sig' }), rsaJwk(2048, { kid: 'k1', use: 'sig' })]));
    const dup = findings.filter((f) => f.rule === 'duplicate-kid');
    assert.equal(dup.length, 2);
    assert.ok(dup.every((f) => f.severity === 'error'));
  });

  test('warns on same kid across different kty', () => {
    const findings = lint(jwks([rsaJwk(2048, { kid: 'k1' }), ecJwk('P-256', { kid: 'k1' })]));
    const dup = findings.filter((f) => f.rule === 'duplicate-kid');
    assert.equal(dup.length, 2);
    assert.ok(dup.every((f) => f.severity === 'warning'));
  });

  test('warns on missing kid when more than one key is present', () => {
    const findings = lint(jwks([rsaJwk(2048, { kid: 'a' }), rsaJwk(2048)]));
    assert.ok(findings.some((f) => f.rule === 'missing-kid' && f.severity === 'warning'));
  });

  test('does not warn about a missing kid on a single-key set', () => {
    assert.deepEqual(lint(jwks([rsaJwk()])), []);
  });

  test('distinct kids on distinct keys produce no kid findings', () => {
    const findings = lint(jwks([rsaJwk(2048, { kid: 'a' }), rsaJwk(2048, { kid: 'b' })]));
    assert.deepEqual(
      findings.filter((f) => f.rule.includes('kid')),
      [],
    );
  });
});

describe('rsa', () => {
  test('flags a 1024-bit modulus as too small', () => {
    const findings = lint(jwks([rsaJwk(1024)]));
    const f = findings.find((x) => x.rule === 'rsa-key-too-small');
    assert.ok(f);
    assert.equal(f?.severity, 'error');
    assert.match(f?.message ?? '', /1024/);
  });

  test('does not flag a 2048-bit modulus', () => {
    assert.deepEqual(
      lint(jwks([rsaJwk(2048)])).filter((f) => f.rule === 'rsa-key-too-small'),
      [],
    );
  });

  test('flags an unusual (non-65537) odd exponent as a warning', () => {
    const key = rsaJwk(2048, { e: Buffer.from([3]).toString('base64url') });
    const findings = lint(jwks([key]));
    const f = findings.find((x) => x.rule === 'rsa-exponent-unusual');
    assert.ok(f);
    assert.equal(f?.severity, 'warning');
  });

  test('flags an even exponent', () => {
    const key = rsaJwk(2048, { e: Buffer.from([4]).toString('base64url') });
    const findings = lint(jwks([key]));
    assert.ok(findings.some((f) => f.rule === 'rsa-exponent-unusual' && f.message.includes('even')));
  });

  test('does not flag the standard 65537 exponent', () => {
    assert.deepEqual(
      lint(jwks([rsaJwk(2048)])).filter((f) => f.rule === 'rsa-exponent-unusual'),
      [],
    );
  });
});

describe('ec', () => {
  test('warns on an unrecognized curve', () => {
    const findings = lint(jwks([{ kty: 'EC', crv: 'P-192', x: 'AAAA', y: 'AAAA' }]));
    assert.ok(findings.some((f) => f.rule === 'ec-curve-unknown' && f.severity === 'warning'));
  });

  test('errors when x/y do not satisfy the curve equation', () => {
    const key = ecJwk('P-256');
    const xBuf = Buffer.from(key['x'] as string, 'base64url');
    xBuf[xBuf.length - 1] = (xBuf[xBuf.length - 1] as number) ^ 0x01;
    key['x'] = xBuf.toString('base64url');
    const findings = lint(jwks([key]));
    assert.ok(findings.some((f) => f.rule === 'ec-point-not-on-curve' && f.severity === 'error'));
  });

  test('does not flag a genuine P-256/P-384/P-521 key', () => {
    for (const crv of ['P-256', 'P-384', 'P-521'] as const) {
      assert.deepEqual(lint(jwks([ecJwk(crv)])), [], `expected no findings for ${crv}`);
    }
  });
});

describe('okp', () => {
  test('warns on an unrecognized curve', () => {
    const findings = lint(jwks([{ kty: 'OKP', crv: 'Curve448-ish', x: Buffer.alloc(32).toString('base64url') }]));
    assert.ok(findings.some((f) => f.rule === 'okp-curve-unknown' && f.severity === 'warning'));
  });

  test('errors on a wrong-length x for Ed25519', () => {
    const findings = lint(jwks([{ kty: 'OKP', crv: 'Ed25519', x: Buffer.alloc(16).toString('base64url') }]));
    assert.ok(findings.some((f) => f.rule === 'okp-key-invalid' && f.severity === 'error'));
  });

  test('does not flag a genuine Ed25519 key', () => {
    assert.deepEqual(lint(jwks([okpJwk('ed25519')])), []);
  });

  test('does not flag a genuine X25519 key', () => {
    assert.deepEqual(lint(jwks([okpJwk('x25519')])), []);
  });
});

describe('alg/kty/use consistency', () => {
  test('errors when alg requires a different kty', () => {
    const findings = lint(jwks([ecJwk('P-256', { alg: 'RS256' })]));
    assert.ok(findings.some((f) => f.rule === 'alg-kty-mismatch' && f.severity === 'error'));
  });

  test('errors when ES256 is set on a P-384 key', () => {
    const findings = lint(jwks([ecJwk('P-384', { alg: 'ES256' })]));
    assert.ok(findings.some((f) => f.rule === 'alg-kty-mismatch' && f.message.includes('P-256')));
  });

  test('does not flag ES256 on a P-256 key', () => {
    assert.deepEqual(lint(jwks([ecJwk('P-256', { alg: 'ES256' })])), []);
  });

  test('does not flag EdDSA on an Ed25519 key', () => {
    assert.deepEqual(lint(jwks([okpJwk('ed25519', { alg: 'EdDSA' })])), []);
  });

  test('warns on alg "none"', () => {
    const findings = lint(jwks([rsaJwk(2048, { alg: 'none' })]));
    assert.ok(findings.some((f) => f.rule === 'alg-deprecated' && f.severity === 'warning'));
  });

  test('warns on alg "RSA1_5"', () => {
    const findings = lint(jwks([rsaJwk(2048, { alg: 'RSA1_5' })]));
    assert.ok(findings.some((f) => f.rule === 'alg-deprecated' && f.severity === 'warning'));
  });

  test('warns when use and key_ops are both present', () => {
    const findings = lint(jwks([rsaJwk(2048, { use: 'sig', key_ops: ['verify'] })]));
    assert.ok(findings.some((f) => f.rule === 'use-key-ops-conflict' && f.severity === 'warning'));
  });

  test('errors when use and key_ops disagree', () => {
    const findings = lint(jwks([rsaJwk(2048, { use: 'sig', key_ops: ['encrypt'] })]));
    assert.ok(findings.some((f) => f.rule === 'use-key-ops-conflict' && f.severity === 'error'));
  });

  test('errors on duplicate key_ops values', () => {
    const findings = lint(jwks([rsaJwk(2048, { key_ops: ['verify', 'verify'] })]));
    assert.ok(findings.some((f) => f.rule === 'key-ops-unrelated-combination' && f.severity === 'error'));
  });

  test('warns on an unrelated key_ops combination', () => {
    const findings = lint(jwks([rsaJwk(2048, { key_ops: ['sign', 'encrypt'] })]));
    assert.ok(findings.some((f) => f.rule === 'key-ops-unrelated-combination' && f.severity === 'warning'));
  });

  test('does not flag sign+verify together', () => {
    assert.deepEqual(
      lint(jwks([rsaJwk(2048, { key_ops: ['sign', 'verify'] })])).filter((f) => f.rule.startsWith('key-ops')),
      [],
    );
  });
});

describe('x5c', () => {
  let opensslAvailable = true;
  try {
    execFileSync('openssl', ['version']);
  } catch {
    opensslAvailable = false;
  }

  function makeCert(): { der: Buffer; jwk: Record<string, unknown>; validTo: Date } {
    const dir = mkdtempSync(join(tmpdir(), 'jwks-lint-x5c-'));
    const keyPath = join(dir, 'key.pem');
    const certPath = join(dir, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '30', '-subj', '/CN=jwks-lint-test']);
    const pem = readFileSync(certPath, 'utf8');
    const der = Buffer.from(pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\r?\n/g, ''), 'base64');
    const cert = new crypto.X509Certificate(der);
    const jwk = cert.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    return { der, jwk, validTo: new Date(cert.validTo) };
  }

  test('a key whose x5c/x5t/n/e all agree produces no x5c findings', { skip: !opensslAvailable && 'openssl not found in PATH; skipping x5c fixture tests' }, () => {
    const { der, jwk } = makeCert();
    const key = {
      ...jwk,
      x5c: [der.toString('base64')],
      x5t: crypto.createHash('sha1').update(der).digest('base64url'),
      'x5t#S256': crypto.createHash('sha256').update(der).digest('base64url'),
    };
    const findings = lint(jwks([key])).filter((f) => f.rule.startsWith('x5'));
    assert.deepEqual(findings, []);
  });

  test('flags a key whose n/e do not match the x5c certificate', { skip: !opensslAvailable && 'openssl not found in PATH; skipping x5c fixture tests' }, () => {
    const { der } = makeCert();
    const otherJwk = rsaJwk(2048);
    const key = { ...otherJwk, x5c: [der.toString('base64')] };
    const findings = lint(jwks([key]));
    assert.ok(findings.some((f) => f.rule === 'x5c-key-mismatch' && f.severity === 'error'));
  });

  test('flags a wrong x5t thumbprint', { skip: !opensslAvailable && 'openssl not found in PATH; skipping x5c fixture tests' }, () => {
    const { der, jwk } = makeCert();
    const key = { ...jwk, x5c: [der.toString('base64')], x5t: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA' };
    const findings = lint(jwks([key]));
    assert.ok(findings.some((f) => f.rule === 'x5t-mismatch' && f.severity === 'error'));
  });

  test('warns when the x5c leaf has expired, relative to an injected clock', { skip: !opensslAvailable && 'openssl not found in PATH; skipping x5c fixture tests' }, () => {
    const { der, jwk, validTo } = makeCert();
    const key = { ...jwk, x5c: [der.toString('base64')] };
    const afterExpiry = new Date(validTo.getTime() + 24 * 60 * 60 * 1000);
    const findings = lint(jwks([key]), { now: afterExpiry });
    assert.ok(findings.some((f) => f.rule === 'x5c-expired' && f.severity === 'warning'));
  });

  test('does not warn about expiry before the leaf expires', { skip: !opensslAvailable && 'openssl not found in PATH; skipping x5c fixture tests' }, () => {
    const { der, jwk } = makeCert();
    const key = { ...jwk, x5c: [der.toString('base64')] };
    const findings = lint(jwks([key]), { now: new Date() });
    assert.deepEqual(
      findings.filter((f) => f.rule === 'x5c-expired'),
      [],
    );
  });
});

describe('jose-generated fixtures', () => {
  test('a key pair generated with jose is clean', async () => {
    const { exportJWK, generateKeyPair } = await import('jose');
    const { publicKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const jwk = await exportJWK(publicKey);
    const findings = lint(jwks([{ ...jwk, alg: 'RS256', use: 'sig', kid: 'jose-1' }]));
    assert.deepEqual(findings, []);
  });

  test('a jose-generated private key is caught by private-key-material', async () => {
    const { exportJWK, generateKeyPair } = await import('jose');
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk = await exportJWK(privateKey);
    const findings = lint(jwks([jwk as Record<string, unknown>]));
    assert.ok(findings.some((f) => f.rule === 'private-key-material'));
  });
});

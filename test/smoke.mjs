/**
 * Plain-JS checks against the built package, so they run on every Node version
 * in `engines` — the TypeScript suite needs type stripping and only runs on 24+.
 *
 *   npm run build && node --test test/smoke.mjs
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

const { lint, JwksLintError } = await import('../dist/index.js');

test('a clean RSA public key produces no findings', () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  assert.deepEqual(lint({ keys: [{ ...jwk, kid: 'k1', use: 'sig', alg: 'RS256' }] }), []);
});

test('a private RSA key is flagged', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const findings = lint({ keys: [jwk] });
  assert.ok(findings.some((f) => f.rule === 'private-key-material'));
});

test('a 1024-bit RSA key is flagged as too small', () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const jwk = publicKey.export({ format: 'jwk' });
  const findings = lint({ keys: [jwk] });
  assert.ok(findings.some((f) => f.rule === 'rsa-key-too-small' && f.severity === 'error'));
});

test('invalid JSON throws JwksLintError', () => {
  assert.throws(() => lint('{not json'), JwksLintError);
});

test('cli: exits 0 with "No findings." on a clean set, reading stdin', () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const input = JSON.stringify({ keys: [jwk] });
  const out = execFileSync('node', ['dist/cli.js', '-'], { input, encoding: 'utf8' });
  assert.match(out, /No findings\./);
});

test('cli: exits 1 and prints findings for a set with a private key', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const input = JSON.stringify({ keys: [jwk] });
  let code = 0;
  let out = '';
  try {
    execFileSync('node', ['dist/cli.js', '-', '--format', 'json'], { input, encoding: 'utf8' });
  } catch (err) {
    code = err.status;
    out = err.stdout;
  }
  assert.equal(code, 1);
  const findings = JSON.parse(out);
  assert.ok(findings.some((f) => f.rule === 'private-key-material'));
});

test('cli: exits 2 on invalid JSON', () => {
  let code = 0;
  try {
    execFileSync('node', ['dist/cli.js', '-'], { input: 'not json', encoding: 'utf8' });
  } catch (err) {
    code = err.status;
  }
  assert.equal(code, 2);
});

#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { lint, JwksLintError } from './index.ts';
import type { Finding } from './types.ts';
import { fetchJwks, FetchJwksError } from './fetch-jwks.ts';

const USAGE = `Usage: jwks-lint <file|url|-> [options]

Lint a JWK Set's contents against RFC 7517/7518/8037/8812.

  <file|url|->        Path to a JSON file, an https:// URL, or "-" for stdin.

Options:
  --format <fmt>      text (default), json, or github.
  --timeout <ms>      URL fetch timeout. Default 5000.
  --max-bytes <n>     URL fetch size cap. Default 1048576 (1 MiB).
  --allow-http        Permit plain http:// URLs (https only by default).
  --now <iso-date>    Clock used for x5c expiry checks. Default: current time.
  -h, --help          Show this help.

Exit codes:
  0  no findings
  1  findings reported (at least one error or warning)
  2  could not analyse the input (bad JSON, not a JWK Set, fetch failure)
`;

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.help || !args.input) {
    process.stdout.write(USAGE);
    return args.help ? 0 : 2;
  }

  let text: string;
  try {
    if (args.input === '-') {
      text = readFileSync(0, 'utf8');
    } else if (/^https?:\/\//i.test(args.input)) {
      text = await fetchJwks(new URL(args.input), { timeoutMs: args.timeout, maxBytes: args.maxBytes, allowHttp: args.allowHttp });
    } else {
      text = readFileSync(args.input, 'utf8');
    }
  } catch (err) {
    const msg = err instanceof FetchJwksError ? err.message : `Could not read "${args.input}": ${err instanceof Error ? err.message : String(err)}`;
    process.stderr.write(msg + '\n');
    return 2;
  }

  let findings: Finding[];
  try {
    findings = lint(text, { url: /^https?:\/\//i.test(args.input) ? args.input : undefined, now: args.now });
  } catch (err) {
    if (err instanceof JwksLintError) {
      process.stderr.write(err.message + '\n');
      return 2;
    }
    throw err;
  }

  report(findings, args.format);
  return findings.length === 0 ? 0 : 1;
}

function report(findings: Finding[], format: 'text' | 'json' | 'github'): void {
  if (format === 'json') {
    process.stdout.write(JSON.stringify(findings, null, 2) + '\n');
    return;
  }
  if (format === 'github') {
    for (const f of findings) {
      const cmd = f.severity === 'error' ? 'error' : 'warning';
      const where = f.keyIndex !== undefined ? `key[${f.keyIndex}]${f.kid ? ` (kid=${f.kid})` : ''}: ` : '';
      process.stdout.write(`::${cmd}::${where}${f.rule}: ${f.message} (${f.rfc})\n`);
    }
    return;
  }
  if (findings.length === 0) {
    process.stdout.write('No findings.\n');
    return;
  }
  for (const f of findings) {
    const where = f.keyIndex !== undefined ? `key[${f.keyIndex}]${f.kid ? ` (kid=${f.kid})` : ''} ` : '';
    process.stdout.write(`[${f.severity.toUpperCase()}] ${where}${f.rule}: ${f.message} (${f.rfc})\n`);
  }
  const errors = findings.filter((f) => f.severity === 'error').length;
  const warnings = findings.length - errors;
  process.stdout.write(`\n${errors} error(s), ${warnings} warning(s).\n`);
}

interface Args {
  input: string | undefined;
  format: 'text' | 'json' | 'github';
  timeout: number;
  maxBytes: number;
  allowHttp: boolean;
  now: Date | undefined;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { input: undefined, format: 'text', timeout: 5000, maxBytes: 1024 * 1024, allowHttp: false, now: undefined, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '--format') args.format = requireOneOf(argv[++i], ['text', 'json', 'github'], '--format');
    else if (a === '--timeout') args.timeout = requireInt(argv[++i], '--timeout');
    else if (a === '--max-bytes') args.maxBytes = requireInt(argv[++i], '--max-bytes');
    else if (a === '--allow-http') args.allowHttp = true;
    else if (a === '--now') args.now = requireDate(argv[++i]);
    else if (args.input === undefined) args.input = a;
    else throw new Error(`Unexpected argument "${a}"`);
  }
  return args;
}

function requireOneOf<T extends string>(v: string | undefined, allowed: T[], flag: string): T {
  if (v === undefined || !(allowed as string[]).includes(v)) throw new Error(`${flag} expects one of: ${allowed.join(', ')}`);
  return v as T;
}
function requireInt(v: string | undefined, flag: string): number {
  const n = Number(v);
  if (v === undefined || !Number.isFinite(n)) throw new Error(`${flag} expects a number`);
  return n;
}
function requireDate(v: string | undefined): Date {
  const d = v === undefined ? new Date(NaN) : new Date(v);
  if (Number.isNaN(d.getTime())) throw new Error('--now expects an ISO 8601 date');
  return d;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  },
);

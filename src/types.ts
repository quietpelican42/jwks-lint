export type Severity = 'error' | 'warning';

/** One thing wrong (or worth a second look) with one key, or with the set as a whole. */
export interface Finding {
  /** Stable, kebab-case rule identifier, e.g. `rsa-key-too-small`. */
  rule: string;
  severity: Severity;
  /** Human-readable explanation, specific to the offending value. */
  message: string;
  /** The RFC section the rule is enforcing or drawing its threshold from. */
  rfc: string;
  /** Index into `keys[]`, absent for set-level findings (e.g. duplicate kid). */
  keyIndex?: number;
  /** The key's `kid`, when it has one, repeated here for convenience in reports. */
  kid?: string;
}

export interface LintOptions {
  /** Where the JWKS came from. Used only to make messages more specific. */
  url?: string;
  /** Clock used for `x5c` certificate expiry checks. Defaults to `new Date()`. */
  now?: Date;
}

/** A JWK as JSON: a bag of string/array members keyed by the standard names. */
export type JsonWebKey = Record<string, unknown>;

export interface JsonWebKeySet {
  keys: JsonWebKey[];
  [extra: string]: unknown;
}

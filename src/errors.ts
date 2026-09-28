/** Thrown when the input cannot be analysed at all — not valid JSON, or not a JWK Set. */
export class JwksLintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

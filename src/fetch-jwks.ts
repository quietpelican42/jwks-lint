/** Fetch a JWKS URL with the caps a CLI reading arbitrary input needs: https only by
 * default, a wall-clock timeout, and a hard byte cap enforced while the body streams
 * (not just checked against `content-length`, which a server can omit or misstate). */
export interface FetchJwksOptions {
  timeoutMs: number;
  maxBytes: number;
  allowHttp: boolean;
}

export class FetchJwksError extends Error {}

export async function fetchJwks(url: URL, opts: FetchJwksOptions): Promise<string> {
  if (url.protocol !== 'https:' && !(opts.allowHttp && url.protocol === 'http:')) {
    throw new FetchJwksError(`Refusing to fetch "${url.protocol}" URL without --allow-http (https only by default).`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new FetchJwksError(`Request exceeded timeout of ${opts.timeoutMs}ms`)), opts.timeoutMs);
  timer.unref?.();

  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      throw new FetchJwksError(`GET ${url} -> HTTP ${res.status}`);
    }
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > opts.maxBytes) {
      throw new FetchJwksError(`Response declares ${declared} bytes, over the ${opts.maxBytes} byte cap.`);
    }
    if (!res.body) return await res.text();

    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > opts.maxBytes) {
        await reader.cancel();
        throw new FetchJwksError(`Response exceeded the ${opts.maxBytes} byte cap while streaming.`);
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
  } catch (err) {
    if (controller.signal.aborted && controller.signal.reason instanceof FetchJwksError) throw controller.signal.reason;
    if (err instanceof FetchJwksError) throw err;
    throw new FetchJwksError(`Fetching ${url} failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timer);
  }
}

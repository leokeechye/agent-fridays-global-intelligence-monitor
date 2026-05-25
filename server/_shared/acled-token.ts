/**
 * ACLED OAuth access-token manager.
 *
 * ACLED access tokens (password grant) expire after ~24h, and the API is used
 * with a static Bearer token. To keep the conflict/unrest/risk layers alive
 * without manual token rotation, this module fetches a token at runtime from
 * ACLED credentials and caches it in Redis (shared across serverless
 * invocations) plus an in-memory fast path for warm instances.
 *
 * Resolution order:
 *   1. ACLED_USERNAME + ACLED_PASSWORD set → fetch/refresh via OAuth and cache.
 *   2. Otherwise fall back to a static ACLED_ACCESS_TOKEN (legacy behaviour).
 *
 * Returns null when nothing is configured or a refresh fails — callers treat
 * that as "ACLED disabled" and degrade gracefully (empty result).
 */

declare const process: { env: Record<string, string | undefined> };

import { CHROME_UA } from './constants';
import { getCachedJson, setCachedJson } from './redis';

const ACLED_OAUTH_URL = 'https://acleddata.com/oauth/token';
const TOKEN_CACHE_KEY = 'acled:oauth:access-token';
const DEFAULT_TTL_SECONDS = 86_400; // ACLED access tokens last ~24h
const TTL_SAFETY_MARGIN = 300; // refresh 5 min before expiry
const OAUTH_TIMEOUT_MS = 15_000;
const REDIS_RECHECK_MS = 60_000; // how long to trust a Redis-sourced token before re-reading

interface CachedToken {
  token: string;
}

interface OAuthResponse {
  access_token?: string;
  expires_in?: number;
}

// Fast path within a warm serverless instance.
let memoToken: string | null = null;
let memoExpiresAt = 0;
// Coalesces concurrent refreshes so only one OAuth call goes out at a time.
let inflight: Promise<string | null> | null = null;

async function requestNewToken(): Promise<string | null> {
  const username = process.env.ACLED_USERNAME;
  const password = process.env.ACLED_PASSWORD;
  if (!username || !password) return null;

  const body = new URLSearchParams({
    username,
    password,
    grant_type: 'password',
    client_id: process.env.ACLED_CLIENT_ID || 'acled',
  });

  let resp: Response;
  try {
    resp = await fetch(ACLED_OAUTH_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        // acleddata.com sits behind Cloudflare, which returns 1010 to
        // non-browser User-Agents — send a browser UA.
        'User-Agent': CHROME_UA,
      },
      body: body.toString(),
      signal: AbortSignal.timeout(OAUTH_TIMEOUT_MS),
    });
  } catch {
    return null;
  }
  if (!resp.ok) return null;

  let data: OAuthResponse;
  try {
    data = (await resp.json()) as OAuthResponse;
  } catch {
    return null;
  }
  const token = data.access_token;
  if (!token) return null;

  const ttl = Math.max(60, (data.expires_in || DEFAULT_TTL_SECONDS) - TTL_SAFETY_MARGIN);
  memoToken = token;
  memoExpiresAt = Date.now() + ttl * 1000;
  await setCachedJson(TOKEN_CACHE_KEY, { token } as CachedToken, ttl);
  return token;
}

export async function getAcledToken(): Promise<string | null> {
  const hasCreds = Boolean(process.env.ACLED_USERNAME && process.env.ACLED_PASSWORD);
  if (!hasCreds) {
    // Legacy path: a manually-set, manually-rotated static token.
    return process.env.ACLED_ACCESS_TOKEN || null;
  }

  // Warm in-memory fast path.
  if (memoToken && Date.now() < memoExpiresAt) return memoToken;

  // Shared Redis cache (survives across cold starts and instances).
  const cached = (await getCachedJson(TOKEN_CACHE_KEY)) as CachedToken | null;
  if (cached?.token) {
    memoToken = cached.token;
    // Redis owns the real TTL; trust this token briefly, then re-check Redis.
    memoExpiresAt = Date.now() + REDIS_RECHECK_MS;
    return cached.token;
  }

  // Cache miss — refresh once, shared by concurrent callers.
  if (!inflight) {
    inflight = requestNewToken().finally(() => {
      inflight = null;
    });
  }
  return inflight;
}

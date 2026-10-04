/**
 * Thin HTTP client for the Koru Shield v1 API.
 * Auth: Authorization: Bearer <api-key> (user creates keys in the dashboard).
 * Base URL configurable via KORU_SHIELD_API_URL, defaults to production.
 */

const DEFAULT_BASE_URL = "https://my.korushield.com/api";

export interface KoruClientOptions {
  apiKey: string;
  baseUrl?: string;
}

export class KoruApiError extends Error {
  status: number;
  body: string;
  constructor(status: number, body: string) {
    super(`Koru Shield API error ${status}: ${body.slice(0, 300)}`);
    this.status = status;
    this.body = body;
  }
}

export class KoruClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(opts: KoruClientOptions) {
    if (!opts.apiKey) throw new Error("Koru Shield API key is required");
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl || process.env.KORU_SHIELD_API_URL || DEFAULT_BASE_URL).replace(/\/$/, "");
  }

  private async request<T>(method: string, path: string, body?: unknown, query?: Record<string, string | undefined>): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== "") url.searchParams.set(k, v);
      }
    }
    const res = await fetch(url.toString(), {
      method,
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": "koru-shield-mcp/1.0",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) throw new KoruApiError(res.status, text);
    if (!text) return undefined as T;
    try {
      const parsed = JSON.parse(text);
      // v1 envelope: { data, meta } - unwrap for convenience
      if (parsed && typeof parsed === "object" && "data" in parsed && "meta" in parsed) {
        return parsed.data as T;
      }
      return parsed as T;
    } catch {
      return text as unknown as T;
    }
  }

  get<T>(path: string, query?: Record<string, string | undefined>): Promise<T> {
    return this.request<T>("GET", path, undefined, query);
  }
  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }
  patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PATCH", path, body);
  }
  delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }
}

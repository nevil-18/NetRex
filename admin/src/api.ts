export type Severity = "low" | "medium" | "high" | "critical";

export type BlacklistEntry = {
  domain: string;
  reason: string;
  added_at: string;
  severity: Severity;
  updated_at?: string;
};

export type AnalyzeResult = {
  domain: string;
  url: string;
  blocked: boolean;
  score: number;
  level: string;
  factors: string[];
  summary: string;
  recommendations: string[];
  blacklist: BlacklistEntry | null;
  mentions: Array<{
    domain: string;
    reason: string;
    severity: Severity;
    count: number;
    sources: string[];
    contexts: string[];
  }>;
  llm: boolean;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ ok: boolean; blacklist: { total: number } }>("/api/health"),
  stats: () =>
    request<{ total: number; by_severity: Record<string, number> }>("/api/stats"),
  list: () => request<{ domains: BlacklistEntry[]; total: number }>("/api/blacklist"),
  add: (payload: { domain: string; reason?: string; severity?: Severity }) =>
    request<{ ok: boolean; entry: BlacklistEntry }>("/api/blacklist", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  remove: (domain: string) =>
    request<{ ok: boolean }>(`/api/blacklist/${encodeURIComponent(domain)}`, {
      method: "DELETE",
    }),
  analyze: (url: string, html?: string) =>
    request<AnalyzeResult>("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ url, html, use_llm: true }),
    }),
};

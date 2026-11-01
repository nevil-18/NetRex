export const DEFAULT_API_BASE = "http://127.0.0.1:8741";

export async function getApiBase() {
  const stored = await chrome.storage.sync.get(["apiBase"]);
  return (stored.apiBase || DEFAULT_API_BASE).replace(/\/$/, "");
}

export async function apiFetch(path, options = {}) {
  const base = await getApiBase();
  const res = await fetch(`${base}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

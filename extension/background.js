import { apiFetch, getApiBase, DEFAULT_API_BASE } from "./config.js";

const tabState = new Map();

function hostnameFromUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return null;
  }
}

function isExtensionPage(url) {
  return !url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("devtools://");
}

async function checkUrl(url) {
  return apiFetch("/api/check", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

async function scanHtml(url, html) {
  // Cap payload size for hackathon demos
  const trimmed = (html || "").slice(0, 350000);
  return apiFetch("/api/scan", {
    method: "POST",
    body: JSON.stringify({ url, html: trimmed }),
  });
}

async function analyzeUrl(url, html) {
  const trimmed = html ? html.slice(0, 120000) : null;
  return apiFetch("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ url, html: trimmed, use_llm: true }),
  });
}

function setBadge(tabId, level, blocked) {
  // Benchmark: low / medium / high / critical (+ unknown)
  let text = "";
  let color = "#1f7a5c";
  if (blocked || level === "critical") {
    text = "!";
    color = "#e84b3a";
  } else if (level === "high") {
    text = "H";
    color = "#c9851a";
  } else if (level === "medium") {
    text = "M";
    color = "#b8932e";
  } else if (level === "low") {
    text = "L";
    color = "#1f7a5c";
  } else if (level === "unknown") {
    text = "?";
    color = "#6b7280";
  }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

async function protectTab(tabId, url) {
  if (isExtensionPage(url)) return;
  const host = hostnameFromUrl(url);
  if (!host) return;

  try {
    const result = await checkUrl(url);
    const severity = result.severity ?? result.score;
    const level = result.level || "unknown";
    // Critical (80–100) blocks like the blacklist
    const shouldBlock = Boolean(result.blocked) || level === "critical";
    tabState.set(tabId, {
      url,
      domain: result.domain,
      blocked: shouldBlock,
      score: severity,
      severity,
      level,
      summary: result.summary,
      factors: result.factors || [],
      recommendations: result.recommendations || [],
      criteria: result.criteria || null,
      entry: result.entry || null,
      updatedAt: Date.now(),
    });
    setBadge(tabId, level, shouldBlock);

    if (shouldBlock) {
      const blockedUrl =
        chrome.runtime.getURL("blocked.html") +
        `?domain=${encodeURIComponent(result.domain)}` +
        `&score=${encodeURIComponent(severity ?? "")}` +
        `&reason=${encodeURIComponent(result.entry?.reason || result.summary || "")}` +
        `&target=${encodeURIComponent(url)}`;
      await chrome.tabs.update(tabId, { url: blockedUrl });
    }
  } catch (err) {
    tabState.set(tabId, {
      url,
      domain: host,
      error: String(err.message || err),
      updatedAt: Date.now(),
    });
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7280" });
  }
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (details.url.includes("blocked.html")) return;
  void protectTab(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handle = async () => {
    if (message.type === "GET_TAB_STATE") {
      const tabId = message.tabId ?? sender.tab?.id;
      return tabState.get(tabId) || null;
    }
    if (message.type === "SCAN_PAGE") {
      const tabId = sender.tab?.id;
      const url = message.url || sender.tab?.url || "";
      const scan = await scanHtml(url, message.html || "");
      if (tabId != null) {
        const prev = tabState.get(tabId) || {};
        tabState.set(tabId, {
          ...prev,
          url,
          mentions: scan.matches,
          highlights: scan.highlights,
          updatedAt: Date.now(),
        });
      }
      return scan;
    }
    if (message.type === "ANALYZE_TAB") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id || !tab.url || isExtensionPage(tab.url)) {
        throw new Error("Open a normal webpage to analyze.");
      }
      let html = "";
      try {
        const [{ result }] = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => document.documentElement.outerHTML,
        });
        html = result || "";
      } catch {
        html = "";
      }
      const analysis = await analyzeUrl(tab.url, html);
      tabState.set(tab.id, {
        ...(tabState.get(tab.id) || {}),
        ...analysis,
        url: tab.url,
        updatedAt: Date.now(),
      });
      setBadge(tab.id, analysis.level, analysis.blocked);
      return analysis;
    }
    if (message.type === "GET_CONFIG") {
      return { apiBase: await getApiBase(), defaultApiBase: DEFAULT_API_BASE };
    }
    if (message.type === "SET_API_BASE") {
      await chrome.storage.sync.set({ apiBase: message.apiBase });
      return { ok: true };
    }
    if (message.type === "RECHECK") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id && tab.url) await protectTab(tab.id, tab.url);
      return tabState.get(tab?.id) || null;
    }
    throw new Error(`Unknown message ${message.type}`);
  };

  handle().then(sendResponse).catch((err) => sendResponse({ error: String(err.message || err) }));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(["apiBase"], (data) => {
    if (!data.apiBase) {
      chrome.storage.sync.set({ apiBase: DEFAULT_API_BASE });
    }
  });
});

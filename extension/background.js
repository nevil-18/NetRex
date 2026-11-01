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

// Gmail is checked one email at a time, never as a website: scoring it would send the
// inbox to the AI model and rate Google rather than the mail.
function isGmail(url) {
  return hostnameFromUrl(url) === "mail.google.com";
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

async function fetchReport(url, html) {
  return apiFetch("/api/report", {
    method: "POST",
    body: JSON.stringify({ url, html: (html || "").slice(0, 1000000) }),
  });
}

async function fetchEmailReport(raw) {
  return apiFetch("/api/email-report", {
    method: "POST",
    body: JSON.stringify({ raw }),
  });
}

const reportKey = (tabId) => `report:${tabId}`;

// Session storage survives the service worker being stopped while idle.
async function saveReport(tabId, url, report) {
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch {
    return; // tab closed while the report was generating
  }
  // The tab moved to another site while this report was generating.
  if (hostnameFromUrl(tab.url) !== hostnameFromUrl(url)) return;

  await chrome.storage.session.set({ [reportKey(tabId)]: report });
  if (report.severity == null) return;
  setBadge(tabId, report.level, tabState.get(tabId)?.blocked);
  tabState.set(tabId, {
    ...(tabState.get(tabId) || {}),
    url,
    domain: report.domain,
    score: report.severity,
    level: report.level,
    summary: report.summary,
    factors: report.criteria.flatMap((c) => c.evidence),
    updatedAt: Date.now(),
  });
}

// NetRex's own dashboard and API docs aren't worth a Gemini request. The demo
// threat page is served from the same place but exists to be scored.
function isNetRexPage(url) {
  const { hostname, port, pathname } = new URL(url);
  return (
    ["127.0.0.1", "localhost"].includes(hostname) &&
    ["8741", "8742"].includes(port) &&
    !pathname.startsWith("/demo/")
  );
}

async function shouldRunReport(url, manual) {
  if (isNetRexPage(url) || isGmail(url)) return false;
  if (!manual) {
    const { autoReport } = await chrome.storage.sync.get(["autoReport"]);
    if (autoReport === false) return false;
  }
  // Blocked pages are about to be replaced by the interstitial.
  const check = await checkUrl(url);
  return !check.blocked;
}

function setBadge(tabId, level, blocked) {
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
    color = "#4d8f74";
  } else if (level === "safe") {
    text = "OK";
    color = "#1f7a5c";
  }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

async function protectTab(tabId, url) {
  if (isExtensionPage(url)) return;
  const host = hostnameFromUrl(url);
  if (!host) return;
  if (isGmail(url)) {
    tabState.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  try {
    const result = await checkUrl(url);
    tabState.set(tabId, {
      url,
      domain: result.domain,
      blocked: result.blocked,
      score: result.score,
      level: result.level,
      summary: result.summary,
      factors: result.factors || [],
      recommendations: result.recommendations || [],
      entry: result.entry || null,
      updatedAt: Date.now(),
    });
    setBadge(tabId, result.level, result.blocked);

    if (result.blocked) {
      const blockedUrl =
        chrome.runtime.getURL("blocked.html") +
        `?domain=${encodeURIComponent(result.domain)}` +
        `&score=${encodeURIComponent(result.score)}` +
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
  void chrome.storage.session.remove(reportKey(details.tabId));
  if (details.url.includes("blocked.html")) return;
  void protectTab(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
  void chrome.storage.session.remove(reportKey(tabId));
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
      if (isGmail(tab.url)) throw new Error("Gmail isn't scored as a website. Check an email instead.");
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
    if (message.type === "REPORT_GATE") {
      return { run: await shouldRunReport(message.url, Boolean(message.manual)) };
    }
    if (message.type === "GENERATE_REPORT") {
      const report = await fetchReport(message.url, message.html);
      if (sender.tab?.id != null) await saveReport(sender.tab.id, message.url, report);
      return report;
    }
    if (message.type === "CHECK_EMAIL") {
      return fetchEmailReport(message.raw);
    }
    if (message.type === "GET_REPORT") {
      const key = reportKey(sender.tab?.id);
      return (await chrome.storage.session.get([key]))[key] || null;
    }
    if (message.type === "CLOSE_REPORT_FRAME") {
      await chrome.tabs.sendMessage(sender.tab.id, { type: "CLOSE_REPORT_FRAME" }, { frameId: 0 });
      return { ok: true };
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

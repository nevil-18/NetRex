const scoreEl = document.getElementById("score");
const levelEl = document.getElementById("level");
const domainEl = document.getElementById("domain");
const summaryEl = document.getElementById("summary");
const factorsEl = document.getElementById("factors");
const tipsEl = document.getElementById("tips");
const statusPill = document.getElementById("status-pill");
const errorEl = document.getElementById("error");
const gaugeArc = document.getElementById("gauge-arc");

const CIRC = 169.65;

function colorFor(score) {
  if (score >= 85) return "#e84b3a";
  if (score >= 65) return "#c9851a";
  if (score >= 40) return "#b8932e";
  if (score >= 20) return "#4d8f74";
  return "#1f7a5c";
}

function renderList(el, items, ordered) {
  el.innerHTML = "";
  if (!items || !items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No details yet.";
    el.appendChild(li);
    return;
  }
  items.slice(0, 5).forEach((item) => {
    const li = document.createElement(ordered ? "li" : "li");
    li.textContent = item;
    el.appendChild(li);
  });
}

function paint(state) {
  errorEl.hidden = true;
  if (!state) {
    scoreEl.textContent = "—";
    levelEl.textContent = "no page";
    domainEl.textContent = "—";
    summaryEl.textContent = "Open a website to begin protection.";
    statusPill.textContent = "Idle";
    statusPill.className = "pill";
    return;
  }
  if (state.error) {
    errorEl.hidden = false;
    errorEl.textContent = state.error;
    statusPill.textContent = "API offline";
    statusPill.className = "pill";
  }

  const score = Number(state.score ?? 0);
  const level = state.level || "unknown";
  scoreEl.textContent = Number.isFinite(score) ? String(score) : "—";
  scoreEl.style.color = colorFor(score);
  levelEl.textContent = `${level} risk`;
  gaugeArc.style.stroke = colorFor(score);
  gaugeArc.style.strokeDashoffset = String(CIRC - (Math.min(100, Math.max(0, score)) / 100) * CIRC);

  domainEl.textContent = state.domain || "—";
  summaryEl.textContent = state.summary || "No summary yet.";
  renderList(factorsEl, state.factors, false);
  renderList(tipsEl, state.recommendations, true);

  if (state.blocked) {
    statusPill.textContent = "Blocked";
    statusPill.className = "pill blocked";
  } else if (level === "high" || level === "critical") {
    statusPill.textContent = level;
    statusPill.className = "pill high";
  } else if (level === "safe" || level === "low") {
    statusPill.textContent = level;
    statusPill.className = "pill safe";
  } else {
    statusPill.textContent = level;
    statusPill.className = "pill";
  }
}

async function load() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const state = await chrome.runtime.sendMessage({
    type: "GET_TAB_STATE",
    tabId: tab?.id,
  });
  if (state?.error && !state.score) {
    paint(state);
    return;
  }
  paint(state);
}

document.getElementById("analyze").addEventListener("click", async () => {
  statusPill.textContent = "Analyzing…";
  const result = await chrome.runtime.sendMessage({ type: "ANALYZE_TAB" });
  if (result?.error) {
    paint({ error: result.error, score: 0, level: "unknown", domain: "—" });
    return;
  }
  paint(result);
});

document.getElementById("recheck").addEventListener("click", async () => {
  statusPill.textContent = "Recheck…";
  const result = await chrome.runtime.sendMessage({ type: "RECHECK" });
  paint(result);
});

document.getElementById("options").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

void load();

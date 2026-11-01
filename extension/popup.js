const scoreEl = document.getElementById("score");
const levelEl = document.getElementById("level");
const domainEl = document.getElementById("domain");
const summaryEl = document.getElementById("summary");
const factorsEl = document.getElementById("factors");
const tipsEl = document.getElementById("tips");
const statusPill = document.getElementById("status-pill");
const errorEl = document.getElementById("error");
const gaugeArc = document.getElementById("gauge-arc");
const brandFrom = document.getElementById("brand-from");
const brandTo = document.getElementById("brand-to");

const CIRC = 169.65;

function runBrandTransition() {
  if (!brandFrom || !brandTo) return;
  window.setTimeout(() => {
    brandFrom.classList.add("is-leaving");
  }, 1800);
  window.setTimeout(() => {
    brandFrom.classList.add("is-hidden");
    brandTo.classList.add("is-entering");
    brandTo.removeAttribute("aria-hidden");
    brandTo.querySelectorAll(".brand-headline__letter").forEach((el, i) => {
      el.style.animationDelay = `${i * 55}ms`;
    });
  }, 2400);
}

runBrandTransition();

/** Benchmark: 0–29 low, 30–59 medium, 60–79 high, 80–100 critical */
function colorFor(score) {
  if (score == null || Number.isNaN(Number(score))) return "#6b7280";
  if (score >= 80) return "#e84b3a";
  if (score >= 60) return "#c9851a";
  if (score >= 30) return "#b8932e";
  return "#1f7a5c";
}

function renderList(el, items) {
  el.innerHTML = "";
  if (!items || !items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No details yet.";
    el.appendChild(li);
    return;
  }
  items.slice(0, 5).forEach((item) => {
    const li = document.createElement("li");
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

  const raw = state.severity ?? state.score;
  const unknown = raw == null || raw === "" || Number.isNaN(Number(raw));
  const score = unknown ? null : Number(raw);
  const level = state.level || (unknown ? "unknown" : "low");

  scoreEl.textContent = unknown ? "?" : String(score);
  scoreEl.style.color = colorFor(score);
  levelEl.textContent = unknown ? "unknown severity" : `${level} · ${score}%`;
  gaugeArc.style.stroke = colorFor(score);
  gaugeArc.style.strokeDashoffset = String(
    unknown ? CIRC : CIRC - (Math.min(100, Math.max(0, score)) / 100) * CIRC
  );

  domainEl.textContent = state.domain || "—";
  summaryEl.textContent = state.summary || "No summary yet.";
  renderList(factorsEl, state.factors);
  renderList(tipsEl, state.recommendations);

  if (state.blocked || level === "critical") {
    statusPill.textContent = state.blocked ? "Blocked" : "Critical";
    statusPill.className = "pill blocked";
  } else if (level === "high") {
    statusPill.textContent = "High";
    statusPill.className = "pill high";
  } else if (level === "medium") {
    statusPill.textContent = "Medium";
    statusPill.className = "pill";
  } else if (level === "unknown") {
    statusPill.textContent = "Unknown";
    statusPill.className = "pill";
  } else {
    statusPill.textContent = "Low";
    statusPill.className = "pill safe";
  }
}

async function load() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const state = await chrome.runtime.sendMessage({
    type: "GET_TAB_STATE",
    tabId: tab?.id,
  });
  if (state?.error && state.score == null && state.severity == null) {
    paint(state);
    return;
  }
  paint(state);
}

document.getElementById("analyze").addEventListener("click", async () => {
  statusPill.textContent = "Analyzing…";
  const result = await chrome.runtime.sendMessage({ type: "ANALYZE_TAB" });
  if (result?.error) {
    paint({ error: result.error, score: null, level: "unknown", domain: "—" });
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

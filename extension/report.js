// Report text comes from the model and the page, so it is only set through textContent.
const byId = (id) => document.getElementById(id);

function levelFor(score) {
  if (score < 30) return "low";
  if (score < 60) return "medium";
  if (score < 80) return "high";
  return "critical";
}

function capitalize(word) {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

function showNotice(text) {
  byId("notice").hidden = false;
  byId("notice").textContent = text;
}

function renderDescription(text) {
  const container = byId("description");
  for (const paragraph of text.split("\n\n")) {
    const p = document.createElement("p");
    p.textContent = paragraph;
    container.appendChild(p);
  }
  byId("description-section").hidden = false;
}

function renderCriteria(criteria) {
  const list = byId("criteria");
  for (const item of criteria) {
    const li = document.createElement("li");
    li.dataset.level = levelFor(item.score);

    const head = document.createElement("div");
    head.className = "criterion-head";
    const name = document.createElement("span");
    name.textContent = item.label;
    const value = document.createElement("span");
    value.textContent = `${item.score}/100 · ${item.weight}% weight`;
    head.append(name, value);

    const meter = document.createElement("div");
    meter.className = "meter";
    const fill = document.createElement("span");
    fill.style.width = `${item.score}%`;
    meter.appendChild(fill);

    li.append(head, meter);
    list.appendChild(li);
  }
  byId("criteria-section").hidden = false;
}

function render(report) {
  if (!report) {
    byId("domain").textContent = "No report yet";
    showNotice("This page has no risk report yet. Use the Report button in the Guardian popup.");
    return;
  }

  byId("domain").textContent = report.domain;
  if (report.severity == null) {
    showNotice(report.error || "The page could not be scored.");
    byId("meta").textContent = "An unknown result is not a safe result. Treat this page with care.";
    return;
  }

  byId("score-card").dataset.level = report.level;
  byId("score").textContent = `${report.severity}%`;
  byId("severity").textContent = capitalize(report.level);
  byId("meter-fill").style.width = `${report.severity}%`;
  byId("meter").setAttribute("aria-label", `Risk score ${report.severity} percent`);

  if (report.on_blacklist) showNotice("This domain is on your Guardian blacklist.");
  renderDescription(report.report);
  renderCriteria(report.criteria);

  const when = new Date(report.generated_at).toLocaleString();
  byId("meta").textContent = report.cached
    ? `Saved report from ${when}, by ${report.model}. Purge it in the dashboard to regenerate. AI assessments can be wrong.`
    : `Generated at ${when} by ${report.model}. AI assessments can be wrong.`;
}

function close() {
  void chrome.runtime.sendMessage({ type: "CLOSE_REPORT_FRAME" });
}

byId("close").addEventListener("click", close);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") close();
});

chrome.runtime.sendMessage({ type: "GET_REPORT" }).then(render);

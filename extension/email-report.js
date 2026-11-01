// Report text comes from the email and the model, so it is only set through textContent.
const byId = (id) => document.getElementById(id);

const SAMPLE_EMAIL = `Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypal-verify-account.net; dkim=none; dmarc=fail
From: "PayPal Security" <alert@paypal-verify-account.net>
Reply-To: billing.help@gmail.com
Subject: Your account will be suspended in 24 hours
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Dear customer,</p>
<p>We noticed unusual activity. Verify your password and card details within 24 hours or your account will be closed.</p>
<p><a href="https://paypal-verify-account.net/login">https://www.paypal.com/signin</a></p>`;

function levelFor(score) {
  if (score < 30) return "low";
  if (score < 60) return "medium";
  if (score < 80) return "high";
  return "critical";
}

function capitalize(word) {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

function setText(id, text) {
  const element = byId(id);
  element.textContent = text || "";
  element.hidden = !text;
}

function fillList(id, items, build) {
  const list = byId(id);
  list.replaceChildren(
    ...items.map((item) => {
      const li = document.createElement("li");
      build(li, item);
      return li;
    }),
  );
}

function code(text) {
  const element = document.createElement("code");
  element.textContent = text;
  return element;
}

function severityChip(level) {
  const chip = document.createElement("span");
  chip.className = "level-chip";
  chip.dataset.level = level;
  chip.textContent = level;
  return chip;
}

function renderAuth(report) {
  byId("no-headers").hidden = report.headers_available;
  byId("auth").replaceChildren(
    ...(report.headers_available ? Object.entries(report.authentication) : []).map(([method, result]) => {
      const chip = document.createElement("span");
      chip.className = "auth-chip";
      chip.dataset.result = result === "pass" ? "pass" : result === "not_available" ? "none" : "fail";
      chip.textContent = `${method.toUpperCase()}: ${result === "not_available" ? "not available" : result}`;
      return chip;
    }),
  );
  const replyTo = report.reply_to_domain;
  setText(
    "reply-to",
    replyTo && replyTo !== report.domain ? `Replies go to ${replyTo}, not ${report.domain || "the sender"}.` : "",
  );
}

function renderCriteria(report) {
  fillList("criteria", report.criteria, (li, item) => {
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

    const evidence = document.createElement("ul");
    evidence.className = "evidence";
    for (const line of item.evidence) {
      const row = document.createElement("li");
      row.textContent = line;
      evidence.appendChild(row);
    }
    li.appendChild(evidence);
  });
  setText("not-assessed", report.not_assessed.length ? `Not scored. ${report.not_assessed.join(" ")}` : "");
  byId("adjustments").replaceChildren(
    ...report.adjustments.map((note) => {
      const p = document.createElement("p");
      p.className = "adjustment";
      p.textContent = note;
      return p;
    }),
  );
  byId("criteria-section").hidden = false;
}

function render(report) {
  const scored = report.severity != null;
  byId("heading").textContent = "Email risk report";

  byId("score-card").dataset.level = report.level;
  byId("score").textContent = scored ? `${report.severity}%` : "—";
  byId("severity").textContent = capitalize(report.level);
  byId("meter-fill").style.width = scored ? `${report.severity}%` : "0";
  byId("meter").setAttribute("aria-label", scored ? `Risk score ${report.severity} percent` : "Risk score not available");
  byId("meaning").textContent = report.severity_meaning;
  setText("attack-type", report.attack_type_label);
  setText("summary", report.summary);
  setText("report-error", report.error);

  byId("subject").textContent = report.subject || "(no subject)";
  byId("sender").textContent = report.sender || "Sender not provided";
  setText("brand", report.impersonated_brand ? `Imitating: ${report.impersonated_brand}` : "");
  setText(
    "injection",
    report.prompt_injection_detected
      ? `This email contains text aimed at the AI${report.injection_excerpt ? `: "${report.injection_excerpt}"` : "."}`
      : "",
  );

  fillList("actions", report.recommended_actions, (li, action) => {
    li.textContent = action;
  });
  renderAuth(report);

  byId("links-section").hidden = report.mismatched_links.length === 0;
  fillList("links", report.mismatched_links, (li, link) => {
    li.append(`Shows ${link.text}, but goes to `, code(link.host));
  });
  byId("attachments-section").hidden = report.attachments.length === 0;
  fillList("attachments", report.attachments, (li, file) => {
    li.append(code(file.name));
    if (file.dangerous) li.append(" ", severityChip("high"));
  });
  byId("blacklist-section").hidden = report.blacklisted_domains.length === 0;
  fillList("blacklist", report.blacklisted_domains, (li, hit) => {
    li.append(code(hit.domain), " ", severityChip(hit.severity));
  });

  if (scored) renderCriteria(report);
  else byId("criteria-section").hidden = true;

  byId("meta").textContent = scored
    ? `${report.cached ? "Saved report from" : "Generated"} ${new Date(report.generated_at).toLocaleString()} by ${report.model}. AI assessments can be wrong.`
    : "An unknown result is not a safe result.";

  byId("paste-view").hidden = true;
  byId("report-view").hidden = false;
  window.scrollTo(0, 0);
  byId("close").focus();
}

// The server explains rejected emails in {"detail": ...}. Anything else means it wasn't reached.
function describeError(message) {
  try {
    const { detail } = JSON.parse(message);
    if (typeof detail === "string") return detail;
  } catch {
    /* not a server reply */
  }
  return "The NetRex server could not be reached.";
}

function syncSubmit() {
  byId("submit").disabled = !byId("raw").value.trim();
}

byId("raw").addEventListener("input", syncSubmit);

byId("sample").addEventListener("click", () => {
  byId("raw").value = SAMPLE_EMAIL;
  syncSubmit();
});

byId("paste-view").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = byId("submit");
  submit.disabled = true;
  submit.textContent = "Scoring…";
  setText("error", "");
  try {
    const report = await chrome.runtime.sendMessage({ type: "CHECK_EMAIL", raw: byId("raw").value });
    if (!report || report.severity === undefined) throw new Error(report?.error || "");
    render(report);
  } catch (err) {
    setText("error", describeError(err.message));
  } finally {
    submit.textContent = "Score email";
    syncSubmit();
  }
});

byId("again").addEventListener("click", () => {
  byId("raw").value = "";
  syncSubmit();
  byId("heading").textContent = "Paste an email";
  byId("report-view").hidden = true;
  byId("paste-view").hidden = false;
  byId("raw").focus();
});

function close() {
  void chrome.runtime.sendMessage({ type: "CLOSE_REPORT_FRAME" });
}

byId("close").addEventListener("click", close);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") close();
});

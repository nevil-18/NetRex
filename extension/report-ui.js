(() => {
  const HOST_ID = "netrex-report-ui";
  // Gmail gets the paste-an-email panel instead of a report on the site itself.
  const ON_GMAIL = location.hostname === "mail.google.com";
  const LOW_TOAST_MS = 10000;
  const FAILED_TOAST_MS = 8000;
  // Saved reports return almost at once, so they skip the "generating" toast.
  const GENERATING_TOAST_DELAY_MS = 400;
  const STYLES = `
    :host { all: initial; }
    .toast {
      position: fixed; top: 16px; right: 16px; z-index: 2147483647;
      display: flex; align-items: stretch; width: 320px; max-width: calc(100vw - 32px);
      background: #0f1c1a; color: #f2f7f4; border-radius: 12px; overflow: hidden;
      border-left: 5px solid var(--accent, #7fa596);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
      font: 14px/1.4 "Segoe UI", system-ui, sans-serif;
      animation: slide-in 180ms ease-out;
    }
    .body {
      flex: 1; min-width: 0; display: flex; gap: 10px; align-items: center;
      padding: 12px; border: 0; background: none; color: inherit; font: inherit; text-align: left;
    }
    button.body { cursor: pointer; }
    button.body:hover { background: rgba(255, 255, 255, 0.07); }
    button:focus-visible { outline: 2px solid #f2f7f4; outline-offset: -3px; }
    .title { display: block; font-weight: 700; }
    .detail { display: block; color: #b7cdc3; font-size: 13px; overflow-wrap: anywhere; }
    .dismiss {
      flex: none; width: 34px; border: 0; background: none; color: #b7cdc3;
      font-size: 18px; cursor: pointer;
    }
    .dismiss:hover { color: #fff; background: rgba(255, 255, 255, 0.07); }
    .spinner {
      flex: none; width: 16px; height: 16px; border-radius: 50%;
      border: 2px solid rgba(255, 255, 255, 0.25); border-top-color: #f2f7f4;
      animation: spin 800ms linear infinite;
    }
    .frame {
      position: fixed; top: 16px; right: 16px; z-index: 2147483647;
      width: 420px; max-width: calc(100vw - 32px); height: calc(100vh - 32px);
      border: 0; border-radius: 16px; background: #f5f8f6;
      box-shadow: 0 16px 50px rgba(0, 0, 0, 0.4);
    }
    .launcher {
      position: fixed; bottom: 16px; left: 16px; z-index: 2147483646;
      display: flex; align-items: stretch; border-radius: 999px; overflow: hidden;
      background: #0f1c1a; color: #f2f7f4;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35);
      font: 600 13px/1 "Segoe UI", system-ui, sans-serif;
    }
    .launcher button { border: 0; background: none; color: inherit; font: inherit; cursor: pointer; }
    .launcher button:hover { background: rgba(255, 255, 255, 0.1); }
    .launcher .open { padding: 10px 6px 10px 14px; }
    .launcher .hide { padding: 10px 12px 10px 6px; color: #b7cdc3; font-size: 15px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes slide-in { from { opacity: 0; transform: translateY(-8px); } }
    @media (prefers-reduced-motion: reduce) {
      .toast { animation: none; }
      .spinner { animation-duration: 2.4s; }
    }
  `;
  const ACCENTS = { low: "#2f9e78", medium: "#d4aa2c", high: "#e8772e", critical: "#e84b3a" };

  let root = null;
  let toastEl = null;
  let toastTimer = null;
  let frameEl = null;
  let running = false;
  let hasReport = false;
  let launcherEl = null;
  let launcherDismissed = false;

  function ensureRoot() {
    if (root) return root;
    const host = document.createElement("div");
    host.id = HOST_ID;
    // A closed shadow root keeps page CSS and scripts out of this UI.
    root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLES;
    root.appendChild(style);
    document.documentElement.appendChild(host);
    return root;
  }

  function hideToast() {
    clearTimeout(toastTimer);
    toastEl?.remove();
    toastEl = null;
  }

  function showToast({ title, detail, accent, busy, onOpen, timeoutMs }) {
    hideToast();
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.setAttribute("role", "status");
    if (accent) toast.style.setProperty("--accent", accent);

    const body = document.createElement(onOpen ? "button" : "div");
    body.className = "body";
    if (busy) {
      const spinner = document.createElement("span");
      spinner.className = "spinner";
      body.appendChild(spinner);
    }
    const text = document.createElement("span");
    const titleEl = document.createElement("span");
    titleEl.className = "title";
    titleEl.textContent = title;
    const detailEl = document.createElement("span");
    detailEl.className = "detail";
    detailEl.textContent = detail;
    text.append(titleEl, detailEl);
    body.appendChild(text);
    toast.appendChild(body);

    if (onOpen) {
      body.type = "button";
      body.addEventListener("click", () => {
        hideToast();
        onOpen();
      });
    }

    const dismiss = document.createElement("button");
    dismiss.className = "dismiss";
    dismiss.type = "button";
    dismiss.setAttribute("aria-label", "Dismiss");
    dismiss.textContent = "×";
    dismiss.addEventListener("click", hideToast);
    toast.appendChild(dismiss);

    ensureRoot().appendChild(toast);
    toastEl = toast;
    if (timeoutMs) toastTimer = setTimeout(hideToast, timeoutMs);
  }

  function closeFrame() {
    frameEl?.remove();
    frameEl = null;
    if (ON_GMAIL) showLauncher();
  }

  function hideLauncher() {
    launcherEl?.remove();
    launcherEl = null;
  }

  function showLauncher() {
    if (launcherEl || launcherDismissed) return;
    const launcher = document.createElement("div");
    launcher.className = "launcher";

    const open = document.createElement("button");
    open.className = "open";
    open.type = "button";
    open.textContent = "NetRex: check an email";
    open.addEventListener("click", openFrame);

    const hide = document.createElement("button");
    hide.className = "hide";
    hide.type = "button";
    hide.setAttribute("aria-label", "Hide until this page reloads");
    hide.textContent = "×";
    hide.addEventListener("click", () => {
      launcherDismissed = true;
      hideLauncher();
    });

    launcher.append(open, hide);
    ensureRoot().appendChild(launcher);
    launcherEl = launcher;
  }

  function openFrame() {
    if (frameEl) return;
    hideLauncher();
    const frame = document.createElement("iframe");
    frame.className = "frame";
    frame.title = ON_GMAIL ? "NetRex email check" : "NetRex risk report";
    frame.src = chrome.runtime.getURL(ON_GMAIL ? "email-report.html" : "report.html");
    frame.addEventListener("load", () => frame.focus());
    ensureRoot().appendChild(frame);
    frameEl = frame;
  }

  function capitalize(word) {
    return word.charAt(0).toUpperCase() + word.slice(1);
  }

  function showResult(report) {
    hasReport = report.severity != null; // the popup's Report button retries failures
    if (report.severity == null) {
      showToast({
        title: "Risk report unavailable",
        detail: report.error || "The page could not be scored.",
        onOpen: openFrame,
        timeoutMs: FAILED_TOAST_MS,
      });
      return;
    }
    showToast({
      title: report.cached ? "Saved risk report" : "Risk report ready",
      detail: `${report.severity}% · ${capitalize(report.level)} severity · Click to view`,
      accent: ACCENTS[report.level],
      onOpen: openFrame,
      timeoutMs: report.cached || report.level === "low" ? LOW_TOAST_MS : 0,
    });
  }

  async function generate(manual) {
    if (running) return;
    running = true;
    let generatingTimer;
    try {
      const url = location.href;
      const gate = await chrome.runtime.sendMessage({ type: "REPORT_GATE", url, manual });
      if (gate?.error) throw new Error(gate.error);
      if (!gate?.run) return;

      generatingTimer = setTimeout(() => {
        showToast({
          title: "Generating risk report…",
          detail: location.hostname.replace(/^www\./, ""),
          busy: true,
        });
      }, GENERATING_TOAST_DELAY_MS);
      const report = await chrome.runtime.sendMessage({
        type: "GENERATE_REPORT",
        url,
        html: document.documentElement.outerHTML,
      });
      clearTimeout(generatingTimer);
      if (report?.error && report.severity === undefined) throw new Error(report.error);
      showResult(report);
    } catch {
      clearTimeout(generatingTimer);
      // An offline API on page load is already shown by the toolbar badge.
      if (manual || toastEl) {
        showToast({
          title: "Risk report unavailable",
          detail: "The NetRex server could not be reached.",
          timeoutMs: FAILED_TOAST_MS,
        });
      }
    } finally {
      running = false;
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "CLOSE_REPORT_FRAME") closeFrame();
    if (message.type === "SHOW_REPORT") {
      if (ON_GMAIL) {
        openFrame();
      } else if (hasReport) {
        hideToast();
        openFrame();
      } else {
        void generate(true);
      }
    }
  });

  if (ON_GMAIL) showLauncher();
  else if (document.contentType === "text/html" && document.body) void generate(false);
})();

(() => {
  const STYLE_ATTR = "data-guardian-highlight";
  let lastHighlights = [];
  let observerTimer = null;

  function clearHighlights() {
    document.querySelectorAll(`[${STYLE_ATTR}]`).forEach((el) => {
      const text = el.textContent;
      const parent = el.parentNode;
      if (!parent) return;
      parent.replaceChild(document.createTextNode(text || ""), el);
      parent.normalize();
    });
  }

  function walkTextNodes(root, callback) {
    const skip = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT", "CODE", "PRE"]);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (skip.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
        if (parent.closest(`[${STYLE_ATTR}]`)) return NodeFilter.FILTER_REJECT;
        if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    const nodes = [];
    let current = walker.nextNode();
    while (current) {
      nodes.push(current);
      current = walker.nextNode();
    }
    nodes.forEach(callback);
  }

  function highlightDomain(domain, severity) {
    if (!domain) return;
    const needle = domain.toLowerCase();
    walkTextNodes(document.body, (textNode) => {
      const value = textNode.nodeValue;
      const lower = value.toLowerCase();
      let idx = lower.indexOf(needle);
      if (idx < 0) return;

      const frag = document.createDocumentFragment();
      let cursor = 0;
      while (idx >= 0) {
        if (idx > cursor) {
          frag.appendChild(document.createTextNode(value.slice(cursor, idx)));
        }
        const mark = document.createElement("mark");
        mark.setAttribute(STYLE_ATTR, severity || "high");
        mark.className = `guardian-mark guardian-${severity || "high"}`;
        mark.title = `NetRex: blacklisted domain (${domain})`;
        mark.textContent = value.slice(idx, idx + needle.length);
        frag.appendChild(mark);
        cursor = idx + needle.length;
        idx = lower.indexOf(needle, cursor);
      }
      if (cursor < value.length) {
        frag.appendChild(document.createTextNode(value.slice(cursor)));
      }
      textNode.parentNode.replaceChild(frag, textNode);
    });

    document.querySelectorAll("a[href]").forEach((a) => {
      const href = (a.getAttribute("href") || "").toLowerCase();
      if (href.includes(needle) && !a.querySelector(`[${STYLE_ATTR}]`)) {
        a.classList.add("guardian-link-flag");
        a.setAttribute("data-guardian-domain", domain);
        a.title = `NetRex warning: link points to blacklisted domain ${domain}`;
      }
    });
  }

  let applying = false;
  let lastSignature = "";

  function applyHighlights(highlights) {
    applying = true;
    try {
      clearHighlights();
      lastHighlights = highlights || [];
      lastHighlights.forEach((h) => highlightDomain(h.domain, h.severity));
    } finally {
      // Allow the DOM to settle before listening again
      setTimeout(() => {
        applying = false;
      }, 50);
    }
  }

  async function scanPage() {
    if (applying) return;
    try {
      const html = document.documentElement.outerHTML;
      const response = await chrome.runtime.sendMessage({
        type: "SCAN_PAGE",
        url: location.href,
        html,
      });
      if (response?.error) return;
      const signature = JSON.stringify(response.highlights || []);
      if (signature === lastSignature) return;
      lastSignature = signature;
      applyHighlights(response.highlights || []);
    } catch {
      /* API may be offline during development */
    }
  }

  function scheduleScan() {
    if (applying) return;
    clearTimeout(observerTimer);
    observerTimer = setTimeout(() => {
      void scanPage();
    }, 1200);
  }

  if (document.body) {
    void scanPage();
    const observer = new MutationObserver((mutations) => {
      if (applying) return;
      const relevant = mutations.some((m) => {
        const nodes = [...m.addedNodes, ...m.removedNodes];
        return nodes.some(
          (n) =>
            !(n.nodeType === 1 && n.hasAttribute?.(STYLE_ATTR)) &&
            !(n.nodeType === 1 && n.classList?.contains("guardian-link-flag")),
        );
      });
      if (relevant) scheduleScan();
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: false,
    });
  }
})();

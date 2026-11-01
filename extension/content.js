(() => {
  const STYLE_ATTR = "data-guardian-highlight";
  const UI_HOST_ID = "guardian-report-ui";
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
    document.querySelectorAll("a.guardian-link-flag").forEach((a) => {
      a.classList.remove("guardian-link-flag");
      a.removeAttribute("data-guardian-domain");
      a.removeAttribute("title");
    });
  }

  // Match on label boundaries: bit.ly must not match rabbit.ly or bit.ly.evil.com.
  function domainPattern(domain) {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(?<![a-z0-9-])${escaped}(?![a-z0-9-]|\\.[a-z0-9])`, "gi");
  }

  function linkPointsTo(anchor, domain) {
    try {
      const host = new URL(anchor.href).hostname.toLowerCase();
      return host === domain || host.endsWith(`.${domain}`);
    } catch {
      return false;
    }
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
    const pattern = domainPattern(needle);
    walkTextNodes(document.body, (textNode) => {
      const value = textNode.nodeValue;
      const found = [...value.matchAll(pattern)];
      if (!found.length) return;

      const frag = document.createDocumentFragment();
      let cursor = 0;
      for (const match of found) {
        if (match.index > cursor) {
          frag.appendChild(document.createTextNode(value.slice(cursor, match.index)));
        }
        const mark = document.createElement("mark");
        mark.setAttribute(STYLE_ATTR, severity || "high");
        mark.className = `guardian-mark guardian-${severity || "high"}`;
        mark.title = `Guardian: blacklisted domain (${domain})`;
        mark.textContent = match[0];
        frag.appendChild(mark);
        cursor = match.index + match[0].length;
      }
      if (cursor < value.length) {
        frag.appendChild(document.createTextNode(value.slice(cursor)));
      }
      textNode.parentNode.replaceChild(frag, textNode);
    });

    document.querySelectorAll("a[href]").forEach((a) => {
      if (linkPointsTo(a, needle)) {
        a.classList.add("guardian-link-flag");
        a.setAttribute("data-guardian-domain", domain);
        a.title = `Guardian warning: link points to blacklisted domain ${domain}`;
      }
    });
  }

  let applying = false;
  let lastSignature = "";

  function applyHighlights(highlights, listChanged) {
    applying = true;
    try {
      // With the same list, only newly added page content still needs marks.
      if (listChanged) clearHighlights();
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
      const listChanged = signature !== lastSignature;
      lastSignature = signature;
      applyHighlights(response.highlights || [], listChanged);
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
            n.id !== UI_HOST_ID &&
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

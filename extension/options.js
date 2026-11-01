import { DEFAULT_API_BASE, getApiBase } from "./config.js";

const input = document.getElementById("apiBase");
const msg = document.getElementById("msg");

getApiBase().then((base) => {
  input.value = base || DEFAULT_API_BASE;
});

const autoReport = document.getElementById("autoReport");
chrome.storage.sync.get(["autoReport"]).then((stored) => {
  autoReport.checked = stored.autoReport !== false;
});

document.getElementById("save").addEventListener("click", async () => {
  const apiBase = (input.value || DEFAULT_API_BASE).trim().replace(/\/$/, "");
  await chrome.storage.sync.set({ apiBase, autoReport: autoReport.checked });
  msg.textContent = `Saved. Extension will use ${apiBase}`;
});

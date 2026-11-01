const params = new URLSearchParams(location.search);
document.getElementById("domain").textContent = params.get("domain") || "unknown";
document.getElementById("score").textContent = params.get("score") || "—";
document.getElementById("reason").textContent =
  params.get("reason") || "This domain is on the Guardian blacklist.";
document.getElementById("target").textContent = params.get("target") || "—";

document.getElementById("back").addEventListener("click", () => {
  if (history.length > 1) {
    history.back();
  } else {
    location.href = "https://www.google.com";
  }
});

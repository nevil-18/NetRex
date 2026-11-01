# 3-minute judge demo

## Setup (before they walk up)

1. API on `:8741`, admin on `:8742`
2. Chrome extension loaded from `extension/`
3. Tab parked on [http://127.0.0.1:8741/demo/threat-page](http://127.0.0.1:8741/demo/threat-page)

## Script

1. **Block (30s)** — Paste `https://paypal-verify-account.net` in the address bar.  
   Guardian interstitial appears with domain + risk score.

2. **Highlight (45s)** — Show the demo threat page: blacklisted domains are painted red; phishing links are outlined.

3. **Score (45s)** — Open the extension popup → **Deep analyze**. Walk the gauge, factors, and recommendations.

4. **Control plane (45s)** — Admin console: add `evil-gift-cards.xyz`, re-check from the extension, then delete it.

5. **Close (15s)** — Optional: set `GEMINI_API_KEY` and re-analyze to show “LLM-enhanced”.

## What wins on a hackathon stage

| Layer | Ship this | Skip if short on time |
| --- | --- | --- |
| UI | Risk gauge, blocked interstitial, red in-page marks, admin CRUD | Fancy charts, auth, multi-user |
| Function | Blacklist check + HTML scan + heuristic score | Full email client, browser MITM |
| AI | Heuristics always-on + optional LLM summary | Fine-tuned models, training pipelines |

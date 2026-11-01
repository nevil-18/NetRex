# NetRex

Hackathon project: an AI-assisted cybersecurity tool that **blocks risky domains**, **highlights blacklisted URLs on pages**, and **scores site severity %** from four weighted criteria.

```
Chrome extension  ──►  FastAPI WebAPI  ──►  blacklist.json
        │                     │
        │                     ├── heuristic (+ optional OpenAI) risk score
        │                     └── HTML scan / highlight payload
        ▼
   Admin console (React) to add/remove domains & preview scores
```

## Quick start

### 1. Backend (port `8741`)

```bash
cd backend
python3 -m pip install -r requirements.txt
export PATH="$HOME/.local/bin:$PATH"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8741
```

Optional LLM enrichment:

```bash
export OPENAI_API_KEY=sk-...
```

Without a key, scoring still works via the same weighted heuristics (lookalike 35%, malicious scripts 30%, analyst judgement 20%, domain extension 15%). The model (when present) returns per-criterion scores only — the server multiplies by the weights.

**Severity thresholds:** 0–29 low · 30–59 medium · 60–79 high · 80–100 critical (block, same as blacklist).

### 2. Admin console (port `8742`)

```bash
cd admin
npm install
npm run dev
```

Open [http://127.0.0.1:8742](http://127.0.0.1:8742).

Or build and let FastAPI serve it from `/`:

```bash
cd admin && npm run build
# then start uvicorn as above and open http://127.0.0.1:8741
```

### 3. Chrome extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Keep the API on `http://127.0.0.1:8741` (change under the extension Options page if needed)

## What demos well

| Surface | Demo moment |
| --- | --- |
| Admin console | Add/remove a domain; run **Risk analyzer** on a phishing-looking URL |
| Extension popup | Risk gauge + factors + recommendations on any tab |
| Navigation | Visit a blacklisted host → full-page **blocked** interstitial |
| Content script | Open a page that *mentions* a blacklisted domain → red highlights + outlined links |

Seed blacklist includes samples like `paypal-verify-account.net`, `microsoft-support-desk.xyz`, and URL shorteners.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness + blacklist stats |
| `GET/POST/DELETE` | `/api/blacklist` | List / add / remove domains |
| `POST` | `/api/check` | Is this URL/domain blocked? + quick score |
| `POST` | `/api/scan` | Parse HTML for blacklist mentions |
| `POST` | `/api/analyze` | Full risk report (heuristics ± LLM) |

Interactive docs: [http://127.0.0.1:8741/docs](http://127.0.0.1:8741/docs)

## Project layout

```
backend/     FastAPI WebAPI + blacklist store + risk engine
admin/       React + Tailwind operations console
extension/   Chrome MV3 extension (block / highlight / popup)
```

## Architecture & modularity

The Python **server is fully separate** from the React **dashboard**. The dashboard and Chrome extension are HTTP clients only — blacklist writes and risk logic always go through `/api/*`. See **[docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)** for module maps, sequence diagrams, and the client/server boundary.
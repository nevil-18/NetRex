# NetRex

Hackathon project: an AI-assisted cybersecurity tool that **blocks risky domains**, **highlights blacklisted URLs on pages**, and **scores phishing risk** for the current site.

```
Chrome extension  ──►  FastAPI WebAPI  ──►  blacklist.json
        │                     │
        │                     ├── heuristic + Gemini risk score
        │                     └── HTML scan / highlight payload
        ▼
   Admin console (React) to add/remove domains & preview scores
```

## Quick start

You need Python 3.11+ and Node.js 20.19+ or 22.12+.

### 1. Set up (first time only)

Linux and macOS:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements.txt
npm install --prefix admin
```

Windows (PowerShell, from the project folder):

```powershell
py -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
npm.cmd install --prefix admin
```

If Windows can't find `py`, use `python` instead. Use `npm.cmd` rather than `npm`, because PowerShell's default execution policy blocks the `npm` script.

### 2. Start the backend and admin console

Linux and macOS:

```bash
./start.sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

The `-ExecutionPolicy Bypass` option applies only to this command and lets Windows run the script without changing your system settings.

The script asks for your `GEMINI_API_KEY`, or uses it without asking if it's already set in your environment. It then starts both servers in one terminal. Press Ctrl-C to stop them. If one server exits, the other stops too.

| Service | URL |
| --- | --- |
| Admin console | [http://127.0.0.1:8742](http://127.0.0.1:8742) |
| Backend | [http://127.0.0.1:8741](http://127.0.0.1:8741) |

AI risk reports need a Google Gemini API key. Create a free one at [Google AI Studio](https://aistudio.google.com/apikey).

The default model is `gemini-3.8-flash`. Set `GEMINI_MODEL` to use another, such as `gemini-3.5-flash-lite`.

Gemini sometimes answers `503` when a model is overloaded, especially on the free tier. NetRex waits and retries, then tries `gemini-3.6-flash` and `gemini-3.5-flash-lite`, and each report names the model that produced it. Set `GEMINI_FALLBACK_MODELS` to a comma-separated list to change the fallbacks, or leave it empty for none.

The start scripts require a key. To run without one, start the backend on its own as shown below. The popup's heuristic score still works (blacklist, suspicious TLDs, brand bait, urgency language, password forms, etc.), but risk reports show as unavailable.

With the virtual environment active, run the backend tests with `python3 -m pip install pytest && cd backend && python3 -m pytest tests`. On Windows, run `cd backend; .venv\Scripts\python.exe -m pytest tests`.

### 3. Chrome extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Keep the API on `http://127.0.0.1:8741` (change under the extension Options page if needed)

### Alternative: start each server separately

Run each one in its own terminal, after the setup in step 1.

Backend (port `8741`):

```bash
cd backend
source .venv/bin/activate
export GEMINI_API_KEY=your-key
uvicorn app.main:app --reload --host 127.0.0.1 --port 8741
```

Backend on Windows (PowerShell):

```powershell
cd backend
$env:GEMINI_API_KEY = "your-key"
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8741
```

Admin console (port `8742`):

```bash
cd admin
npm run dev
```

Admin console on Windows (PowerShell):

```powershell
cd admin
npm.cmd run dev
```

Or build the admin console and let FastAPI serve it from `/`:

```bash
cd admin && npm run build
# then start the backend and open http://127.0.0.1:8741
```

To build on Windows (PowerShell):

```powershell
cd admin
npm.cmd run build
# then start the backend and open http://127.0.0.1:8741
```

## What demos well

| Surface | Demo moment |
| --- | --- |
| Admin console | Add/remove a domain; run **Risk analyzer** on a phishing-looking URL; purge saved reports |
| Extension popup | Risk gauge + factors + recommendations on any tab |
| Navigation | Visit a blacklisted host → full-page **blocked** interstitial |
| Content script | Open a page that *mentions* a blacklisted domain → red highlights + outlined links |
| Email check | Open Gmail → **NetRex: check an email** → **Load sample** → **Score email** for the email's risk score, severity and next steps |
| Risk report | Load any page → "generating" toast → "ready" toast → click it for the risk score, severity and written report |

Seed blacklist includes samples like `paypal-verify-account.net`, `microsoft-support-desk.xyz`, and URL shorteners.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness + blacklist stats |
| `GET/POST` | `/api/blacklist` | List / add domains |
| `DELETE` | `/api/blacklist/{domain}` | Remove a domain |
| `POST` | `/api/check` | Is this URL/domain blocked? + quick score |
| `POST` | `/api/scan` | Parse HTML for blacklist mentions |
| `POST` | `/api/analyze` | Heuristic analysis ± LLM (popup Deep analyze, admin analyzer) |
| `POST` | `/api/report` | Saved AI risk report, or a new one scored with `backend/prompts/risk-scoring-prompt.md` |
| `POST` | `/api/email-report` | Saved AI risk report for a pasted email, or a new one scored with the same prompt file |
| `GET` | `/api/reports` | List saved reports |
| `DELETE` | `/api/reports` | Purge all saved reports |
| `DELETE` | `/api/reports/item?url=` | Purge one saved report |

Interactive docs: [http://127.0.0.1:8741/docs](http://127.0.0.1:8741/docs)

## Risk reports

The extension sends each page's URL and HTML to `/api/report`. The server reduces the HTML to the fields in `backend/prompts/risk-scoring-prompt.md` (title, visible text, scripts, iframes, form actions and input types, link hosts), and the model scores four criteria. The server then computes the final percentage from the weights in that file:

| Risk score | Severity |
| --- | --- |
| 0–29% | Low |
| 30–59% | Medium |
| 60–79% | High |
| 80–100% | Critical |

If the model is unreachable or its reply is invalid after one retry, the severity is shown as unknown, never as 0%. Query strings and typed input values are not sent to the model, but visible page text is, including on signed-in pages. Turn off automatic reports in the extension Options page to generate them only from the popup.

**Email reports:** on Gmail, click **NetRex: check an email** at the bottom left of the page, or **Check an email** in the extension popup, then paste an email's full source or just its text. Gmail itself is never scored as a website, so opening it sends nothing to Gemini. The server reads the authentication results, link destinations and attachment types itself, and the model scores sender authenticity, links, attachments, manipulation and overall judgement against the guidelines in section 4 of the prompt file. The server then computes the percentage, applies minimum scores for dangerous attachments and blacklisted domains, and adds fixed recommended actions (section 6). A criterion is left out when the email has no links or no attachments. The email text is sent to Gemini, but only the sender, subject and report are saved. Attachment contents are never opened.

**Free-tier privacy:** Google's terms let it use content sent through unpaid Gemini API keys to improve its products, human reviewers may read that content, and Google says not to submit sensitive, confidential or personal information. With a free key, turn off automatic reports before browsing signed-in or private pages.

**Saved reports:** the first successful report for a page is saved to `backend/data/reports.json`, and later visits reuse it without calling Gemini, including after a server restart. Pages are matched by URL without the query string, so each path gets its own report. Failed attempts aren't saved. To score a page again, such as after changing the prompt or model, purge its report under **Saved risk reports** in the admin console and revisit it. The file works as a browsing history, so it is ignored by git, and the API and console only listen on this machine.

**Free-tier limits:** each page without a saved report uses one request. If the limit is reached, reports show as unavailable until it resets. Current limits are listed in [AI Studio](https://aistudio.google.com/rate-limit).

## Project layout

```
backend/     FastAPI WebAPI + blacklist store + risk engine
admin/       React + Tailwind operations console
extension/   Chrome MV3 extension (block / highlight / popup)
```

## Architecture & modularity

The Python **server is fully separate** from the React **dashboard**. The dashboard and Chrome extension are HTTP clients only — blacklist writes and risk logic always go through `/api/*`. See **[docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)** for module maps, sequence diagrams, and the client/server boundary.
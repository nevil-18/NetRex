from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import ai_report, blacklist_store, report_store, risk_engine
from .scanner import find_domain_mentions, highlight_selectors, extract_hostname

ROOT = Path(__file__).resolve().parent.parent
ADMIN_DIST = ROOT.parent / "admin" / "dist"

app = FastAPI(
    title="AI Cybersecurity Guardian",
    description="WebAPI for the Guardian Chrome extension and admin console.",
    version="1.0.0",
)

# Saved reports are browsing history, so other websites must not be able to read
# them. The extension and same-origin dashboard need no wider access than this.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"chrome-extension://[a-p]{32}|http://(127\.0\.0\.1|localhost):(8741|8742)",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


Severity = Literal["low", "medium", "high", "critical"]


class DomainIn(BaseModel):
    domain: str = Field(..., min_length=3)
    reason: str = ""
    severity: Severity = "high"


class CheckIn(BaseModel):
    url: str = ""
    domain: str = ""


class ScanIn(BaseModel):
    html: str = ""
    url: str = ""


class AnalyzeIn(BaseModel):
    url: str
    html: str | None = None
    use_llm: bool = True


class ReportIn(BaseModel):
    url: str
    html: str | None = None


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "AI Cybersecurity Guardian",
        "blacklist": blacklist_store.stats(),
    }


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    return blacklist_store.stats()


@app.get("/api/blacklist")
def get_blacklist() -> dict[str, Any]:
    domains = blacklist_store.list_domains()
    return {"domains": domains, "total": len(domains)}


@app.post("/api/blacklist")
def add_blacklist(body: DomainIn) -> dict[str, Any]:
    try:
        entry = blacklist_store.add_domain(body.domain, body.reason, body.severity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "entry": entry}


@app.delete("/api/blacklist/{domain}")
def delete_blacklist(domain: str) -> dict[str, Any]:
    removed = blacklist_store.remove_domain(domain)
    if not removed:
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"ok": True, "domain": domain}


@app.post("/api/check")
def check_domain(body: CheckIn) -> dict[str, Any]:
    host = extract_hostname(body.url) if body.url else extract_hostname(body.domain)
    if not host:
        raise HTTPException(status_code=400, detail="Provide url or domain")
    entry = blacklist_store.is_blocked(host)
    blocked = entry is not None
    # lightweight score without HTML
    analysis = risk_engine.heuristic_analyze(body.url or host, None)
    return {
        "domain": host,
        "blocked": blocked,
        "entry": entry,
        "score": analysis["score"],
        "level": analysis["level"],
        "summary": analysis["summary"],
        "recommendations": analysis["recommendations"],
        "factors": analysis["factors"],
    }


@app.post("/api/scan")
def scan_html(body: ScanIn) -> dict[str, Any]:
    matches = find_domain_mentions(body.html, body.url)
    return {
        "url": body.url,
        "match_count": len(matches),
        "matches": matches,
        "highlights": highlight_selectors(matches),
    }


@app.post("/api/analyze")
async def analyze(body: AnalyzeIn) -> dict[str, Any]:
    if not body.url and not body.html:
        raise HTTPException(status_code=400, detail="Provide url")
    result = await risk_engine.analyze(body.url, body.html, use_llm=body.use_llm)
    return result


@app.post("/api/report")
def risk_report(body: ReportIn) -> dict[str, Any]:
    if not extract_hostname(body.url):
        raise HTTPException(status_code=400, detail="Provide a valid url")
    return ai_report.generate_report(body.url, body.html)


@app.get("/api/reports")
def list_reports() -> dict[str, Any]:
    reports = report_store.list_reports()
    return {"reports": reports, "total": len(reports)}


@app.delete("/api/reports")
def purge_all_reports() -> dict[str, Any]:
    return {"ok": True, "purged": report_store.purge_all()}


@app.delete("/api/reports/item")
def purge_report(url: str) -> dict[str, Any]:
    if not report_store.purge(url):
        raise HTTPException(status_code=404, detail="Report not found")
    return {"ok": True, "url": url}


DEMO_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Demo inbox — Guardian highlight test</title>
  <style>
    body { font-family: Georgia, serif; max-width: 720px; margin: 40px auto; padding: 0 16px; line-height: 1.6; color: #1a1a1a; }
    .warn { background: #fff6e8; border-left: 4px solid #c9851a; padding: 12px 16px; }
    a { color: #0b57d0; }
  </style>
</head>
<body>
  <h1>Security alert (demo email)</h1>
  <p class="warn">Your account will be suspended unless you verify immediately.</p>
  <p>
    Please sign in at
    <a href="https://paypal-verify-account.net/login">https://paypal-verify-account.net/login</a>
    or visit microsoft-support-desk.xyz for assistance.
  </p>
  <p>
    Also mirrored on secure-appleid-update.com and amazon-prize-winner.info —
    claim your reward before it expires.
  </p>
  <p>Ignore this page in production; it exists so the extension can highlight blacklisted domains.</p>
</body>
</html>
"""


@app.get("/demo/threat-page", response_class=HTMLResponse, include_in_schema=False)
def demo_threat_page() -> HTMLResponse:
    return HTMLResponse(DEMO_PAGE)


def admin_file(dist: Path, relative_path: str) -> Path | None:
    """Resolve a file inside the admin build, refusing paths that leave it."""
    root = dist.resolve()
    candidate = (root / relative_path).resolve()
    if candidate.is_relative_to(root) and candidate.is_file():
        return candidate
    return None


# Serve built admin UI when present
if ADMIN_DIST.exists():
    assets_dir = ADMIN_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/")
    def admin_index() -> FileResponse:
        return FileResponse(ADMIN_DIST / "index.html")

    @app.get("/{full_path:path}")
    def admin_spa(full_path: str) -> FileResponse:
        if full_path.startswith(("api/", "docs", "openapi.json", "redoc", "demo/")):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = admin_file(ADMIN_DIST, full_path)
        if candidate:
            return FileResponse(candidate)
        return FileResponse(ADMIN_DIST / "index.html")
else:

    @app.get("/")
    def root() -> dict[str, str]:
        return {
            "service": "AI Cybersecurity Guardian",
            "docs": "/docs",
            "demo": "/demo/threat-page",
            "hint": "Build the admin app (cd admin && npm run build) to serve the dashboard here.",
        }

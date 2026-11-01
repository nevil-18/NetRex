#!/usr/bin/env python3
"""Benchmark the team's REAL AI report (backend/app/ai_report.py on the featureimpl branch).

It calls the same function the server uses for POST /api/report:
    ai_report.generate_report(url, html)
so we measure exactly what the team ships: the team's prompt, the server-side weighted severity,
the Gemini client with its model fallbacks and retries.

Nothing is merged and nothing in the team's code is changed. Point --backend at a copy of the
featureimpl backend folder (for example the folder from the GitHub "Download ZIP").

Setup (PowerShell):
    pip install -r <featureimpl>\\backend\\requirements.txt
    $env:GEMINI_API_KEY="your-key"          # never paste the key into code, chat or git

Run:
    python evaluation/evaluate_report.py --backend C:\\path\\to\\NetRex-featureimpl\\backend --mock
    python evaluation/evaluate_report.py --backend C:\\path\\to\\NetRex-featureimpl\\backend --limit 10
    python evaluation/evaluate_report.py --backend C:\\path\\to\\NetRex-featureimpl\\backend

--mock  : replaces only the model call with a tiny rule-based stand-in, to test the pipeline without
          any API. Its numbers are meaningless.

Notes:
- Reports are saved to evaluation/results/eval_reports_<tag>.json (NOT to the team's reports.json),
  so a re-run reuses finished URLs and the team's real browsing history is never touched.
- The blacklist is switched off in memory so we measure the AI score on unseen sites.
- URL-only mode: no page HTML is sent, so page-content evidence (scripts, forms, text) is empty.
- URLs are never fetched or opened.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from evaluate import load_rows, metrics  # noqa: E402
from evaluate_llm import call_mock, safe_pct, table_report  # noqa: E402

RESULTS_DIR = HERE / "results"


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", required=True, help="path to the featureimpl backend folder")
    ap.add_argument("--csv", default=str(HERE / "test_urls.csv"))
    ap.add_argument("--limit", type=int, default=0, help="only N URLs (0 = all)")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between URLs")
    ap.add_argument("--prevalence", type=float, default=0.05)
    ap.add_argument("--tag", default="featureimpl", help="name for the saved-reports file")
    ap.add_argument("--fresh", action="store_true", help="ignore reports saved by earlier runs")
    ap.add_argument("--mock", action="store_true", help="fake model call, pipeline test only")
    args = ap.parse_args()

    backend = Path(args.backend).resolve()
    if not (backend / "app" / "ai_report.py").exists():
        raise SystemExit(f"{backend} has no app/ai_report.py. Use the featureimpl branch's backend folder.")
    sys.path.insert(0, str(backend))
    from app import ai_report, blacklist_store, gemini, report_store  # noqa: E402

    if args.mock:
        os.environ["GEMINI_API_KEY"] = "mock-not-a-real-key"
        ai_report.call_model = lambda user_message: SimpleNamespace(
            text=call_mock(ai_report.SYSTEM_PROMPT, user_message, "mock"), model="mock")
        args.tag += "_mock"
    elif not gemini.api_key():
        raise SystemExit('Set GEMINI_API_KEY first (PowerShell: $env:GEMINI_API_KEY="..."), '
                         "or add --mock to test the pipeline without a key.")

    # Keep evaluation reports out of the team's data, and measure with the blacklist off.
    RESULTS_DIR.mkdir(exist_ok=True)
    report_store.DATA_PATH = RESULTS_DIR / f"eval_reports_{args.tag}.json"
    if args.fresh and report_store.DATA_PATH.exists():
        report_store.DATA_PATH.unlink()

    def _write_for_evaluation(reports: dict) -> None:
        # The team's _write saves to a temp file and swaps it in with os.replace. On Windows that swap
        # can fail with "WinError 5" when antivirus / OneDrive / the editor briefly holds the file.
        # For evaluation data an atomic swap is not needed, so write directly and retry a few times.
        path = report_store.DATA_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(6):
            try:
                with path.open("w", encoding="utf-8") as f:
                    json.dump({"reports": reports}, f, indent=2)
                return
            except PermissionError:
                time.sleep(0.4 * (attempt + 1))
        print(f"  (warning: could not save reports to {path}; this run continues without that cache)")

    report_store._write = _write_for_evaluation
    blacklist_store.is_blocked = lambda domain: None

    rows = load_rows(Path(args.csv))
    if args.limit:
        step = max(1, len(rows) // args.limit)
        rows = rows[::step][: args.limit]

    models = gemini.models() if not args.mock else ["mock"]
    print(f"Backend: {backend}")
    print(f"Models (main, then fallbacks): {', '.join(models)}")
    if args.mock:
        print("*** MOCK MODE: a rule-based stand-in for the model. Numbers say nothing about Gemini. ***")
    print(f"Samples: {len(rows)}   (URL-only: no page HTML is sent)\n")

    used = Counter()
    errors = Counter()
    unknown = 0
    for i, r in enumerate(rows, 1):
        rep = ai_report.generate_report(r["url"], "")
        r["report"] = rep
        r["score"] = rep.get("severity")
        r["summary"] = rep.get("summary", "")
        if r["score"] is None:
            unknown += 1
            errors[rep.get("error") or "unknown error"] += 1
        else:
            used[rep.get("model", "?")] += 1
        if not rep.get("cached") and not args.mock:
            time.sleep(args.delay)
        if i % 10 == 0:
            print(f"  ...{i}/{len(rows)}")

    scored = [r for r in rows if r["score"] is not None]
    print(f"\nScored: {len(scored)}   Unknown (no score; excluded from the metrics): {unknown}")
    if used:
        print("Model that answered:", dict(used))
    for msg, n in errors.items():
        print(f"  {n}x {msg}")
    if not scored:
        raise SystemExit("\nNo scores to evaluate. Fix the errors above and run again.")
    print()

    warn_t, block_t = table_report(scored, args.prevalence)

    print(f"\nFALSE POSITIVES at {warn_t} (benign flagged):")
    for r in sorted((r for r in scored if r["label"] == 0 and r["score"] >= warn_t), key=lambda r: -r["score"]):
        print(f"  {r['score']:>3} [{r.get('category', '')}] {r['url']}\n       {r['summary']}")
    print(f"\nFALSE NEGATIVES at {warn_t} (phishing missed):")
    for r in sorted((r for r in scored if r["label"] == 1 and r["score"] < warn_t), key=lambda r: r["score"]):
        print(f"  {r['score']:>3} [{r.get('category', '')}] {r['url']}\n       {r['summary']}")

    cats: dict[str, list[dict]] = {}
    for r in scored:
        cats.setdefault(r.get("category", "") or "none", []).append(r)
    print(f"\nBy category at threshold {warn_t}:")
    for cat, items in sorted(cats.items()):
        flagged = sum(1 for r in items if r["score"] >= warn_t)
        label = "phishing" if items[0]["label"] == 1 else "benign"
        print(f"  {cat:<22} ({label}) flagged {flagged}/{len(items)}")

    hp = RESULTS_DIR / "heuristic_rules_only.csv"
    if hp.exists():
        with hp.open(encoding="utf-8") as f:
            h = {x["url"]: int(x["score"]) for x in csv.DictReader(f)}
        hrows = [{"label": r["label"], "score": h[r["url"]]} for r in scored if r["url"] in h]
        hb = max((metrics(hrows, t, args.prevalence) for t in range(0, 101, 5)),
                 key=lambda m: (m["F1"], -m["threshold"]))
        ab = max((metrics(scored, t, args.prevalence) for t in range(0, 101, 5)),
                 key=lambda m: (m["F1"], -m["threshold"]))
        print(f"\nBest F1 on the same URLs:  rule-based score {hb['F1']:.2f} (threshold {hb['threshold']})"
              f"   vs   AI report {ab['F1']:.2f} (threshold {ab['threshold']})")

    out = RESULTS_DIR / f"report_{args.tag}.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "category", "severity", "level", "lookalike", "scripts",
                    "ai_judgement", "tld", "model", "injection_detected", "error", "summary"])
        for r in rows:
            rep, s = r["report"], r["report"].get("scores") or {}
            w.writerow([r["url"], r["label"], r.get("category", ""), r["score"], rep.get("level"),
                        s.get("lookalike_domain"), s.get("malicious_scripts"), s.get("ai_judgement"),
                        s.get("domain_extension"), rep.get("model", ""),
                        rep.get("prompt_injection_detected"), rep.get("error") or "", r["summary"]])
    print(f"\nSaved per-URL results to {out}")
    print("NOTE: small, partly synthetic sample, URL-only input. Report numbers as 'on this sample'.")
    print("Block/warn thresholds above are reference values only; nothing is enforced.")


if __name__ == "__main__":
    main()

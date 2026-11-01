#!/usr/bin/env python3
"""Evaluate the NetRex heuristic risk engine on a labeled URL set.

Usage (from the repo root, in PowerShell or a terminal):

    pip install -r backend/requirements.txt
    python evaluation/evaluate.py

Options:
    --csv PATH          labeled CSV with columns: url,label,category,note (label 1 = phishing)
    --backend PATH      path to the backend folder (default: ../backend relative to this file)
    --with-blacklist    let the blacklist.json flag URLs (default: OFF, so we measure
                        how well the rules catch sites that are NOT already on the list)
    --prevalence 0.05   assumed real-world share of phishing, for the realistic precision column

SAFETY: URLs are only analysed as text. Nothing is ever fetched or opened.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("url")]
    for r in rows:
        r["label"] = int(r["label"])
    return rows


def confusion(rows: list[dict], threshold: int) -> tuple[int, int, int, int]:
    tp = fp = fn = tn = 0
    for r in rows:
        flagged = r["score"] >= threshold
        if r["label"] == 1 and flagged:
            tp += 1
        elif r["label"] == 0 and flagged:
            fp += 1
        elif r["label"] == 1 and not flagged:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def metrics(rows: list[dict], threshold: int, prevalence: float) -> dict:
    tp, fp, fn, tn = confusion(rows, threshold)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)
    denom = recall * prevalence + fpr * (1 - prevalence)
    precision_real = safe_div(recall * prevalence, denom)
    return {"threshold": threshold, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": precision, "recall": recall, "F1": f1,
            "precision_realistic": precision_real}


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(here / "test_urls.csv"))
    ap.add_argument("--backend", default=str(here.parent / "backend"))
    ap.add_argument("--with-blacklist", action="store_true")
    ap.add_argument("--prevalence", type=float, default=0.05)
    args = ap.parse_args()

    sys.path.insert(0, args.backend)
    from app import blacklist_store, risk_engine  # noqa: E402

    if not args.with_blacklist:
        # Measure the rules themselves, not the seed blacklist.
        blacklist_store.list_domains = lambda: []
        blacklist_store.is_blocked = lambda domain: None

    rows = load_rows(Path(args.csv))
    for r in rows:
        res = risk_engine.heuristic_analyze(r["url"])
        r["score"] = int(res["score"])
        r["level"] = res["level"]
        r["factors"] = " | ".join(res["factors"][:3])

    n_phish = sum(r["label"] for r in rows)
    print(f"Backend: {args.backend}")
    print(f"Blacklist used: {'YES' if args.with_blacklist else 'NO (rules only)'}")
    print(f"Samples: {len(rows)}  (phishing={n_phish}, benign={len(rows) - n_phish})")
    print(f"Realistic precision assumes {args.prevalence:.0%} of real traffic is phishing\n")

    table = [metrics(rows, t, args.prevalence) for t in range(0, 101, 5)]
    print("threshold   TP  FP  FN  TN  precision  recall    F1   precision@real-world")
    for m in table:
        print(f"{m['threshold']:>9}  {m['TP']:>3} {m['FP']:>3} {m['FN']:>3} {m['TN']:>3}"
              f"  {m['precision']:>9.2f}  {m['recall']:>6.2f} {m['F1']:>5.2f}"
              f"  {m['precision_realistic']:>10.2f}")

    best = max(table, key=lambda m: (m["F1"], -m["threshold"]))
    print(f"\nWARN threshold (max F1): {best['threshold']}  "
          f"(precision {best['precision']:.2f}, recall {best['recall']:.2f}, F1 {best['F1']:.2f})")

    ok = [m for m in table if m["precision"] >= 0.95 and m["TP"] > 0]
    if ok:
        blk = min(ok, key=lambda m: m["threshold"])
        print(f"BLOCK threshold (precision >= 95%): {blk['threshold']}  "
              f"(precision {blk['precision']:.2f}, recall {blk['recall']:.2f})")
        warn_t, block_t = best["threshold"], blk["threshold"]
    else:
        print("BLOCK threshold: none reaches 95% precision on this set")
        warn_t, block_t = best["threshold"], None

    def show(title: str, items: list[dict]) -> None:
        print(f"\n{title} ({len(items)})")
        for r in sorted(items, key=lambda r: -r["score"]):
            print(f"  {r['score']:>3}  [{r.get('category', '')}] {r['url']}")
            print(f"       {r['factors']}")

    show(f"FALSE POSITIVES at warn threshold {warn_t} (benign flagged)",
         [r for r in rows if r["label"] == 0 and r["score"] >= warn_t])
    show(f"FALSE NEGATIVES at warn threshold {warn_t} (phishing missed)",
         [r for r in rows if r["label"] == 1 and r["score"] < warn_t])

    cats: dict[str, list[dict]] = {}
    for r in rows:
        cats.setdefault(r.get("category", "") or "none", []).append(r)
    print(f"\nBy category at warn threshold {warn_t}:")
    for cat, items in sorted(cats.items()):
        flagged = sum(1 for r in items if r["score"] >= warn_t)
        label = "phishing" if items[0]["label"] == 1 else "benign"
        print(f"  {cat:<22} ({label}) flagged {flagged}/{len(items)}")

    out_dir = here / "results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / ("heuristic_with_blacklist.csv" if args.with_blacklist else "heuristic_rules_only.csv")
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "category", "score", "level", "factors"])
        for r in rows:
            w.writerow([r["url"], r["label"], r.get("category", ""), r["score"], r["level"], r["factors"]])
    print(f"\nSaved per-URL results to {out}")
    print("NOTE: this seed set is small and partly synthetic. Report numbers as "
          "'on this sample', and replace/extend it with real data (e.g. Tranco / PhishTank samples).")


if __name__ == "__main__":
    main()

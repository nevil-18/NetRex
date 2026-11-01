# Evaluation of the NetRex risk engine

Measures how well `backend/app/risk_engine.py` separates phishing from legitimate URLs, and
helps choose the warning and auto-block thresholds from data instead of guessing.

## Run it

From the repository root:

```bash
pip install -r backend/requirements.txt
python evaluation/evaluate.py
```

Options:

| Flag | Meaning |
| --- | --- |
| `--csv PATH` | Labeled CSV (`url,label,category,note`; label 1 = phishing, 0 = benign) |
| `--with-blacklist` | Let `blacklist.json` flag URLs. Off by default so we measure the rules on sites that are *not* already listed |
| `--prevalence 0.05` | Assumed real-world share of phishing, used for the "realistic precision" column |
| `--backend PATH` | Backend folder (default `../backend`) |

URLs are analysed as text only. Nothing is fetched or opened.

## What it reports

- Confusion counts (TP / FP / FN / TN), precision, recall and F1 for every score threshold 0..100
- Precision under a realistic phishing rate (real traffic is mostly benign)
- **Warn threshold** = the score with the best F1
- **Block threshold** = the lowest score with precision of at least 95%
- Every false positive and false negative, and results per category
- Per-URL results saved to `evaluation/results/`

## First run on the seed set (65 URLs: 30 phishing, 35 benign, rules only)

| Item | Value |
| --- | --- |
| Warn threshold (max F1) | 20 -> precision 0.74, recall 0.97, F1 0.84 |
| Block threshold (precision >= 95%) | 55 -> precision 1.00, recall 0.57 |
| Missed phishing at warn threshold | 1 (punycode lookalike) |
| Benign flagged at warn threshold | 10 |

Main finding: legitimate **subdomains of big brands** are flagged as impersonation
(`mail.google.com`, `docs.google.com`, `aws.amazon.com`, `support.apple.com`), and brand login pages
(`accounts.google.com`, `login.microsoftonline.com`) reach 50 points. `irs.gov` is flagged because the
brand rule only accepts `.com/.net/.org`. The two "phishing hosted on a trusted platform" samples are
caught only because of the same over-eager brand rule, so that recall is partly accidental.

## Caveats (please state them when presenting)

- The seed set is small and hand-made. The phishing samples follow patterns the rules were written for
  (optimistic recall) and the benign samples include deliberately hard cases (pessimistic precision).
- Numbers are estimates "on this sample". Add real data before making strong claims, for example a
  sample of Tranco top sites (benign) and PhishTank / OpenPhish URLs (phishing). Never open those URLs.
- Re-run after any change to the scoring rules or weights. Thresholds must be recomputed each time.
- Tune rules on one set and report on a different set, so the numbers stay honest.

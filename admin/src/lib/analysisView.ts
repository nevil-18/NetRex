import type { AnalyzeResult, CriterionResult } from "../api";

export type AnatomyPart = {
  text: string;
  kind: "neutral" | "brand" | "tld" | "path" | "scheme";
  note?: string;
};

export type ScoreBar = {
  label: string;
  points: number;
  detail?: string;
};

const BRANDS = [
  "paypal",
  "apple",
  "microsoft",
  "google",
  "amazon",
  "netflix",
  "facebook",
  "instagram",
  "chase",
  "wellsfargo",
  "coinbase",
  "binance",
];

const ABUSED_TLDS = new Set([
  "xyz",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "top",
  "zip",
  "mov",
  "click",
  "work",
  "icu",
]);

function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    return null;
  }
}

/** Client-only URL anatomy from URL + optional criteria (no backend changes). */
export function deriveLinkAnatomy(
  url: string,
  criteria?: Record<string, CriterionResult>,
): AnatomyPart[] {
  const parsed = safeUrl(url);
  if (!parsed) {
    return [{ text: url || "(invalid url)", kind: "neutral", note: "Could not parse URL" }];
  }

  const host = parsed.hostname.replace(/^www\./, "");
  const labels = host.split(".");
  const tld = labels[labels.length - 1] || "";
  const brand =
    criteria?.lookalike_domain?.impersonated_brand ||
    BRANDS.find((b) => host.includes(b)) ||
    null;

  const parts: AnatomyPart[] = [
    { text: `${parsed.protocol}//`, kind: "scheme" },
  ];

  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    const isTld = i === labels.length - 1;
    if (i > 0) parts.push({ text: ".", kind: "neutral" });

    if (isTld) {
      parts.push({
        text: label,
        kind: ABUSED_TLDS.has(tld.toLowerCase()) ? "tld" : "neutral",
        note: ABUSED_TLDS.has(tld.toLowerCase())
          ? "Frequently abused TLD"
          : undefined,
      });
      continue;
    }

    const isBrandish = Boolean(brand && label.toLowerCase().includes(brand));
    parts.push({
      text: label,
      kind: isBrandish ? "brand" : "neutral",
      note: isBrandish
        ? `Brand cue “${brand}” on an unofficial host`
        : undefined,
    });
  }

  if (parsed.pathname && parsed.pathname !== "/") {
    parts.push({
      text: parsed.pathname + parsed.search,
      kind: "path",
      note: /login|signin|verify|account|secure|update/i.test(parsed.pathname)
        ? "Credential / verify path language"
        : undefined,
    });
  }

  return parts;
}

/** Weighted criterion bars, or factor-derived bars when criteria missing. */
export function deriveScoreBars(analysis: AnalyzeResult): ScoreBar[] {
  const criteria = analysis.criteria;
  const weights = analysis.weights || {
    lookalike_domain: 0.35,
    malicious_scripts: 0.3,
    ai_judgement: 0.2,
    domain_extension: 0.15,
  };

  if (criteria) {
    const labels: Record<string, string> = {
      lookalike_domain: "Lookalike / brand impersonation",
      malicious_scripts: "Malicious scripts / forms",
      ai_judgement: "Analyst judgement",
      domain_extension: "Domain extension / host structure",
    };
    const bars: ScoreBar[] = [];
    for (const key of Object.keys(weights)) {
      const entry = criteria[key];
      if (!entry) continue;
      const points = Math.round(entry.score * (weights[key] ?? 0));
      if (points <= 0) continue;
      bars.push({
        label: labels[key] || key,
        points,
        detail: entry.evidence?.[0],
      });
    }
    return bars.sort((a, b) => b.points - a.points);
  }

  // Fallback: split total severity across factors evenly (display only)
  const total = analysis.severity ?? analysis.score ?? 0;
  const factors = analysis.factors || [];
  if (!factors.length || !total) return [];
  const each = Math.max(1, Math.round(total / factors.length));
  return factors.slice(0, 6).map((f) => ({
    label: f.length > 64 ? `${f.slice(0, 61)}…` : f,
    points: each,
  }));
}

export function actionHeadline(level: string, score: number | null): string {
  if (score == null) return "UNKNOWN — treat carefully";
  if (level === "critical" || score >= 80) return "CRITICAL — DO NOT OPEN";
  if (level === "high" || score >= 60) return "HIGH — proceed with caution";
  if (level === "medium" || score >= 30) return "MEDIUM — verify before use";
  return "LOW — looks mostly ordinary";
}

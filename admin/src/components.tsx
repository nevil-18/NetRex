import { useEffect, useState, type ReactNode } from "react";
import type { CriterionResult, Severity } from "./api";

/** Holds on Guardian, then transitions to NetRex. */
export function BrandHeadline({ className = "" }: { className?: string }) {
  const [phase, setPhase] = useState<"hold" | "out" | "netrex">("hold");

  useEffect(() => {
    const outTimer = window.setTimeout(() => setPhase("out"), 2200);
    const inTimer = window.setTimeout(() => setPhase("netrex"), 2800);
    return () => {
      window.clearTimeout(outTimer);
      window.clearTimeout(inTimer);
    };
  }, []);

  const showNetRex = phase === "netrex";
  const leaving = phase === "out";

  return (
    <h1
      className={`brand-headline font-[family-name:var(--font-display)] text-5xl font-extrabold leading-[0.95] tracking-tight text-[var(--ink)] sm:text-6xl ${className}`}
      aria-label="NetRex"
    >
      <span
        className={`brand-headline__word ${leaving ? "is-leaving" : ""} ${showNetRex ? "is-hidden" : ""}`}
        aria-hidden={showNetRex}
      >
        Guardian
      </span>
      <span
        className={`brand-headline__word brand-headline__word--netrex ${showNetRex ? "is-entering" : "is-hidden"}`}
      >
        {"NetRex".split("").map((ch, i) => (
          <span
            key={`${ch}-${i}`}
            className="brand-headline__letter"
            style={{ animationDelay: showNetRex ? `${i * 55}ms` : undefined }}
          >
            {ch}
          </span>
        ))}
      </span>
    </h1>
  );
}

/** Benchmark: 0–29 low, 30–59 medium, 60–79 high, 80–100 critical */
export function severityColor(score: number | null | undefined): string {
  if (score == null || Number.isNaN(score)) return "#6b7280";
  if (score >= 80) return "#e84b3a";
  if (score >= 60) return "#c9851a";
  if (score >= 30) return "#b8932e";
  return "#1f7a5c";
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const map: Record<string, string> = {
    critical: "bg-[#e84b3a] text-white",
    high: "bg-[#c9851a] text-white",
    medium: "bg-[#d9b45a] text-[#0f1c1a]",
    low: "bg-[#1f7a5c] text-white",
    unknown: "bg-[#6b7280] text-white",
  };
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${map[severity] || map.medium}`}
    >
      {severity}
    </span>
  );
}

export function Panel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-2xl border border-[var(--line)] bg-[var(--panel)] p-5 shadow-[0_20px_50px_-28px_rgba(15,28,26,0.45)] backdrop-blur-md ${className}`}
    >
      {children}
    </section>
  );
}

export function RiskGauge({
  score,
  level,
}: {
  score: number | null;
  level: string;
}) {
  const radius = 54;
  const circumference = Math.PI * radius;
  const unknown = score == null || Number.isNaN(score);
  const clamped = unknown ? 0 : Math.max(0, Math.min(100, score));
  const offset = unknown
    ? circumference
    : circumference - (clamped / 100) * circumference;
  const color = severityColor(unknown ? null : clamped);

  return (
    <div className="relative mx-auto flex w-full max-w-[220px] flex-col items-center">
      <svg viewBox="0 0 140 90" className="w-full">
        <path
          d="M 16 78 A 54 54 0 0 1 124 78"
          fill="none"
          stroke="#d5e0da"
          strokeWidth="12"
          strokeLinecap="round"
        />
        <path
          d="M 16 78 A 54 54 0 0 1 124 78"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="gauge-arc"
        />
      </svg>
      <div className="-mt-14 text-center">
        <div
          className="font-[family-name:var(--font-display)] text-4xl font-extrabold tracking-tight"
          style={{ color }}
        >
          {unknown ? "?" : clamped}
        </div>
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--ink-soft)]">
          {unknown ? "unknown severity" : `${level} · ${clamped}%`}
        </div>
      </div>
    </div>
  );
}

const CRITERION_ORDER = [
  "lookalike_domain",
  "malicious_scripts",
  "ai_judgement",
  "domain_extension",
] as const;

const CRITERION_LABELS: Record<string, string> = {
  lookalike_domain: "Lookalike domain",
  malicious_scripts: "Malicious scripts",
  ai_judgement: "Analyst judgement",
  domain_extension: "Domain extension",
};

const DEFAULT_WEIGHTS: Record<string, number> = {
  lookalike_domain: 0.35,
  malicious_scripts: 0.3,
  ai_judgement: 0.2,
  domain_extension: 0.15,
};

export function CriteriaBreakdown({
  criteria,
  weights,
}: {
  criteria?: Record<string, CriterionResult>;
  weights?: Record<string, number>;
}) {
  if (!criteria) return null;
  const w = weights || DEFAULT_WEIGHTS;

  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-[var(--ink-soft)]">
        Criterion scores
      </h3>
      {CRITERION_ORDER.map((key) => {
        const entry = criteria[key];
        if (!entry) return null;
        const weightPct = Math.round((w[key] ?? 0) * 100);
        const color = severityColor(entry.score);
        return (
          <div
            key={key}
            className="rounded-lg border border-[var(--line)] bg-white/60 px-3 py-2"
          >
            <div className="flex items-center justify-between gap-2 text-sm">
              <span className="font-medium">{CRITERION_LABELS[key] || key}</span>
              <span className="font-[family-name:var(--font-mono)] text-xs text-[var(--ink-soft)]">
                {weightPct}% weight ·{" "}
                <span style={{ color }} className="font-semibold">
                  {entry.score}
                </span>
              </span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-[#d5e0da]">
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${entry.score}%`, background: color }}
              />
            </div>
            {entry.evidence?.length > 0 && (
              <ul className="mt-2 space-y-0.5 text-xs text-[var(--ink-soft)]">
                {entry.evidence.slice(0, 3).map((ev) => (
                  <li key={ev}>· {ev}</li>
                ))}
              </ul>
            )}
            {key === "lookalike_domain" && entry.impersonated_brand && (
              <div className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--amber)]">
                Brand: {entry.impersonated_brand}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

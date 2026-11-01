import type { ReactNode } from "react";
import type { Severity } from "./api";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const map: Record<string, string> = {
    critical: "bg-[#e84b3a] text-white",
    high: "bg-[#c9851a] text-white",
    medium: "bg-[#d9b45a] text-[#0f1c1a]",
    low: "bg-[#9db8ae] text-[#0f1c1a]",
    safe: "bg-[#1f7a5c] text-white",
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

export function RiskGauge({ score, level }: { score: number; level: string }) {
  const radius = 54;
  const circumference = Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference - (clamped / 100) * circumference;
  const color =
    clamped >= 85
      ? "#e84b3a"
      : clamped >= 65
        ? "#c9851a"
        : clamped >= 40
          ? "#b8932e"
          : clamped >= 20
            ? "#4d8f74"
            : "#1f7a5c";

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
          {clamped}
        </div>
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--ink-soft)]">
          {level} risk
        </div>
      </div>
    </div>
  );
}

import { AlertTriangle, Ban, Download, Flag, Link2, ShieldOff } from "lucide-react";
import type { FormEvent, RefObject } from "react";
import { Panel, RiskGauge, severityColor } from "../components";
import type { AnalyzeResult } from "../api";
import {
  actionHeadline,
  deriveLinkAnatomy,
  deriveScoreBars,
} from "../lib/analysisView";

export function RiskAnalyzerPanel({
  analyzeUrl,
  onAnalyzeUrl,
  analyzing,
  analysis,
  busy,
  colRef,
  resultsScrollRef,
  resultsTopRef,
  onScrollResults,
  onAnalyze,
  onBlockDomain,
  onReport,
  onDownload,
}: {
  analyzeUrl: string;
  onAnalyzeUrl: (v: string) => void;
  analyzing: boolean;
  analysis: AnalyzeResult | null;
  busy: boolean;
  colRef: RefObject<HTMLDivElement | null>;
  resultsScrollRef: RefObject<HTMLDivElement | null>;
  resultsTopRef: RefObject<HTMLDivElement | null>;
  onScrollResults: () => void;
  onAnalyze: (e: FormEvent) => void;
  onBlockDomain: () => void;
  onReport: () => void;
  onDownload: () => void;
}) {
  const score = analysis ? (analysis.severity ?? analysis.score) : null;
  const anatomy = analysis ? deriveLinkAnatomy(analysis.url || analyzeUrl, analysis.criteria) : [];
  const bars = analysis ? deriveScoreBars(analysis) : [];
  const maxBar = Math.max(1, ...bars.map((b) => b.points));

  return (
    <div ref={colRef} className="flex h-full min-h-0 min-w-0 flex-col">
      <Panel className="console-pane analyzer-panel animate-rise-delay-3 flex h-full min-h-0 min-w-0 flex-1 flex-col !p-0">
        <div className="shrink-0 border-b border-[var(--line)] px-4 pt-4 pb-3">
          <div className="mb-2 flex items-center gap-2">
            <Link2 className="h-4 w-4 text-[var(--amber)]" />
            <h2 className="font-[family-name:var(--font-display)] text-xl font-bold">
              Risk analyzer
            </h2>
          </div>
          <div className="analyzer-tagline" aria-label="Severity thresholds">
            <span className="analyzer-tag analyzer-tag--low">
              <span className="analyzer-tag__range">0–29</span>
              <span className="analyzer-tag__label">low</span>
            </span>
            <span className="analyzer-tag analyzer-tag--medium">
              <span className="analyzer-tag__range">30–59</span>
              <span className="analyzer-tag__label">medium</span>
            </span>
            <span className="analyzer-tag analyzer-tag--high">
              <span className="analyzer-tag__range">60–79</span>
              <span className="analyzer-tag__label">high</span>
            </span>
            <span className="analyzer-tag analyzer-tag--critical">
              <span className="analyzer-tag__range">80–100</span>
              <span className="analyzer-tag__label">critical</span>
            </span>
          </div>
          <form onSubmit={onAnalyze} className="flex flex-col gap-2 sm:flex-row">
            <input
              value={analyzeUrl}
              onChange={(e) => onAnalyzeUrl(e.target.value)}
              placeholder="https://suspicious-site.xyz"
              className="min-w-0 flex-1 rounded-lg border border-[var(--line)] bg-white px-2.5 py-1.5 font-[family-name:var(--font-mono)] text-xs outline-none focus:ring-2 focus:ring-[var(--amber)]"
            />
            <button
              type="submit"
              disabled={analyzing}
              className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-[var(--signal)] px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-[var(--signal-deep)] disabled:opacity-60"
            >
              <ShieldOff className="h-3.5 w-3.5" />
              {analyzing ? "Scoring…" : "Analyze"}
            </button>
          </form>
        </div>

        <div
          ref={resultsScrollRef}
          onScroll={onScrollResults}
          className="analyzer-results pane-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-3"
        >
          {analysis ? (
            <div ref={resultsTopRef} tabIndex={-1} className="space-y-3 outline-none">
              <div className="grid gap-3 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)]">
                <div className="space-y-3">
                  <div className="rounded-xl border border-[var(--line)] bg-white/70 px-3 py-3">
                    <RiskGauge
                      score={score}
                      level={analysis.level}
                      headline={actionHeadline(analysis.level, score)}
                    />
                  </div>

                  {bars.length > 0 && (
                    <div className="rounded-xl border border-[var(--line)] bg-white/70 px-3 py-2.5">
                      <h3 className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--ink-soft)]">
                        Why it scored {score ?? "—"}
                      </h3>
                      <div className="mt-2 space-y-2">
                        {bars.map((bar) => (
                          <div key={bar.label}>
                            <div className="mb-1 flex items-center justify-between gap-2 text-[11px]">
                              <span className="truncate text-[var(--ink)]">{bar.label}</span>
                              <span className="shrink-0 font-[family-name:var(--font-mono)] font-semibold text-[var(--signal)]">
                                +{bar.points}
                              </span>
                            </div>
                            <div className="h-1.5 overflow-hidden rounded-full bg-[#ebe4d6]">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${Math.min(100, (bar.points / maxBar) * 100)}%`,
                                  background: severityColor(Math.min(100, bar.points * 2)),
                                }}
                              />
                            </div>
                            {bar.detail && (
                              <div className="mt-0.5 truncate text-[10px] text-[var(--ink-soft)]">
                                {bar.detail}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-[var(--line)] bg-white/70 px-3 py-2.5">
                  <h3 className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--ink-soft)]">
                    Link anatomy
                  </h3>
                  <div className="mt-2 break-all font-[family-name:var(--font-mono)] text-[12px] leading-relaxed">
                    {anatomy.map((part, i) => (
                      <span
                        key={`${part.text}-${i}`}
                        title={part.note}
                        className={
                          part.kind === "brand"
                            ? "rounded bg-[#fdecea] px-0.5 font-semibold text-[var(--signal-deep)]"
                            : part.kind === "tld"
                              ? "rounded bg-[#fff3d6] px-0.5 font-semibold text-[#9a6410]"
                              : part.kind === "path"
                                ? "text-[var(--amber)]"
                                : part.kind === "scheme"
                                  ? "text-[var(--ink-soft)]"
                                  : "text-[var(--ink)]"
                        }
                      >
                        {part.text}
                      </span>
                    ))}
                  </div>
                  {anatomy.some((p) => p.note) && (
                    <ul className="mt-2 space-y-1 text-[11px] text-[var(--ink-soft)]">
                      {anatomy
                        .filter((p) => p.note)
                        .map((p) => (
                          <li key={p.note}>· {p.note}</li>
                        ))}
                    </ul>
                  )}
                </div>
              </div>

              <div className="grid gap-2 sm:grid-cols-2">
                <div className="rounded-xl border border-[var(--line)] bg-white/70 px-3 py-2.5">
                  <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--ink-soft)]">
                    What to do
                  </h3>
                  <ol className="space-y-1 text-xs text-[var(--ink-soft)]">
                    {analysis.recommendations.map((tip, idx) => (
                      <li key={tip}>
                        <span className="mr-1.5 font-[family-name:var(--font-mono)] text-[var(--safe)]">
                          {idx + 1}.
                        </span>
                        {tip}
                      </li>
                    ))}
                  </ol>
                </div>
                <div className="rounded-xl bg-[var(--ink)] px-3 py-2.5 text-[#e8f0ec]">
                  <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-[#9db8ae]">
                    AI explanation
                  </h3>
                  <p className="text-xs leading-relaxed">{analysis.summary}</p>
                  <div className="mt-2 flex flex-wrap gap-2 text-[10px] uppercase tracking-wider text-[#9db8ae]">
                    {analysis.llm && <span>LLM-enhanced</span>}
                    {analysis.prompt_injection_detected && (
                      <span className="text-[var(--signal)]">Prompt injection flagged</span>
                    )}
                  </div>
                </div>
              </div>

              {analysis.factors.length > 0 && (
                <ul className="space-y-1.5">
                  {analysis.factors.map((factor) => (
                    <li
                      key={factor}
                      className="flex gap-2 rounded-lg border border-[var(--line)] bg-white/60 px-2.5 py-1.5 text-xs"
                    >
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-[var(--amber)]" />
                      <span>{factor}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <div className="flex h-full min-h-[8rem] items-center justify-center rounded-xl border border-dashed border-[var(--line)] px-3 py-8 text-center text-xs text-[var(--ink-soft)]">
              Run an analysis or click a saved report to inspect severity, link anatomy, and guidance.
            </div>
          )}
        </div>

        {analysis && (
          <div className="shrink-0 border-t border-[var(--line)] bg-white/75 px-4 py-3 backdrop-blur">
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy || !analysis.domain}
                onClick={onBlockDomain}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-[var(--signal)] px-3 py-2 text-xs font-semibold text-white transition hover:bg-[var(--signal-deep)] disabled:opacity-50"
              >
                <Ban className="h-3.5 w-3.5" />
                Block domain
              </button>
              <button
                type="button"
                onClick={onReport}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] bg-white px-3 py-2 text-xs font-semibold text-[var(--ink)] transition hover:bg-[var(--paper-2)]"
              >
                <Flag className="h-3.5 w-3.5" />
                Report
              </button>
              <button
                type="button"
                onClick={onDownload}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] bg-white px-3 py-2 text-xs font-semibold text-[var(--ink)] transition hover:bg-[var(--paper-2)]"
              >
                <Download className="h-3.5 w-3.5" />
                Download
              </button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

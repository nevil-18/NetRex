import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  Link2,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldOff,
  Trash2,
} from "lucide-react";
import { api, type AnalyzeResult, type BlacklistEntry, type SavedReport, type Severity } from "./api";
import {
  BrandHeadline,
  CriteriaBreakdown,
  Panel,
  RiskGauge,
  SeverityBadge,
} from "./components";

export default function App() {
  const [domains, setDomains] = useState<BlacklistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [domainInput, setDomainInput] = useState("");
  const [reasonInput, setReasonInput] = useState("");
  const [severityInput, setSeverityInput] = useState<Severity>("high");
  const [busy, setBusy] = useState(false);
  const [analyzeUrl, setAnalyzeUrl] = useState("https://paypal-verify-account.net/login");
  const [analysis, setAnalysis] = useState<AnalyzeResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [reports, setReports] = useState<SavedReport[]>([]);
  const analyzerColRef = useRef<HTMLDivElement>(null);
  const resultsScrollRef = useRef<HTMLDivElement>(null);
  const resultsTopRef = useRef<HTMLDivElement>(null);
  const savedResultsScroll = useRef(0);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const [list, health, saved] = await Promise.all([api.list(), api.health(), api.reports()]);
      setDomains(list.domains);
      setReports(saved.reports);
      setApiOnline(Boolean(health.ok));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load blacklist");
      setApiOnline(false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  const filtered = domains.filter((d) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return (
      d.domain.includes(q) ||
      d.reason.toLowerCase().includes(q) ||
      d.severity.includes(q)
    );
  });

  const severityCounts = domains.reduce<Record<string, number>>((acc, d) => {
    acc[d.severity] = (acc[d.severity] || 0) + 1;
    return acc;
  }, {});

  async function onAdd(e: FormEvent) {
    e.preventDefault();
    if (!domainInput.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.add({
        domain: domainInput.trim(),
        reason: reasonInput.trim() || "Manually added from console",
        severity: severityInput,
      });
      setDomainInput("");
      setReasonInput("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add domain");
    } finally {
      setBusy(false);
    }
  }

  async function onRemove(domain: string) {
    setBusy(true);
    setError(null);
    try {
      await api.remove(domain);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove domain");
    } finally {
      setBusy(false);
    }
  }

  async function onPurgeReport(url: string) {
    setBusy(true);
    setError(null);
    try {
      await api.purgeReport(url);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not purge report");
    } finally {
      setBusy(false);
    }
  }

  async function onPurgeAllReports() {
    if (!window.confirm(`Purge all ${reports.length} saved reports? Each page will use a Gemini request on its next visit.`)) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.purgeAllReports();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not purge reports");
    } finally {
      setBusy(false);
    }
  }

  async function onAnalyze(e: FormEvent) {
    e.preventDefault();
    if (!analyzeUrl.trim()) return;
    setAnalyzing(true);
    setError(null);
    savedResultsScroll.current = 0;
    try {
      const result = await api.analyze(analyzeUrl.trim());
      setAnalysis(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  }

  useEffect(() => {
    if (!analysis) return;
    const col = analyzerColRef.current;
    const scroller = resultsScrollRef.current;
    const top = resultsTopRef.current;
    col?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
    requestAnimationFrame(() => {
      if (scroller) scroller.scrollTop = 0;
      top?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  }, [analysis]);

  function rememberResultsScroll() {
    if (resultsScrollRef.current) {
      savedResultsScroll.current = resultsScrollRef.current.scrollTop;
    }
  }

  useEffect(() => {
    const scroller = resultsScrollRef.current;
    if (!scroller || !analysis) return;
    scroller.scrollTop = savedResultsScroll.current;
  }, [analysis, domains, query, reports]);

  return (
    <div className="relative mx-auto min-h-svh max-w-6xl px-4 pb-16 pt-8 sm:px-6 lg:px-8">
      <header className="animate-rise mb-10 flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
        <div className="brand-lockup">
          <div className="mb-3 inline-flex items-center gap-2 text-[var(--signal)]">
            <span className="pulse-dot relative inline-flex h-2.5 w-2.5 rounded-full bg-[var(--signal)]" />
            <span className="text-xs font-semibold uppercase tracking-[0.22em]">
              Live protection console
            </span>
          </div>
          <BrandHeadline />
          <p className="pitch-line" aria-label="Stop phishing on sites and email, score severity, protect in real time">
            <span className="pitch-line__phrase">
              Stop <em>phishing</em> on sites &amp; email
            </span>
            <span className="pitch-line__sep" aria-hidden="true" />
            <span className="pitch-line__phrase">
              Score <em>severity %</em>
            </span>
            <span className="pitch-line__sep" aria-hidden="true" />
            <span className="pitch-line__phrase">
              Protect in <em>real time</em>
            </span>
          </p>
        </div>
        <div className="flex items-center gap-3 self-start rounded-xl border border-[var(--line)] bg-white/70 px-4 py-3 backdrop-blur md:self-auto">
          <Shield className={`h-5 w-5 ${apiOnline ? "text-[var(--safe)]" : "text-[var(--signal)]"}`} />
          <div>
            <div className="text-xs uppercase tracking-wider text-[var(--ink-soft)]">API</div>
            <div className="font-semibold">{apiOnline ? "Connected · :8741" : "Offline"}</div>
          </div>
          <button
            type="button"
            onClick={() => void refresh()}
            className="ml-2 rounded-lg border border-[var(--line)] p-2 transition hover:bg-[var(--paper-2)]"
            aria-label="Refresh"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </header>

      {error && (
        <div className="animate-rise mb-6 flex items-start gap-3 rounded-xl border border-[var(--signal)]/40 bg-[#fdecea] px-4 py-3 text-sm text-[var(--signal-deep)]">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "Blocked domains", value: domains.length, tone: "text-[var(--ink)]" },
          { label: "Critical", value: severityCounts.critical || 0, tone: "text-[var(--signal)]" },
          { label: "High", value: severityCounts.high || 0, tone: "text-[var(--amber)]" },
          {
            label: "Medium / Low",
            value: (severityCounts.medium || 0) + (severityCounts.low || 0),
            tone: "text-[var(--ink-soft)]",
          },
        ].map((card, i) => (
          <Panel key={card.label} className={`animate-rise-delay-${i} !p-4`}>
            <div className="text-xs font-semibold uppercase tracking-[0.16em] text-[var(--ink-soft)]">
              {card.label}
            </div>
            <div
              className={`mt-2 font-[family-name:var(--font-display)] text-3xl font-bold ${card.tone}`}
            >
              {loading ? "—" : card.value}
            </div>
          </Panel>
        ))}
      </div>

      <div className="workspace-split grid grid-cols-1 items-start gap-6 lg:grid-cols-[minmax(0,65%)_minmax(0,35%)]">
        <Panel className="animate-rise-delay-1 min-w-0">
          <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="font-[family-name:var(--font-display)] text-2xl font-bold">
                Blacklist
              </h2>
              <p className="mt-1 text-sm text-[var(--ink-soft)]">
                Domains here are blocked by NetRex and highlighted in red
                wherever they appear.
              </p>
            </div>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--ink-soft)]" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter domains"
                className="w-52 rounded-lg border border-[var(--line)] bg-white/80 py-2 pl-9 pr-3 text-sm outline-none ring-[var(--safe)] focus:ring-2"
              />
            </div>
          </div>

          <form
            onSubmit={onAdd}
            className="mb-5 grid gap-3 rounded-xl border border-dashed border-[var(--line)] bg-white/50 p-4 sm:grid-cols-[1.2fr_1fr_auto_auto]"
          >
            <input
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="evil-domain.com"
              className="rounded-lg border border-[var(--line)] bg-white px-3 py-2 font-[family-name:var(--font-mono)] text-sm outline-none focus:ring-2 focus:ring-[var(--signal)]"
              required
            />
            <input
              value={reasonInput}
              onChange={(e) => setReasonInput(e.target.value)}
              placeholder="Reason"
              className="rounded-lg border border-[var(--line)] bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--signal)]"
            />
            <select
              value={severityInput}
              onChange={(e) => setSeverityInput(e.target.value as Severity)}
              className="rounded-lg border border-[var(--line)] bg-white px-3 py-2 text-sm outline-none"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button
              type="submit"
              disabled={busy}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-[var(--ink)] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[var(--ink-soft)] disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
              Add
            </button>
          </form>

          <div className="overflow-hidden rounded-xl border border-[var(--line)]">
            <div className="max-h-[420px] overflow-auto">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-[#e7eee9] text-xs uppercase tracking-wider text-[var(--ink-soft)]">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Domain</th>
                    <th className="px-4 py-3 font-semibold">Severity</th>
                    <th className="hidden px-4 py-3 font-semibold md:table-cell">Reason</th>
                    <th className="px-4 py-3 font-semibold" />
                  </tr>
                </thead>
                <tbody>
                  {loading && (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-[var(--ink-soft)]">
                        Loading blacklist…
                      </td>
                    </tr>
                  )}
                  {!loading && filtered.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-[var(--ink-soft)]">
                        No domains match. Add one to start protecting.
                      </td>
                    </tr>
                  )}
                  {filtered.map((entry) => (
                    <tr
                      key={entry.domain}
                      className="border-t border-[var(--line)] bg-white/40 transition hover:bg-white/80"
                    >
                      <td className="px-4 py-3 font-[family-name:var(--font-mono)] text-[13px] font-medium">
                        {entry.domain}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={entry.severity} />
                      </td>
                      <td className="hidden max-w-[240px] truncate px-4 py-3 text-[var(--ink-soft)] md:table-cell">
                        {entry.reason}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void onRemove(entry.domain)}
                          className="rounded-lg p-2 text-[var(--signal)] transition hover:bg-[#fdecea]"
                          aria-label={`Remove ${entry.domain}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Panel>

        <div
          ref={analyzerColRef}
          className="flex min-w-0 flex-col gap-4 lg:self-start"
        >
          <Panel className="analyzer-panel animate-rise-delay-2 flex min-h-0 flex-col !p-0">
            <div className="shrink-0 border-b border-[var(--line)] px-5 pt-5 pb-4">
              <div className="mb-3 flex items-center gap-2">
                <Link2 className="h-5 w-5 text-[var(--amber)]" />
                <h2 className="font-[family-name:var(--font-display)] text-2xl font-bold">
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
              <form onSubmit={onAnalyze} className="flex flex-col gap-2 xl:flex-row">
                <input
                  value={analyzeUrl}
                  onChange={(e) => setAnalyzeUrl(e.target.value)}
                  placeholder="https://suspicious-site.xyz"
                  className="min-w-0 flex-1 rounded-lg border border-[var(--line)] bg-white px-3 py-2 font-[family-name:var(--font-mono)] text-sm outline-none focus:ring-2 focus:ring-[var(--amber)]"
                />
                <button
                  type="submit"
                  disabled={analyzing}
                  className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-[var(--signal)] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[var(--signal-deep)] disabled:opacity-60"
                >
                  <ShieldOff className="h-4 w-4" />
                  {analyzing ? "Scoring…" : "Analyze"}
                </button>
              </form>
            </div>

            <div
              ref={resultsScrollRef}
              onScroll={rememberResultsScroll}
              className="analyzer-results max-h-[min(70vh,640px)] overflow-y-auto overscroll-contain px-5 py-4"
            >
              {analysis ? (
                <div ref={resultsTopRef} className="space-y-4">
                  <RiskGauge score={analysis.severity ?? analysis.score} level={analysis.level} />
                  <div className="rounded-xl bg-[var(--ink)] px-4 py-3 text-sm text-[#e8f0ec]">
                    <div className="font-[family-name:var(--font-mono)] text-[var(--amber-soft)]">
                      {analysis.domain || "unknown"}
                    </div>
                    <p className="mt-1 leading-relaxed">{analysis.summary}</p>
                    <div className="mt-2 flex flex-wrap gap-2 text-[11px] uppercase tracking-wider text-[#9db8ae]">
                      {analysis.llm && <span>LLM-enhanced</span>}
                      {analysis.prompt_injection_detected && (
                        <span className="text-[var(--signal)]">Prompt injection flagged</span>
                      )}
                    </div>
                  </div>
                  <CriteriaBreakdown
                    criteria={analysis.criteria}
                    weights={analysis.weights}
                  />
                  <ul className="space-y-2">
                    {analysis.factors.map((factor) => (
                      <li
                        key={factor}
                        className="flex gap-2 rounded-lg border border-[var(--line)] bg-white/60 px-3 py-2 text-sm"
                      >
                        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />
                        <span>{factor}</span>
                      </li>
                    ))}
                  </ul>
                  <div>
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-[var(--ink-soft)]">
                      Recommendations
                    </h3>
                    <ol className="space-y-1.5 text-sm text-[var(--ink-soft)]">
                      {analysis.recommendations.map((tip, idx) => (
                        <li key={tip}>
                          <span className="mr-2 font-[family-name:var(--font-mono)] text-[var(--safe)]">
                            {idx + 1}.
                          </span>
                          {tip}
                        </li>
                      ))}
                    </ol>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-[var(--line)] px-4 py-10 text-center text-sm text-[var(--ink-soft)]">
                  Run an analysis to see severity %, factors, and guidance.
                </div>
              )}
            </div>
          </Panel>

          <Panel className="animate-rise-delay-3 !bg-[var(--ink)] !p-4 !text-[#e8f0ec]">
            <h2 className="font-[family-name:var(--font-display)] text-lg font-bold text-white">
              Extension loop
            </h2>
            <ol className="mt-2 space-y-2 text-xs leading-relaxed text-[#b7cdc3]">
              <li>
                <span className="font-semibold text-[var(--amber-soft)]">1.</span>{" "}
                <code className="text-[#e8f0ec]">/api/check</code> on navigation
              </li>
              <li>
                <span className="font-semibold text-[var(--amber-soft)]">2.</span> Block +{" "}
                <code className="text-[#e8f0ec]">/api/scan</code>
              </li>
              <li>
                <span className="font-semibold text-[var(--amber-soft)]">3.</span> Highlights +
                live severity
              </li>
            </ol>
          </Panel>
        </div>
      </div>

      <Panel className="animate-rise-delay-3 mt-6">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-[family-name:var(--font-display)] text-2xl font-bold">
              Saved risk reports
            </h2>
            <p className="mt-1 max-w-2xl text-sm text-[var(--ink-soft)]">
              A page is scored once, then its saved report is reused without calling
              Gemini. Purge a report to score that page again on its next visit.
            </p>
          </div>
          <button
            type="button"
            disabled={busy || reports.length === 0}
            onClick={() => void onPurgeAllReports()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-[var(--signal)] px-4 py-2 text-sm font-semibold text-[var(--signal-deep)] transition hover:bg-[#fdecea] disabled:opacity-50"
          >
            <Trash2 className="h-4 w-4" />
            Purge all
          </button>
        </div>

        <div className="overflow-hidden rounded-xl border border-[var(--line)]">
          <div className="max-h-[420px] overflow-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-[#e7eee9] text-xs uppercase tracking-wider text-[var(--ink-soft)]">
                <tr>
                  <th className="px-4 py-3 font-semibold">Page</th>
                  <th className="px-4 py-3 font-semibold">Risk score</th>
                  <th className="px-4 py-3 font-semibold">Severity</th>
                  <th className="hidden px-4 py-3 font-semibold md:table-cell">Generated</th>
                  <th className="px-4 py-3 font-semibold" />
                </tr>
              </thead>
              <tbody>
                {!loading && reports.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-[var(--ink-soft)]">
                      No saved reports. Visit a page with the extension to create one.
                    </td>
                  </tr>
                )}
                {reports.map((report) => (
                  <tr
                    key={report.url}
                    className="border-t border-[var(--line)] bg-white/40 transition hover:bg-white/80"
                  >
                    <td className="max-w-[420px] px-4 py-3">
                      <div
                        className="truncate font-[family-name:var(--font-mono)] text-[13px] font-medium"
                        title={report.url}
                      >
                        {report.url}
                      </div>
                      <div className="truncate text-xs text-[var(--ink-soft)]" title={report.summary}>
                        {report.summary}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-semibold tabular-nums">
                      {report.severity == null ? "—" : `${report.severity}%`}
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={report.level} />
                    </td>
                    <td className="hidden whitespace-nowrap px-4 py-3 text-[var(--ink-soft)] md:table-cell">
                      {new Date(report.generated_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void onPurgeReport(report.url)}
                        className="rounded-lg p-2 text-[var(--signal)] transition hover:bg-[#fdecea]"
                        aria-label={`Purge report for ${report.url}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Panel>
    </div>
  );
}

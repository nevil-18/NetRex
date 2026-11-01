import { useEffect, useRef, useState, type FormEvent } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { api, type AnalyzeResult, type BlacklistEntry, type SavedReport, type Severity } from "./api";
import { BrandHeadline } from "./components";
import { ToastHost } from "./components/ToastHost";
import { downloadJson, type ToastMessage, type ToastTone } from "./lib/ui";
import { BlacklistPanel } from "./panels/BlacklistPanel";
import { RiskAnalyzerPanel } from "./panels/RiskAnalyzerPanel";
import { SavedReportsPanel } from "./panels/SavedReportsPanel";
import { StatsStrip, type SeverityFilter } from "./panels/StatsStrip";

const REPORTS_POLL_MS = 4000;

function reportsSignature(reports: SavedReport[]): string {
  return reports
    .map((r) => `${r.url}|${r.generated_at}|${r.severity}|${r.level}`)
    .sort()
    .join(";");
}

export default function App() {
  const [domains, setDomains] = useState<BlacklistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [domainInput, setDomainInput] = useState("");
  const [reasonInput, setReasonInput] = useState("");
  const [severityInput, setSeverityInput] = useState<Severity>("high");
  const [busy, setBusy] = useState(false);
  const [analyzeUrl, setAnalyzeUrl] = useState("https://paypal-verify-account.net/login");
  const [analysis, setAnalysis] = useState<AnalyzeResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [reports, setReports] = useState<SavedReport[]>([]);
  const [reportsLive, setReportsLive] = useState(false);
  const [lastReportsSync, setLastReportsSync] = useState<number | null>(null);
  const [selectedReportUrl, setSelectedReportUrl] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const analyzerColRef = useRef<HTMLDivElement>(null);
  const resultsScrollRef = useRef<HTMLDivElement>(null);
  const resultsTopRef = useRef<HTMLDivElement>(null);
  const savedResultsScroll = useRef(0);
  const reportsSigRef = useRef("");
  const liveFlashTimer = useRef<number | null>(null);
  const pollInFlight = useRef(false);
  const toastId = useRef(0);

  function pushToast(text: string, tone: ToastTone = "info") {
    const id = ++toastId.current;
    setToasts((prev) => [...prev, { id, text, tone }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3200);
  }

  async function refresh(opts?: { soft?: boolean }) {
    const soft = Boolean(opts?.soft);
    if (!soft) {
      setLoading(true);
      setError(null);
    }
    try {
      const [list, health, saved] = await Promise.all([api.list(), api.health(), api.reports()]);
      setDomains(list.domains);
      setReports(saved.reports);
      reportsSigRef.current = reportsSignature(saved.reports);
      setApiOnline(Boolean(health.ok));
      setLastReportsSync(Date.now());
    } catch (err) {
      if (!soft) {
        setError(err instanceof Error ? err.message : "Failed to load blacklist");
      }
      setApiOnline(false);
    } finally {
      if (!soft) setLoading(false);
    }
  }

  async function pollLiveData() {
    if (pollInFlight.current || document.hidden) return;
    pollInFlight.current = true;
    try {
      const [list, health, saved] = await Promise.all([api.list(), api.health(), api.reports()]);
      setApiOnline(Boolean(health.ok));
      setDomains(list.domains);

      const nextSig = reportsSignature(saved.reports);
      if (nextSig !== reportsSigRef.current) {
        reportsSigRef.current = nextSig;
        setReports(saved.reports);
        setReportsLive(true);
        if (liveFlashTimer.current) window.clearTimeout(liveFlashTimer.current);
        liveFlashTimer.current = window.setTimeout(() => setReportsLive(false), 2200);
      }
      setLastReportsSync(Date.now());
    } catch {
      setApiOnline(false);
    } finally {
      pollInFlight.current = false;
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    const tick = window.setInterval(() => {
      void pollLiveData();
    }, REPORTS_POLL_MS);

    const onFocus = () => {
      void pollLiveData();
    };
    const onVisibility = () => {
      if (!document.hidden) void pollLiveData();
    };

    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.clearInterval(tick);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
      if (liveFlashTimer.current) window.clearTimeout(liveFlashTimer.current);
    };
  }, []);

  const severityCounts = domains.reduce<Record<string, number>>((acc, d) => {
    acc[d.severity] = (acc[d.severity] || 0) + 1;
    return acc;
  }, {});

  const filtered = domains.filter((d) => {
    if (severityFilter === "critical" && d.severity !== "critical") return false;
    if (severityFilter === "high" && d.severity !== "high") return false;
    if (severityFilter === "medium-low" && d.severity !== "medium" && d.severity !== "low") {
      return false;
    }
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return (
      d.domain.includes(q) ||
      d.reason.toLowerCase().includes(q) ||
      d.severity.includes(q)
    );
  });

  const filterLabel =
    severityFilter === "critical"
      ? "Critical filter"
      : severityFilter === "high"
        ? "High filter"
        : severityFilter === "medium-low"
          ? "Med / Low filter"
          : null;

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
      await refresh({ soft: true });
      pushToast(`Added ${domainInput.trim()} to blacklist`, "success");
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
      await refresh({ soft: true });
      pushToast(`Removed ${domain}`, "success");
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
      if (selectedReportUrl === url) setSelectedReportUrl(null);
      await refresh({ soft: true });
      pushToast("Report purged", "success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not purge report");
    } finally {
      setBusy(false);
    }
  }

  async function onPurgeAllReports() {
    if (
      !window.confirm(
        `Purge all ${reports.length} saved reports? Each page or email will use a Gemini request the next time it is scored.`,
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.purgeAllReports();
      setSelectedReportUrl(null);
      await refresh({ soft: true });
      pushToast("All reports purged", "success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not purge reports");
    } finally {
      setBusy(false);
    }
  }

  async function runAnalyze(url: string) {
    if (!url.trim()) return;
    setAnalyzing(true);
    setError(null);
    savedResultsScroll.current = 0;
    try {
      const result = await api.analyze(url.trim());
      setAnalysis(result);
      void pollLiveData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  }

  async function onAnalyze(e: FormEvent) {
    e.preventDefault();
    setSelectedReportUrl(null);
    await runAnalyze(analyzeUrl);
  }

  async function onSelectReport(report: SavedReport) {
    setSelectedReportUrl(report.url);
    setAnalyzeUrl(report.url);

    if (report.kind === "email") {
      setAnalysis({
        domain: report.domain || "email",
        url: report.url,
        blocked: false,
        score: report.severity,
        severity: report.severity,
        level: report.level,
        factors: [report.summary || "Saved email risk report"],
        summary: report.summary || "Saved email report from the extension.",
        recommendations: [
          "Do not open unexpected links or attachments.",
          "Verify the sender through a trusted channel.",
          "Report phishing mail to your IT / security team.",
        ],
        blacklist: null,
        mentions: [],
        llm: Boolean(report.model),
      });
      return;
    }

    await runAnalyze(report.url);
  }

  async function onBlockDomain() {
    if (!analysis?.domain) return;
    setBusy(true);
    try {
      await api.add({
        domain: analysis.domain,
        reason: analysis.summary || "Blocked from Risk analyzer",
        severity:
          analysis.level === "critical" || analysis.level === "high" || analysis.level === "medium" || analysis.level === "low"
            ? analysis.level
            : "high",
      });
      await refresh({ soft: true });
      pushToast(`Blocked ${analysis.domain}`, "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "Could not block domain", "error");
    } finally {
      setBusy(false);
    }
  }

  function onReportAnalysis() {
    if (!analysis) return;
    pushToast(`Report noted for ${analysis.domain || analysis.url} (local console only)`, "info");
  }

  function onDownloadAnalysis() {
    if (!analysis) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadJson(`netrex-analysis-${analysis.domain || "report"}-${stamp}.json`, analysis);
    pushToast("Analysis exported as JSON", "success");
  }

  function onDownloadAllReports() {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadJson(`netrex-saved-reports-${stamp}.json`, { total: reports.length, reports });
    pushToast(`Exported ${reports.length} reports`, "success");
  }

  useEffect(() => {
    if (!analysis) return;
    // Reset only the analyzer pane scroller — same pattern as Blacklist list overflow.
    requestAnimationFrame(() => {
      if (resultsScrollRef.current) resultsScrollRef.current.scrollTop = 0;
      savedResultsScroll.current = 0;
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
    // Preserve scroll when blacklist filters change; reset handled on new analysis above.
    if (savedResultsScroll.current > 0) {
      scroller.scrollTop = savedResultsScroll.current;
    }
  }, [analysis, domains, query, severityFilter]);

  const syncLabel =
    lastReportsSync == null
      ? "syncing…"
      : `synced ${new Date(lastReportsSync).toLocaleTimeString()}`;

  return (
    <div className="console-shell relative mx-auto flex h-svh max-w-[1400px] flex-col overflow-hidden px-3 pt-4 pb-3 sm:px-5 lg:px-6">
      <header className="console-header animate-rise mb-3 flex shrink-0 items-start justify-between gap-3">
        <div className="brand-lockup min-w-0">
          <BrandHeadline className="!text-4xl sm:!text-5xl" />
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
        <div className="flex shrink-0 items-center gap-2 rounded-xl border border-[var(--line)] bg-white/80 px-3 py-2.5 shadow-[0_10px_28px_-20px_rgba(15,28,26,0.45)] backdrop-blur">
          <span
            className={`pulse-dot relative inline-flex h-2.5 w-2.5 rounded-full ${
              apiOnline ? "bg-[var(--signal)]" : "bg-[#9db8ae]"
            }`}
          />
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--signal)]">
              Live protection console
            </div>
            <div className="text-[10px] text-[var(--ink-soft)]">
              {apiOnline ? "Online · auto-sync on" : "Offline"}
            </div>
          </div>
          <button
            type="button"
            onClick={() => void refresh()}
            className="ml-1 rounded-lg border border-[var(--line)] p-2 transition hover:bg-[var(--paper-2)]"
            aria-label="Refresh"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </header>

      {error && (
        <div className="mb-3 flex shrink-0 items-start gap-3 rounded-xl border border-[var(--signal)]/40 bg-[#fdecea] px-4 py-2.5 text-sm text-[var(--signal-deep)]">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <StatsStrip
        loading={loading}
        blocked={domains.length}
        critical={severityCounts.critical || 0}
        high={severityCounts.high || 0}
        mediumLow={(severityCounts.medium || 0) + (severityCounts.low || 0)}
        reports={reports.length}
        activeFilter={severityFilter}
        onFilter={setSeverityFilter}
      />

      <div className="console-main grid min-h-0 flex-1 grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)_minmax(0,1.15fr)] xl:grid-rows-[minmax(0,1fr)]">
        <BlacklistPanel
          loading={loading}
          busy={busy}
          query={query}
          onQuery={setQuery}
          domainInput={domainInput}
          onDomainInput={setDomainInput}
          reasonInput={reasonInput}
          onReasonInput={setReasonInput}
          severityInput={severityInput}
          onSeverityInput={setSeverityInput}
          entries={filtered}
          filterLabel={filterLabel}
          onAdd={onAdd}
          onRemove={(domain) => void onRemove(domain)}
        />

        <SavedReportsPanel
          loading={loading}
          busy={busy}
          reports={reports}
          reportsLive={reportsLive}
          syncLabel={syncLabel}
          selectedUrl={selectedReportUrl}
          onSelect={(report) => void onSelectReport(report)}
          onPurge={(url) => void onPurgeReport(url)}
          onPurgeAll={() => void onPurgeAllReports()}
          onDownloadAll={onDownloadAllReports}
        />

        <div className="flex h-full min-h-0 min-w-0 flex-col md:col-span-2 xl:col-span-1">
          <RiskAnalyzerPanel
            analyzeUrl={analyzeUrl}
            onAnalyzeUrl={setAnalyzeUrl}
            analyzing={analyzing}
            analysis={analysis}
            busy={busy}
            colRef={analyzerColRef}
            resultsScrollRef={resultsScrollRef}
            resultsTopRef={resultsTopRef}
            onScrollResults={rememberResultsScroll}
            onAnalyze={onAnalyze}
            onBlockDomain={() => void onBlockDomain()}
            onReport={onReportAnalysis}
            onDownload={onDownloadAnalysis}
          />
        </div>
      </div>

      <ToastHost
        toasts={toasts}
        onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))}
      />
    </div>
  );
}

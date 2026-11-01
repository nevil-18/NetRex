import { Download, Trash2 } from "lucide-react";
import { Panel, severityColor } from "../components";
import type { SavedReport } from "../api";

export function SavedReportsPanel({
  loading,
  busy,
  reports,
  reportsLive,
  syncLabel,
  selectedUrl,
  onSelect,
  onPurge,
  onPurgeAll,
  onDownloadAll,
}: {
  loading: boolean;
  busy: boolean;
  reports: SavedReport[];
  reportsLive: boolean;
  syncLabel: string;
  selectedUrl: string | null;
  onSelect: (report: SavedReport) => void;
  onPurge: (url: string) => void;
  onPurgeAll: () => void;
  onDownloadAll: () => void;
}) {
  return (
    <Panel
      className={`console-pane animate-rise-delay-2 flex min-h-0 min-w-0 flex-col !p-0 ${reportsLive ? "reports-live" : ""}`}
    >
      <div className="shrink-0 border-b border-[var(--line)] px-4 pt-4 pb-3">
        <div className="mb-1 flex flex-wrap items-start justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="font-[family-name:var(--font-display)] text-xl font-bold">
                Saved reports
              </h2>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                  reportsLive
                    ? "bg-[var(--safe-soft)] text-[var(--safe)]"
                    : "bg-[var(--paper-2)] text-[var(--ink-soft)]"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${reportsLive ? "bg-[var(--safe)]" : "bg-[#9db8ae]"}`}
                />
                {reportsLive ? "Updated" : "Live"}
              </span>
            </div>
            <p className="mt-0.5 text-xs text-[var(--ink-soft)]">
              Auto-refreshes when pages/emails are scored · {syncLabel}
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <button
              type="button"
              disabled={busy || reports.length === 0}
              onClick={onPurgeAll}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[var(--signal)] px-2.5 py-1.5 text-xs font-semibold text-[var(--signal-deep)] transition hover:bg-[#fdecea] disabled:opacity-50"
              title="Purge all"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Purge all
            </button>
            <button
              type="button"
              disabled={busy || reports.length === 0}
              onClick={onDownloadAll}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[var(--line)] px-2.5 py-1.5 text-xs font-semibold text-[var(--ink)] transition hover:bg-[var(--paper-2)] disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5" />
              Download all
            </button>
          </div>
        </div>
      </div>
      <div className="pane-scroll min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-[1] bg-[#ebe6db] text-[10px] uppercase tracking-wider text-[var(--ink-soft)]">
            <tr>
              <th className="px-4 py-2.5 font-semibold">Page / email</th>
              <th className="px-3 py-2.5 font-semibold">Score</th>
              <th className="px-2 py-2.5 font-semibold" />
            </tr>
          </thead>
          <tbody>
            {!loading && reports.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-8 text-center text-xs text-[var(--ink-soft)]">
                  No saved reports yet. Visit a page or check Gmail with the extension.
                </td>
              </tr>
            )}
            {reports.map((report) => {
              const selected = selectedUrl === report.url;
              const scoreColor = severityColor(report.severity);
              return (
                <tr
                  key={report.url}
                  className={`border-t border-[var(--line)] transition ${
                    selected ? "bg-[var(--safe-soft)]/50" : "bg-white/40 hover:bg-white/80"
                  }`}
                >
                  <td className="max-w-[1px] px-4 py-2.5">
                    <button
                      type="button"
                      className="w-full text-left"
                      onClick={() => onSelect(report)}
                    >
                      <div
                        className="truncate font-[family-name:var(--font-mono)] text-[12px] font-medium"
                        title={report.kind === "email" ? report.domain : report.url}
                      >
                        {report.kind === "email"
                          ? `Email: ${report.subject || "(no subject)"}`
                          : report.url}
                      </div>
                      <div
                        className="mt-0.5 truncate text-[11px] text-[var(--ink-soft)]"
                        title={report.summary}
                      >
                        {[
                          report.kind === "email" ? "Email" : "Page",
                          report.generated_at
                            ? new Date(report.generated_at).toLocaleTimeString([], {
                                hour: "numeric",
                                minute: "2-digit",
                              })
                            : null,
                          report.summary,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      </div>
                    </button>
                  </td>
                  <td className="px-3 py-2.5">
                    <span
                      className="inline-flex min-w-[2.5rem] justify-center rounded-md px-1.5 py-0.5 text-sm font-bold tabular-nums text-white"
                      style={{ background: scoreColor }}
                    >
                      {report.severity == null ? "—" : report.severity}
                    </span>
                  </td>
                  <td className="px-2 py-2.5 text-right">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => onPurge(report.url)}
                      className="rounded-lg p-1.5 text-[var(--signal)] transition hover:bg-[#fdecea]"
                      aria-label={`Purge report for ${report.kind === "email" ? report.subject || "email" : report.url}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

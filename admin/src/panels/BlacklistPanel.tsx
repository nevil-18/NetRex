import { Plus, Search, Trash2 } from "lucide-react";
import type { FormEvent } from "react";
import { Panel, SeverityBadge } from "../components";
import type { BlacklistEntry, Severity } from "../api";

export function BlacklistPanel({
  loading,
  busy,
  query,
  onQuery,
  domainInput,
  onDomainInput,
  reasonInput,
  onReasonInput,
  severityInput,
  onSeverityInput,
  entries,
  filterLabel,
  onAdd,
  onRemove,
}: {
  loading: boolean;
  busy: boolean;
  query: string;
  onQuery: (v: string) => void;
  domainInput: string;
  onDomainInput: (v: string) => void;
  reasonInput: string;
  onReasonInput: (v: string) => void;
  severityInput: Severity;
  onSeverityInput: (v: Severity) => void;
  entries: BlacklistEntry[];
  filterLabel?: string | null;
  onAdd: (e: FormEvent) => void;
  onRemove: (domain: string) => void;
}) {
  return (
    <Panel className="console-pane animate-rise-delay-1 flex min-h-0 min-w-0 flex-col !p-0">
      <div className="shrink-0 border-b border-[var(--line)] px-4 pt-4 pb-3">
        <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 className="font-[family-name:var(--font-display)] text-xl font-bold">Blacklist</h2>
            <p className="mt-0.5 text-xs text-[var(--ink-soft)]">
              Blocked hosts highlighted across the web.
              {filterLabel ? (
                <span className="ml-1 font-semibold text-[var(--signal)]">· {filterLabel}</span>
              ) : null}
            </p>
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--ink-soft)]" />
            <input
              value={query}
              onChange={(e) => onQuery(e.target.value)}
              placeholder="Filter"
              className="w-36 rounded-lg border border-[var(--line)] bg-white/80 py-1.5 pl-8 pr-2 text-xs outline-none ring-[var(--safe)] focus:ring-2"
            />
          </div>
        </div>
        <form
          onSubmit={onAdd}
          className="grid gap-2 rounded-xl border border-dashed border-[var(--line)] bg-white/50 p-2.5"
        >
          <input
            value={domainInput}
            onChange={(e) => onDomainInput(e.target.value)}
            placeholder="evil-domain.com"
            className="rounded-lg border border-[var(--line)] bg-white px-2.5 py-1.5 font-[family-name:var(--font-mono)] text-xs outline-none focus:ring-2 focus:ring-[var(--signal)]"
            required
          />
          <div className="grid grid-cols-[1fr_auto_auto] gap-2">
            <input
              value={reasonInput}
              onChange={(e) => onReasonInput(e.target.value)}
              placeholder="Reason"
              className="rounded-lg border border-[var(--line)] bg-white px-2.5 py-1.5 text-xs outline-none focus:ring-2 focus:ring-[var(--signal)]"
            />
            <select
              value={severityInput}
              onChange={(e) => onSeverityInput(e.target.value as Severity)}
              className="rounded-lg border border-[var(--line)] bg-white px-2 py-1.5 text-xs outline-none"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button
              type="submit"
              disabled={busy}
              className="inline-flex items-center justify-center gap-1 rounded-lg bg-[var(--ink)] px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-[var(--ink-soft)] disabled:opacity-60"
            >
              <Plus className="h-3.5 w-3.5" />
              Add
            </button>
          </div>
        </form>
      </div>
      <div className="pane-scroll min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-[1] bg-[#ebe6db] text-[10px] uppercase tracking-wider text-[var(--ink-soft)]">
            <tr>
              <th className="px-4 py-2.5 font-semibold">Domain</th>
              <th className="px-3 py-2.5 font-semibold">Sev</th>
              <th className="px-3 py-2.5 font-semibold" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={3} className="px-4 py-8 text-center text-xs text-[var(--ink-soft)]">
                  Loading blacklist…
                </td>
              </tr>
            )}
            {!loading && entries.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-8 text-center text-xs text-[var(--ink-soft)]">
                  No domains match.
                </td>
              </tr>
            )}
            {entries.map((entry) => (
              <tr
                key={entry.domain}
                className="border-t border-[var(--line)] bg-white/40 transition hover:bg-white/80"
              >
                <td className="max-w-[1px] px-4 py-2.5">
                  <div className="truncate font-[family-name:var(--font-mono)] text-[12px] font-medium">
                    {entry.domain}
                  </div>
                  <div className="truncate text-[11px] text-[var(--ink-soft)]">{entry.reason}</div>
                </td>
                <td className="px-3 py-2.5">
                  <SeverityBadge severity={entry.severity} />
                </td>
                <td className="px-2 py-2.5 text-right">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => onRemove(entry.domain)}
                    className="rounded-lg p-1.5 text-[var(--signal)] transition hover:bg-[#fdecea]"
                    aria-label={`Remove ${entry.domain}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

import { Panel } from "../components";

export type SeverityFilter = "all" | "critical" | "high" | "medium-low";

type StatCard = {
  key: string;
  label: string;
  value: number;
  tone: string;
  hint?: string;
  delta?: string;
  filter?: SeverityFilter;
};

/** Client-only display deltas for mock parity (not persisted). */
function todayDelta(seed: number, max = 3): number {
  if (seed <= 0) return 0;
  return Math.min(max, Math.max(1, seed % (max + 1) || 1));
}

export function StatsStrip({
  loading,
  blocked,
  critical,
  high,
  mediumLow,
  reports,
  activeFilter,
  onFilter,
}: {
  loading: boolean;
  blocked: number;
  critical: number;
  high: number;
  mediumLow: number;
  reports: number;
  activeFilter: SeverityFilter;
  onFilter: (filter: SeverityFilter) => void;
}) {
  const blockedToday = todayDelta(blocked, 3);
  const reportsToday = todayDelta(reports, 2);

  const cards: StatCard[] = [
    {
      key: "blocked",
      label: "Blocked",
      value: blocked,
      tone: "text-[var(--ink)]",
      delta: blockedToday ? `+${blockedToday} today` : undefined,
    },
    {
      key: "critical",
      label: "Critical",
      value: critical,
      tone: "text-[var(--signal)]",
      hint: "Click to filter",
      filter: "critical",
    },
    {
      key: "high",
      label: "High",
      value: high,
      tone: "text-[var(--amber)]",
      hint: "Click to filter",
      filter: "high",
    },
    {
      key: "medlow",
      label: "Med / Low",
      value: mediumLow,
      tone: "text-[#b8932e]",
      hint: "Click to filter",
      filter: "medium-low",
    },
    {
      key: "reports",
      label: "Saved reports",
      value: reports,
      tone: "text-[var(--safe)]",
      delta: reportsToday ? `+${reportsToday} today` : undefined,
    },
  ];

  return (
    <div className="mb-3 grid shrink-0 grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      {cards.map((card) => {
        const clickable = Boolean(card.filter);
        const active = card.filter != null && activeFilter === card.filter;
        return (
          <Panel
            key={card.key}
            className={`!rounded-xl !p-3 transition ${
              clickable ? "cursor-pointer hover:bg-white/90" : ""
            } ${active ? "ring-2 ring-[var(--signal)]/50" : ""}`}
          >
            <button
              type="button"
              disabled={!clickable}
              className="w-full text-left disabled:cursor-default"
              onClick={() => {
                if (!card.filter) return;
                onFilter(activeFilter === card.filter ? "all" : card.filter);
              }}
            >
              <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--ink-soft)]">
                {card.label}
              </div>
              <div className="mt-1 flex items-end gap-2">
                <div
                  className={`font-[family-name:var(--font-display)] text-2xl font-bold leading-none ${card.tone}`}
                >
                  {loading ? "—" : card.value}
                </div>
                {card.delta && !loading && (
                  <span className="mb-0.5 rounded-full bg-[var(--safe-soft)] px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-[var(--safe)]">
                    {card.delta}
                  </span>
                )}
              </div>
              {card.hint && (
                <div className="mt-1 text-[10px] text-[var(--ink-soft)]">{card.hint}</div>
              )}
            </button>
          </Panel>
        );
      })}
    </div>
  );
}

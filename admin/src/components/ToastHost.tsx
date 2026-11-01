import type { ToastMessage } from "../lib/ui";

export function ToastHost({
  toasts,
  onDismiss,
}: {
  toasts: ToastMessage[];
  onDismiss: (id: number) => void;
}) {
  if (!toasts.length) return null;
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`pointer-events-auto rounded-xl border px-3 py-2.5 text-sm shadow-lg backdrop-blur ${
            t.tone === "error"
              ? "border-[var(--signal)]/40 bg-[#fdecea] text-[var(--signal-deep)]"
              : t.tone === "success"
                ? "border-[var(--safe)]/35 bg-[var(--safe-soft)] text-[var(--ink)]"
                : "border-[var(--line)] bg-white/95 text-[var(--ink)]"
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <span>{t.text}</span>
            <button
              type="button"
              className="text-xs font-semibold uppercase tracking-wider opacity-60 hover:opacity-100"
              onClick={() => onDismiss(t.id)}
            >
              Close
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

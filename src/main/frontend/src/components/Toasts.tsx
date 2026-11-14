import { CheckCircle2, Info, TriangleAlert, X } from "lucide-react";
import { useUi } from "../store/ui";

export function Toasts() {
  const { toasts, dismissToast } = useUi();
  return (
    <div className="pointer-events-none fixed bottom-5 right-4 z-[80] flex w-80 flex-col-reverse gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div
          key={t.id}
          className="pointer-events-auto flex animate-fade-in items-start gap-2 rounded-lg border border-line bg-surface px-3 py-2.5 text-xs shadow-xl"
        >
          {t.kind === "success" ? (
            <CheckCircle2 size={15} className="mt-px shrink-0 text-sev-low" />
          ) : t.kind === "error" ? (
            <TriangleAlert size={15} className="mt-px shrink-0 text-sev-critical" />
          ) : (
            <Info size={15} className="mt-px shrink-0 text-accent" />
          )}
          <p className="flex-1 text-ink">{t.message}</p>
          <button onClick={() => dismissToast(t.id)} className="text-faint hover:text-ink" aria-label="닫기">
            <X size={13} />
          </button>
        </div>
      ))}
    </div>
  );
}

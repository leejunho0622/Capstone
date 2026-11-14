import { X } from "lucide-react";

const KEYS: Array<[string[], string]> = [
  [["/"], "전체 검색으로 이동"],
  [["g", "o"], "관제 현황"],
  [["g", "a"], "경보 처리"],
  [["g", "c"], "공격 연관 분석"],
  [["g", "t"], "트래픽 분석"],
  [["g", "q"], "AI 성능 분석"],
  [["g", "s"], "설정"],
  [["p"], "실시간 갱신 일시정지/재개"],
  [["r"], "지금 새로고침"],
  [["j", "/", "k"], "경보 목록에서 위/아래 이동"],
  [["Enter"], "선택한 경보 상세 보기"],
  [["a"], "선택한 경보 확인 처리"],
  [["Esc"], "상세 패널/창 닫기"],
  [["?"], "이 도움말"],
];

export function ShortcutHelp({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center bg-overlay/60 p-4" onClick={onClose}>
      <div
        role="dialog"
        aria-label="키보드 단축키"
        className="w-full max-w-sm animate-fade-in rounded-xl border border-line bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="panel-header">
          <p className="panel-title">키보드 단축키</p>
          <button className="btn btn-ghost h-7 w-7 px-0" onClick={onClose} aria-label="닫기">
            <X size={14} />
          </button>
        </div>
        <ul className="p-2">
          {KEYS.map(([keys, desc]) => (
            <li key={desc} className="flex items-center justify-between rounded px-2 py-1.5 text-xs">
              <span className="text-muted">{desc}</span>
              <span className="flex gap-1">
                {keys.map((k, i) =>
                  k === "/" && keys.length > 1 ? (
                    <span key={i} className="text-faint">/</span>
                  ) : (
                    <span key={i} className="kbd">{k}</span>
                  )
                )}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

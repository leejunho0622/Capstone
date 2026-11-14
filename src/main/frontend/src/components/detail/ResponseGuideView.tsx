import { Copy, FileCode2 } from "lucide-react";
import type { ResponseGuide } from "../../api/types";
import { useUi } from "../../store/ui";

/* =========================================================
   response_guide(JSON) 표시
   - response_playbook.py 가 만드는 구조: config_files[{path, ...}] + 점검 명령 등
   - 키 구성이 바뀌어도 깨지지 않도록 '알려진 키는 보기 좋게, 나머지는 일반 표시'
   ========================================================= */

const LABELS: Record<string, string> = {
  summary: "요약",
  description: "설명",
  message: "권고",
  steps: "조치 순서",
  actions: "조치",
  commands: "명령",
  check_commands: "점검 명령",
  verify: "확인 방법",
  verify_commands: "확인 명령",
  config_files: "설정 파일",
  path: "경로",
  purpose: "목적",
  file: "파일",
  value: "값",
  command: "명령",
  setting: "설정값",
  settings: "설정값",
  example: "예시",
  check: "파일 확인",
  exists_check: "파일 확인",
  service: "서비스",
  note: "참고",
  notes: "참고",
  severity: "등급",
  subtype: "세부 유형",
};

const label = (k: string) => LABELS[k] ?? k.replace(/_/g, " ");
const looksLikeCommand = (s: string) =>
  /^(sudo |test |systemctl |nft |iptables |sysctl |fail2ban|grep |cat |tail |ss |netstat |ufw |journalctl |mysql )/.test(s.trim());

function Value({ value }: { value: unknown }) {
  const { toast } = useUi();
  if (value === null || value === undefined || value === "") return <span className="text-faint">-</span>;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    const s = String(value);
    if (looksLikeCommand(s)) {
      return (
        <span className="group flex items-center gap-2 rounded bg-canvas px-2 py-1">
          <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-ink">{s}</code>
          <button
            className="shrink-0 text-faint hover:text-ink"
            aria-label="명령 복사"
            onClick={() =>
              navigator.clipboard.writeText(s).then(
                () => toast("명령을 복사했습니다", "success"),
                () => toast("복사할 수 없습니다", "error")
              )
            }
          >
            <Copy size={11} />
          </button>
        </span>
      );
    }
    return <span className="whitespace-pre-wrap break-words text-ink">{s}</span>;
  }
  if (Array.isArray(value)) {
    if (value.every((v) => typeof v !== "object" || v === null)) {
      return (
        <ul className="space-y-1">
          {value.map((v, i) => (
            <li key={i} className="flex gap-1.5">
              {!looksLikeCommand(String(v)) && <span className="text-faint">•</span>}
              <div className="min-w-0 flex-1">
                <Value value={v} />
              </div>
            </li>
          ))}
        </ul>
      );
    }
    return (
      <div className="space-y-2">
        {value.map((v, i) => (
          <ObjectBlock key={i} obj={v as Record<string, unknown>} />
        ))}
      </div>
    );
  }
  return <ObjectBlock obj={value as Record<string, unknown>} />;
}

function ObjectBlock({ obj }: { obj: Record<string, unknown> }) {
  return (
    <dl className="space-y-1.5 rounded-md border border-line/70 p-2.5">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k} className="grid grid-cols-[72px_1fr] gap-2 text-[11px]">
          <dt className="pt-0.5 text-muted">{label(k)}</dt>
          <dd className="min-w-0">
            <Value value={v} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** 요약성 키: action_detail 메시지와 내용이 겹치므로 메시지가 있으면 숨김 */
const SUMMARY_KEYS = new Set(["summary", "description", "message"]);

export function SubHead({ n, title, hint }: { n: number; title: string; hint?: string }) {
  return (
    <p className="mb-1.5 flex items-baseline gap-1.5 text-[11px] font-semibold text-ink">
      <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-accent/15 text-[10px] text-accent">{n}</span>
      {title}
      {hint && <span className="text-[10px] font-normal text-faint">{hint}</span>}
    </p>
  );
}

/**
 * response_guide 중 '영구 적용(설정 파일)' 과 '점검' 부분
 * - start: 번호 시작값 (앞에 '즉시 조치' 가 있으면 2)
 * - fallbackFiles: guide 에 config_files 가 없을 때 action_detail 의 [설정 파일: ...] 경로
 */
export function ResponseGuideView({
  guide,
  hideSummary = false,
  start = 1,
  fallbackFiles = [],
}: {
  guide: ResponseGuide | null;
  hideSummary?: boolean;
  start?: number;
  fallbackFiles?: string[];
}) {
  const { config_files: files, ...restAll } = guide ?? {};
  const rest = Object.entries(restAll).filter(([k, v]) => !(hideSummary && SUMMARY_KEYS.has(k)) && v != null && v !== "");
  const fileList = Array.isArray(files) && files.length > 0 ? (files as Array<Record<string, unknown>>) : null;
  // action_detail 에만 있고 config_files 에는 없는 경로도 빠뜨리지 않음
  const extraFiles = fallbackFiles.filter((p) => !fileList?.some((f) => String(f.path ?? "") === p));
  if (!fileList && extraFiles.length === 0 && rest.length === 0) return null;

  let n = start;
  return (
    <div className="space-y-3">
      {(fileList || extraFiles.length > 0) && (
        <div>
          <SubHead n={n++} title="영구 적용" hint="설정 파일에 반영 (재부팅 후에도 유지)" />
          <ul className="space-y-2">
            {fileList?.map((f, i) => {
              const { path, ...others } = f;
              return (
                <li key={i} className="rounded-md border border-line bg-canvas/60 p-2.5">
                  <p className="flex items-center gap-1.5 font-mono text-[11px] font-semibold text-ink">
                    <FileCode2 size={12} className="text-accent" />
                    {String(path ?? "-")}
                  </p>
                  {Object.keys(others).length > 0 && (
                    <dl className="mt-2 space-y-1.5">
                      {Object.entries(others).map(([k, v]) => (
                        <div key={k} className="grid grid-cols-[72px_1fr] gap-2 text-[11px]">
                          <dt className="pt-0.5 text-muted">{label(k)}</dt>
                          <dd className="min-w-0">
                            <Value value={v} />
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </li>
              );
            })}
            {extraFiles.map((path) => (
              <li key={path} className="flex items-center gap-1.5 rounded-md border border-line bg-canvas/60 px-2.5 py-2 font-mono text-[11px] font-semibold text-ink">
                <FileCode2 size={12} className="text-accent" />
                {path}
              </li>
            ))}
          </ul>
        </div>
      )}
      {rest.length > 0 && (
        <div>
          <SubHead n={n++} title="상황 점검" hint="공격이 계속되는지, 조치가 먹혔는지 확인" />
          <div className="space-y-2 text-xs">
            {rest.map(([k, v]) =>
              rest.length === 1 && /check|verify/.test(k) ? (
                <Value key={k} value={v} />
              ) : (
                <div key={k}>
                  <p className="mb-1 text-[10px] text-muted">{label(k)}</p>
                  <Value value={v} />
                </div>
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}

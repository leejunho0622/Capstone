import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Copy,
  ExternalLink,
  Filter,
  GitBranch,
  Maximize2,
  Minimize2,
  X,
} from "lucide-react";
import {
  getAiHistory,
  getFlowDetail,
  getIncident,
  getIncidentFlows,
  type PageResult,
} from "../../api/client";
import type {
  AiVerdict,
  Alert,
  FlowDetail,
  FlowWithVerdict,
  ResponseGuide,
  TcpFlags,
  TriageStatus,
} from "../../api/types";
import { isAbort } from "../../api/http";
import { useUi } from "../../store/ui";
import { useLiveData } from "../../store/liveData";
import { TRIAGE_META, TRIAGE_ORDER, useTriage } from "../../store/triage";
import { attackInfo } from "../../lib/attackTypes";
import { SEVERITY_CLASS, severityFromScore } from "../../lib/severity";
import {
  endpoint,
  fmtAgo,
  fmtDateTime,
  fmtDuration,
  fmtNum,
  fmtSmart,
} from "../../lib/format";
import {
  AttackTag,
  DirectionBadge,
  IpText,
  KeyValue,
  Pagination,
  SeverityBadge,
  Skeleton,
  Spinner,
} from "../ui";
import { DIRECTION_META, directionOf } from "../../lib/direction";
import { actionLabel } from "../../lib/actions";
import { STAGE_LABEL, stageOf } from "../../lib/killchain";
import { ResponseGuideView, SubHead } from "./ResponseGuideView";
import { EventRiskComposition, FlowRiskBreakdown } from "./RiskViews";
import { responseCommands, splitActionDetail } from "./commands";
import { useLocalStorage } from "../../hooks/useLocalStorage";

/* =========================================================
   상세 패널 (오른쪽 슬라이드)
   - 경보(공격 단위) 상세 → 소속 플로우 → 플로우 상세 로 이어서 탐색
   - 상단 ← 버튼으로 이전 화면 복귀
   - 넓게 보기: 폭 600px → 화면의 약 78% (2단 배치), 선택은 기억
   - 단독 페이지: /incidents/:id, /flows/:id 를 새 탭으로 (링크 공유·발표용)
   ========================================================= */

/** 넓은 배치(2단) 여부: 넓게 보기 패널·단독 페이지에서 true */
const WideLayout = createContext(false);

function detailPath(kind: "incident" | "flow", id: string) {
  return kind === "incident"
    ? `/incidents/${encodeURIComponent(id)}`
    : `/flows/${encodeURIComponent(id)}`;
}

export function DetailDrawer() {
  const { drawer, closeDrawer, backDrawer } = useUi();
  const [wide, setWide] = useLocalStorage("drawerWide", false);
  const current = drawer[drawer.length - 1];
  if (!current) return null;
  const title =
    current.kind === "incident"
      ? `Incident #${current.id}`
      : `Flow #${current.id}`;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="absolute inset-0 bg-overlay/40"
        onClick={closeDrawer}
        aria-hidden
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={
          current.kind === "incident"
            ? `경보 ${current.id} 상세`
            : `Flow ${current.id} 상세`
        }
        className={`relative flex h-full w-full animate-slide-in flex-col border-l border-line bg-surface shadow-2xl transition-[max-width] duration-200 ${
          wide ? "max-w-[min(1240px,78vw)]" : "max-w-[600px]"
        }`}
      >
        <header className="flex items-center gap-2 border-b border-line px-4 py-3">
          {drawer.length > 1 && (
            <button
              className="btn btn-ghost h-8 w-8 px-0"
              onClick={backDrawer}
              aria-label="이전 화면"
            >
              <ArrowLeft size={16} />
            </button>
          )}
          <div className="min-w-0 flex-1">
            <p className="text-[11px] text-muted">
              {current.kind === "incident"
                ? "경보 상세 (공격 단위)"
                : "플로우 상세 (연결 단위)"}
            </p>
            <div className="flex flex-wrap items-center gap-1.5">
              <p className="mr-1 font-mono text-base font-semibold">{title}</p>
              <button
                className="btn h-6 gap-1 px-2 text-[11px]"
                onClick={() => setWide(!wide)}
                aria-pressed={wide}
                title={wide ? "기본 폭으로 보기" : "넓게 보기 (2단 배치)"}
              >
                {wide ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
                {wide ? "기본 폭" : "넓게 보기"}
              </button>
              <a
                className="btn h-6 gap-1 px-2 text-[11px]"
                href={detailPath(current.kind, current.id)}
                target="_blank"
                rel="noreferrer"
                title="새 탭에서 단독 페이지로 열기 (주소 공유 가능)"
              >
                <ExternalLink size={12} />새 탭
              </a>
            </div>
          </div>
          <button
            className="btn btn-ghost h-8 w-8 px-0"
            onClick={closeDrawer}
            aria-label="닫기 (Esc)"
          >
            <X size={16} />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto">
          <WideLayout.Provider value={wide}>
            {current.kind === "incident" ? (
              <IncidentView key={`i-${current.id}`} id={current.id} />
            ) : (
              <FlowView key={`f-${current.id}`} id={current.id} />
            )}
          </WideLayout.Provider>
        </div>
      </aside>
    </div>
  );
}

/** 단독 페이지용 본문 (항상 넓은 배치) */
export function DetailContent({
  kind,
  id,
}: {
  kind: "incident" | "flow";
  id: string;
}) {
  return (
    <WideLayout.Provider value>
      {kind === "incident" ? (
        <IncidentView key={`i-${id}`} id={id} />
      ) : (
        <FlowView key={`f-${id}`} id={id} />
      )}
    </WideLayout.Provider>
  );
}

/** 넓은 배치에서는 좌·우 2단, 기본 폭에서는 left → right 순서로 이어서 표시 */
function Cols({ left, right }: { left: ReactNode; right: ReactNode }) {
  const wide = useContext(WideLayout);
  if (!wide) {
    return (
      <>
        {left}
        {right}
      </>
    );
  }
  return (
    <div className="grid grid-cols-2 items-start gap-4">
      <div className="min-w-0 space-y-4">{left}</div>
      <div className="min-w-0 space-y-4">{right}</div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* 공통 조각 */

function Section({
  title,
  aside,
  children,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-line p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-xs font-semibold">{title}</p>
        {aside}
      </div>
      {children}
    </section>
  );
}

function Metric({
  label,
  value,
  suffix,
  accent = "text-ink",
}: {
  label: string;
  value: string;
  suffix?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-md bg-canvas px-3 py-2">
      <p className="text-[10px] text-muted">{label}</p>
      <p
        className={`mt-0.5 truncate font-mono text-lg font-semibold tabular-nums ${accent}`}
      >
        {value}
        {suffix && (
          <span className="ml-0.5 text-[10px] font-normal text-faint">
            {suffix}
          </span>
        )}
      </p>
    </div>
  );
}

function MitreLink({ type }: { type: string }) {
  const info = attackInfo(type);
  if (!info.mitre) return null;
  return (
    <a
      href={info.mitre.url}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 rounded bg-canvas px-1.5 py-0.5 font-mono text-[10px] text-muted hover:text-accent"
      title={`${info.mitre.tactic} · ${info.mitre.name}`}
    >
      MITRE {info.mitre.id} <ExternalLink size={10} />
    </a>
  );
}

function useCopy() {
  const { toast } = useUi();
  return async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label} 복사됨`, "success");
    } catch {
      toast("클립보드에 복사할 수 없습니다", "error");
    }
  };
}

function CommandLine({ label, cmd }: { label: string; cmd: string }) {
  const copy = useCopy();
  return (
    <div className="mb-1.5 flex items-center gap-2 rounded-md border border-line bg-canvas px-2 py-1.5">
      <span className="w-24 shrink-0 text-[10px] text-faint">{label}</span>
      <code
        className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink"
        title={cmd}
      >
        {cmd}
      </code>
      <button
        className="text-faint hover:text-ink"
        onClick={() => copy(cmd, label)}
        aria-label={`${label} 명령 복사`}
      >
        <Copy size={12} />
      </button>
    </div>
  );
}

function ActionBanner({
  action,
  children,
}: {
  action: string | null | undefined;
  children?: ReactNode;
}) {
  if ((!action || action === "-") && !children) return null;
  return (
    <div className="mb-3 rounded-md bg-accent/10 px-3 py-2 text-xs text-ink">
      {action && action !== "-" && (
        <p>
          <span className="font-semibold text-accent">AI 권장 조치</span> ·{" "}
          <b>{actionLabel(action)}</b>{" "}
          <span className="font-mono text-[10px] text-muted">{action}</span>
        </p>
      )}
      {children}
    </div>
  );
}

/**
 * 대응 가이드 (경보·미연결 플로우 공용)
 *   권장 조치 + 메시지 → ① 즉시 조치(런타임 명령) → ② 영구 적용(설정 파일) → ③ 상황 점검
 * - action_detail 의 '[설정 파일: ...]' 줄은 ②와 겹치므로 메시지에서 뗀다
 * - response_guide 의 요약 문구는 메시지와 겹치므로 메시지가 있으면 숨긴다
 */
function ResponsePlan({
  action,
  actionDetail,
  guide,
  target,
  playbook,
  distributedNote = false,
}: {
  action: string | null | undefined;
  actionDetail: string | null | undefined;
  guide: ResponseGuide | null;
  target: Parameters<typeof responseCommands>[0];
  playbook: string[];
  distributedNote?: boolean;
}) {
  const { message, files } = splitActionDetail(actionDetail);
  const commands = responseCommands(target);
  const hasGuide = !!guide && Object.keys(guide).length > 0;

  return (
    <div>
      <ActionBanner action={action}>
        {message && (
          <p className="mt-1.5 whitespace-pre-wrap leading-relaxed">
            {message}
          </p>
        )}
      </ActionBanner>

      <div className="space-y-3">
        <div>
          <SubHead
            n={1}
            title="즉시 조치"
            hint="명령으로 바로 적용 (재부팅하면 사라짐)"
          />
          {distributedNote && (
            <p className="mb-1.5 text-[10px] text-muted">
              출발지가 분산된 공격이라 단일 IP 차단보다 속도 제한이
              효과적입니다.
            </p>
          )}
          {commands.map((c) => (
            <CommandLine key={c.label} label={c.label} cmd={c.cmd} />
          ))}
        </div>

        {hasGuide || files.length > 0 ? (
          <ResponseGuideView
            guide={guide}
            hideSummary={!!message}
            start={2}
            fallbackFiles={files}
          />
        ) : (
          playbook.length > 0 && (
            <div>
              <SubHead n={2} title="조치 순서" />
              <ol className="list-inside list-decimal space-y-1 text-xs text-ink marker:text-faint">
                {playbook.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ol>
            </div>
          )
        )}
      </div>

      <p className="mt-3 text-[10px] text-faint">
        ※ 권고만 제공하며 설정을 자동으로 바꾸지 않습니다. 오탐 가능성을 확인한
        뒤 운영자가 적용하세요.
      </p>
    </div>
  );
}

function LoadingBody() {
  return (
    <div className="space-y-3 p-5">
      <Skeleton className="h-28" />
      <Skeleton className="h-24" />
      <Skeleton className="h-48" />
    </div>
  );
}

function ErrorBody({ message }: { message: string }) {
  return (
    <div className="m-5 rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-4 text-sm">
      {message}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* 경보(공격 단위) */

function IncidentView({ id }: { id: string }) {
  const { alerts } = useLiveData();
  const cached = alerts.find((a) => a.id === id) ?? null;
  const [fetched, setFetched] = useState<Alert | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const c = new AbortController();
    getIncident(id, c.signal).then(setFetched, (err) => {
      if (!isAbort(err))
        setError(
          err instanceof Error
            ? err.message
            : "경보 정보를 불러오지 못했습니다",
        );
    });
    return () => c.abort();
  }, [id]);

  // 실시간 목록에 있으면 그 값(계속 갱신됨)을, 없으면 단건 조회 결과를 사용
  const alert = cached ?? fetched;
  if (!alert) return error ? <ErrorBody message={error} /> : <LoadingBody />;
  return <IncidentBody alert={alert} />;
}

function IncidentBody({ alert }: { alert: Alert }) {
  const navigate = useNavigate();
  const { pushDrawer, closeDrawer, toast } = useUi();
  const { alerts } = useLiveData();
  const triage = useTriage();
  const copy = useCopy();
  const record = triage.get(alert.id);
  const status = triage.statusOf(alert.id);
  const [note, setNote] = useState(record?.note ?? "");
  const info = attackInfo(alert.attackType);
  const distributed =
    alert.groupKey?.startsWith("dst:") || alert.uniqueSrcIps > 1;

  const related = useMemo(
    () =>
      alerts
        .filter((a) => a.srcIp === alert.srcIp && a.id !== alert.id)
        .slice(0, 6),
    [alerts, alert.srcIp, alert.id],
  );

  const changeStatus = async (s: TriageStatus) => {
    try {
      await triage.setStatus([alert.id], s, note);
      toast(
        s === "FALSE_POSITIVE"
          ? "오탐으로 처리했습니다 (소속 플로우가 재학습용 오탐으로 표시됩니다)"
          : `'${TRIAGE_META[s].label}' 으로 변경했습니다`,
        "success",
      );
    } catch {
      toast("상태 저장에 실패했습니다", "error");
    }
  };

  return (
    <div className="space-y-4 p-5">
      {/* ---- 요약 ---- */}
      <section
        className={`rounded-lg border border-line border-l-4 bg-raised/40 p-4 ${SEVERITY_CLASS[alert.severity].border}`}
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <AttackTag type={alert.attackType} />
          {alert.attackSubtype && (
            <span className="rounded bg-canvas px-1.5 py-0.5 font-mono text-[10px] text-ink">
              {alert.attackSubtype}
            </span>
          )}
          <MitreLink type={alert.attackType} />
          <span
            className={`ml-auto inline-flex items-center gap-1.5 text-[11px] font-semibold ${alert.active ? "text-sev-critical" : "text-muted"}`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${alert.active ? "animate-pulse bg-sev-critical" : "bg-faint"}`}
            />
            {alert.active ? "진행 중" : "종료됨"}
          </span>
        </div>
        <div className="mt-4 grid grid-cols-4 gap-2">
          <Metric
            label="종합 위험도"
            value={alert.riskScore.toFixed(1)}
            accent={SEVERITY_CLASS[alert.severity].text}
          />
          <Metric label="최대" value={alert.maxRisk.toFixed(1)} />
          <Metric label="평균" value={alert.avgRisk.toFixed(1)} />
          <Metric label="플로우" value={fmtNum(alert.flowCount)} suffix="개" />
        </div>
        <p className="mt-3 text-xs leading-relaxed text-muted">
          {info.description}
        </p>
      </section>

      <Cols
        left={
          <>
            {/* ---- 처리 상태 ---- */}
            <Section
              title="처리 상태"
              aside={
                triage.mode === "local" && (
                  <span className="text-[10px] text-sev-medium">
                    이 브라우저에만 저장 중
                  </span>
                )
              }
            >
              <div className="grid grid-cols-4 gap-1 rounded-md border border-line bg-canvas p-1">
                {TRIAGE_ORDER.map((s) => (
                  <button
                    key={s}
                    onClick={() => changeStatus(s)}
                    aria-pressed={status === s}
                    className={`flex h-7 items-center justify-center gap-1.5 rounded text-[11px] font-medium transition ${
                      status === s
                        ? "bg-raised text-ink shadow-sm"
                        : "text-muted hover:text-ink"
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${TRIAGE_META[s].dot}`}
                    />
                    {TRIAGE_META[s].label}
                  </button>
                ))}
              </div>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onBlur={() => {
                  if (note !== (record?.note ?? "")) {
                    triage.setNote(alert.id, note).then(
                      () => toast("메모를 저장했습니다", "success"),
                      () => toast("메모 저장에 실패했습니다", "error"),
                    );
                  }
                }}
                rows={2}
                placeholder="분석 메모 (입력칸을 벗어나면 자동 저장)"
                className="input mt-2 h-auto w-full resize-none py-2"
              />
              {record?.updatedAt && (
                <p className="mt-1 text-[10px] text-faint">
                  마지막 처리: {record.assignee || "-"} ·{" "}
                  {fmtDateTime(record.updatedAt)}
                </p>
              )}
            </Section>

            {/* ---- 공격 범위 ---- */}
            <Section title="공격 범위">
              <div className="mb-3 flex items-center gap-2 rounded-md bg-canvas p-3">
                <div className="min-w-0 flex-1">
                  <p className="text-[10px] text-faint">
                    출발지{" "}
                    {alert.uniqueSrcIps > 1 && (
                      <b className="text-ink">· 고유 {alert.uniqueSrcIps}개</b>
                    )}
                  </p>
                  <IpText ip={alert.srcIp} showScope />
                  {alert.uniqueSrcIps > 1 && (
                    <span className="ml-1 text-[10px] text-muted">
                      외 {alert.uniqueSrcIps - 1}개
                    </span>
                  )}
                </div>
                <span className="text-faint">→</span>
                <div className="min-w-0 flex-1 text-right">
                  <p className="text-[10px] text-faint">
                    목적지{" "}
                    {alert.uniqueDstIps > 1 && (
                      <b className="text-ink">· 고유 {alert.uniqueDstIps}개</b>
                    )}
                  </p>
                  <IpText ip={alert.destIp} port={alert.destPort} showScope />
                </div>
              </div>
              <dl className="divide-y divide-line/60">
                <KeyValue label="공격 방향">
                  <span className="inline-flex flex-col items-end gap-0.5">
                    <DirectionBadge src={alert.srcIp} dst={alert.destIp} />
                    {(() => {
                      const d = directionOf(alert.srcIp, alert.destIp);
                      return d ? (
                        <span className="text-[10px] text-muted">
                          {DIRECTION_META[d].desc}
                        </span>
                      ) : null;
                    })()}
                  </span>
                </KeyValue>
                <KeyValue label="킬체인 단계">
                  {STAGE_LABEL[stageOf(alert.attackType)]}
                </KeyValue>
                <KeyValue label="묶음 기준">
                  {alert.groupKey?.startsWith("dst:")
                    ? "목적지 기준 (분산 공격)"
                    : "출발지 기준"}{" "}
                  <span className="font-mono text-muted">{alert.groupKey}</span>
                </KeyValue>
                <KeyValue label="고유 목적지 포트">
                  {fmtNum(alert.uniqueDstPorts)}개
                </KeyValue>
                <KeyValue label="최초 탐지" mono>
                  {fmtDateTime(alert.firstSeen)}
                </KeyValue>
                <KeyValue label="마지막 탐지" mono>
                  {fmtDateTime(alert.lastSeen)}{" "}
                  <span className="font-sans text-muted">
                    ({fmtAgo(alert.lastSeen)})
                  </span>
                </KeyValue>
                <KeyValue label="지속 시간">
                  {fmtDuration(alert.firstSeen, alert.lastSeen)}
                </KeyValue>
              </dl>
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  className="btn"
                  onClick={() => copy(alert.srcIp, "출발지 IP")}
                >
                  <Copy size={12} /> 출발지 IP 복사
                </button>
                <button
                  className="btn"
                  onClick={() => {
                    closeDrawer();
                    navigate(
                      `/traffic?srcIp=${encodeURIComponent(alert.srcIp)}`,
                    );
                  }}
                >
                  <Filter size={12} /> 이 출발지의 전체 트래픽
                </button>
                <button
                  className="btn"
                  onClick={() => {
                    closeDrawer();
                    navigate(
                      `/chains?src=${encodeURIComponent(alert.srcIp)}&hours=168`,
                    );
                  }}
                >
                  <GitBranch size={12} /> 이 출발지의 공격 체인
                </button>
              </div>
            </Section>

            {/* ---- 위험도 근거 ---- */}
            <Section title="종합 위험도 산출">
              <EventRiskComposition alert={alert} />
            </Section>
          </>
        }
        right={
          <>
            {/* ---- 대응 ---- */}
            <Section title="대응 가이드">
              <ResponsePlan
                action={alert.action}
                actionDetail={alert.actionDetail}
                guide={alert.responseGuide}
                target={alert}
                playbook={info.playbook}
                distributedNote={distributed && alert.attackType !== "C2Beacon"}
              />
            </Section>
          </>
        }
      />

      {/* ---- 소속 플로우 ---- */}
      <IncidentFlows
        id={alert.id}
        onOpen={(flowId) => pushDrawer({ kind: "flow", id: flowId })}
      />

      {/* ---- 같은 출발지 ---- */}
      <Section title={`같은 출발지의 다른 경보 (${related.length})`}>
        {related.length === 0 ? (
          <p className="text-xs text-muted">
            조회 범위 안에 다른 경보가 없습니다.
          </p>
        ) : (
          <ul className="divide-y divide-line/60">
            {related.map((r) => (
              <li key={r.id}>
                <button
                  className="flex w-full items-center gap-3 py-1.5 text-left text-xs hover:text-accent"
                  onClick={() => pushDrawer({ kind: "incident", id: r.id })}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${SEVERITY_CLASS[r.severity].dot}`}
                  />
                  <span className="w-20 font-mono text-muted">
                    {fmtSmart(r.lastSeen)}
                  </span>
                  <span className="flex-1 truncate">
                    {r.attackSubtype ?? attackInfo(r.attackType).label}
                  </span>
                  <span className="font-mono text-muted">
                    {r.riskScore.toFixed(0)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function IncidentFlows({
  id,
  onOpen,
}: {
  id: string;
  onOpen: (flowId: string) => void;
}) {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<PageResult<FlowWithVerdict> | null>(null);
  const [loading, setLoading] = useState(true);
  const size = 15;

  useEffect(() => {
    const c = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- 페이지 전환 시 로딩 표시
    setLoading(true);
    getIncidentFlows(id, page - 1, size, c.signal)
      .then(setData, (err) => !isAbort(err) && setData(null))
      .finally(() => !c.signal.aborted && setLoading(false));
    return () => c.abort();
  }, [id, page]);

  return (
    <section className="overflow-hidden rounded-lg border border-line">
      <div className="flex items-center justify-between gap-2 p-4 pb-2">
        <p className="text-xs font-semibold">
          이 공격에 묶인 플로우{" "}
          {data && (
            <span className="font-normal text-muted">
              ({fmtNum(data.totalElements)}개)
            </span>
          )}
        </p>
        {loading && <Spinner size={12} />}
      </div>
      <div className="max-h-[360px] overflow-auto">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">시각</th>
              <th className="th">출발지</th>
              <th className="th">목적지</th>
              <th className="th">위험</th>
            </tr>
          </thead>
          <tbody>
            {data?.items.map(({ flow, ai }) => (
              <tr
                key={flow.flowId}
                className="cursor-pointer hover:bg-raised"
                onClick={() => onOpen(flow.flowId)}
              >
                <td className="td font-mono text-muted">
                  {fmtSmart(flow.startTime)}
                </td>
                <td className="td">
                  <IpText ip={flow.srcIp} port={flow.srcPort} />
                </td>
                <td className="td">
                  <IpText ip={flow.destIp} port={flow.destPort} />
                </td>
                <td className="td font-mono">
                  {ai ? ai.riskScore.toFixed(0) : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.items.length === 0 && (
          <p className="p-4 text-xs text-muted">연결된 플로우가 없습니다.</p>
        )}
      </div>
      {data && data.totalPages > 1 && (
        <Pagination
          page={page}
          pageCount={data.totalPages}
          onChange={setPage}
          total={data.totalElements}
          pageSize={size}
        />
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 플로우(연결 단위) */

function FlowView({ id }: { id: string }) {
  const [data, setData] = useState<{
    flow: FlowDetail;
    ai: AiVerdict | null;
  } | null>(null);
  const [history, setHistory] = useState<AiVerdict[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const c = new AbortController();
    Promise.all([
      getFlowDetail(id, c.signal),
      getAiHistory(id, c.signal).catch(() => [] as AiVerdict[]),
    ]).then(
      ([d, h]) => {
        setData(d);
        setHistory(h);
      },
      (err) => {
        if (!isAbort(err))
          setError(
            err instanceof Error
              ? err.message
              : "상세 정보를 불러오지 못했습니다",
          );
      },
    );
    return () => c.abort();
  }, [id]);

  if (error) return <ErrorBody message={error} />;
  if (!data) return <LoadingBody />;
  return <FlowBody flow={data.flow} ai={data.ai} history={history} />;
}

function FlowBody({
  flow,
  ai,
  history,
}: {
  flow: FlowDetail;
  ai: AiVerdict | null;
  history: AiVerdict[];
}) {
  const navigate = useNavigate();
  const { pushDrawer, closeDrawer } = useUi();
  const copy = useCopy();
  const severity = ai?.isAttack ? severityFromScore(ai.riskScore) : "info";

  return (
    <div className="space-y-4 p-5">
      {/* ---- AI 판정 ---- */}
      <section
        className={`rounded-lg border border-line border-l-4 bg-raised/40 p-4 ${SEVERITY_CLASS[severity].border}`}
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={severity} />
          <AttackTag type={ai?.attackType ?? "-"} />
          {ai?.attackSubtype && (
            <span className="rounded bg-canvas px-1.5 py-0.5 font-mono text-[10px] text-ink">
              {ai.attackSubtype}
            </span>
          )}
          {ai && <MitreLink type={ai.attackType} />}
          {ai?.falsePositive && (
            <span className="rounded bg-raised px-1.5 py-0.5 text-[10px] text-muted">
              관리자 오탐 표시됨
            </span>
          )}
        </div>
        {ai ? (
          <>
            <div className="mt-4 grid grid-cols-3 gap-2">
              <Metric
                label="위험 점수"
                value={ai.riskScore.toFixed(1)}
                suffix="/100"
                accent={SEVERITY_CLASS[severity].text}
              />
              <Metric
                label="신뢰도"
                value={(ai.confidence * 100).toFixed(1)}
                suffix="%"
              />
              <Metric label="판정" value={ai.prediction} />
            </div>
            <p className="mt-3 text-[10px] text-faint">
              모델 {ai.modelName} ({ai.modelVersion}) · 분석{" "}
              {fmtDateTime(ai.analyzedAt)}
            </p>
          </>
        ) : (
          <p className="mt-3 text-xs text-muted">
            이 플로우에 대한 AI 분석 결과가 없습니다.
          </p>
        )}
        {flow.attackId && (
          <button
            className="btn mt-3"
            onClick={() => pushDrawer({ kind: "incident", id: flow.attackId! })}
          >
            소속 공격 보기 · Incident #{flow.attackId}
          </button>
        )}
      </section>

      <Cols
        left={
          <>
            {ai && (
              <Section title="위험도 산출 근거">
                <FlowRiskBreakdown
                  breakdown={ai.riskBreakdown}
                  riskScore={ai.riskScore}
                />
              </Section>
            )}

            <Section title="연결 정보">
              <div className="mb-3 flex items-center gap-2 rounded-md bg-canvas p-3">
                <div className="min-w-0 flex-1">
                  <p className="text-[10px] text-faint">출발지</p>
                  <IpText ip={flow.srcIp} port={flow.srcPort} showScope />
                </div>
                <span className="text-faint">→</span>
                <div className="min-w-0 flex-1 text-right">
                  <p className="text-[10px] text-faint">목적지</p>
                  <IpText ip={flow.destIp} port={flow.destPort} showScope />
                </div>
              </div>
              <dl className="divide-y divide-line/60">
                <KeyValue label="공격 방향">
                  <DirectionBadge src={flow.srcIp} dst={flow.destIp} />
                </KeyValue>
                <KeyValue label="프로토콜">{flow.protocol}</KeyValue>
                <KeyValue label="시작" mono>
                  {fmtDateTime(flow.startTime)}
                </KeyValue>
                <KeyValue label="지속 시간">
                  {fmtDuration(flow.startTime, flow.endTime)}
                </KeyValue>
                <KeyValue label="패킷 (→서버 / →클라이언트)" mono>
                  {fmtNum(flow.pktsToServer)} / {fmtNum(flow.pktsToClient)}
                </KeyValue>
                <KeyValue label="바이트 (→서버 / →클라이언트)" mono>
                  {fmtNum(flow.bytesToServer)} / {fmtNum(flow.bytesToClient)}
                </KeyValue>
                {(flow.idsSeverity !== null || flow.idsRuleId) && (
                  <KeyValue label="Suricata 탐지">
                    심각도 {flow.idsSeverity ?? "-"} · 룰{" "}
                    <span className="font-mono">{flow.idsRuleId ?? "-"}</span>
                    {flow.eventType && (
                      <span className="text-muted"> · {flow.eventType}</span>
                    )}
                  </KeyValue>
                )}
              </dl>
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  className="btn"
                  onClick={() =>
                    copy(endpoint(flow.srcIp, flow.srcPort), "출발지")
                  }
                >
                  <Copy size={12} /> 출발지 복사
                </button>
                <button
                  className="btn"
                  onClick={() => {
                    closeDrawer();
                    navigate(
                      `/traffic?srcIp=${encodeURIComponent(flow.srcIp)}`,
                    );
                  }}
                >
                  <Filter size={12} /> 이 출발지의 트래픽
                </button>
              </div>
            </Section>
          </>
        }
        right={
          <>
            <Section title="TCP 플래그">
              <FlagBars flags={flow.flags} />
              <p className="mt-3 text-[11px] leading-relaxed text-muted">
                {flagInsight(flow.flags)}
              </p>
            </Section>

            {ai?.isAttack && (
              <Section title="대응 가이드">
                {flow.attackId ? (
                  /* 공격에 묶인 연결: 대응은 공격 단위로 하므로 같은 가이드를 반복하지 않음 */
                  <>
                    <ActionBanner action={ai.action} />
                    <p className="text-xs leading-relaxed text-muted">
                      이 연결은{" "}
                      <b className="text-ink">Incident #{flow.attackId}</b> 에
                      묶여 있습니다. 차단·설정 변경은 공격 단위로 하므로 대응
                      가이드는 공격 상세에서 확인하세요.
                    </p>
                    <button
                      className="btn mt-2"
                      onClick={() =>
                        pushDrawer({ kind: "incident", id: flow.attackId! })
                      }
                    >
                      공격 #{flow.attackId} 의 대응 가이드 보기
                    </button>
                  </>
                ) : (
                  <ResponsePlan
                    action={ai.action}
                    actionDetail={ai.actionDetail}
                    guide={ai.responseGuide}
                    target={{
                      attackType: ai.attackType,
                      srcIp: flow.srcIp,
                      destIp: flow.destIp,
                      destPort: flow.destPort,
                    }}
                    playbook={attackInfo(ai.attackType).playbook}
                  />
                )}
              </Section>
            )}
          </>
        }
      />

      {history.length > 1 && (
        <Section title={`AI 분석 이력 (${history.length}회)`}>
          <ul className="divide-y divide-line/60 text-xs">
            {history.map((h) => (
              <li key={h.id} className="flex items-center gap-3 py-1.5">
                <span className="w-36 font-mono text-muted">
                  {fmtDateTime(h.analyzedAt)}
                </span>
                <span className="flex-1 truncate">{h.modelName}</span>
                <span>{h.attackSubtype ?? attackInfo(h.attackType).label}</span>
                <span className="w-10 text-right font-mono">
                  {h.riskScore.toFixed(0)}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

function FlagBars({ flags }: { flags: TcpFlags }) {
  const entries: Array<[string, number]> = [
    ["SYN", flags.syn],
    ["ACK", flags.ack],
    ["FIN", flags.fin],
    ["RST", flags.rst],
    ["PSH", flags.psh],
    ["URG", flags.urg],
  ];
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div className="space-y-1.5">
      {entries.map(([name, v]) => (
        <div
          key={name}
          className="grid grid-cols-[36px_1fr_48px] items-center gap-2 text-[11px]"
        >
          <span className="font-mono text-muted">{name}</span>
          <span className="h-2 overflow-hidden rounded-sm bg-line/60">
            <span
              className="block h-full rounded-sm bg-accent"
              style={{ width: `${(v / max) * 100}%` }}
            />
          </span>
          <span className="text-right font-mono tabular-nums text-ink">
            {v.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

/** 플래그 조합 해석 (분석가 보조용, 판정 근거가 아님) */
function flagInsight(f: TcpFlags): string {
  if (f.syn > 0 && f.ack === 0 && f.rst === 0)
    return "SYN 만 있고 응답(ACK)이 없습니다. SYN Flood 또는 응답 없는 스캔에서 보이는 패턴입니다.";
  if (f.syn > 0 && f.rst > 0 && f.ack <= 1)
    return "SYN 직후 RST 로 끊긴 연결입니다. 닫힌 포트를 두드리는 포트 스캔에서 흔한 패턴입니다.";
  if (f.syn > 5 && f.ack > 0)
    return "짧은 시간에 연결 시도(SYN)가 반복되었습니다. 반복 로그인 시도일 수 있습니다.";
  if (f.syn + f.ack + f.fin + f.rst + f.psh + f.urg === 0)
    return "TCP 플래그 정보가 없습니다 (UDP/ICMP 이거나 수집되지 않음).";
  if (f.fin > 0 && f.ack > 0)
    return "연결 수립부터 종료(SYN→ACK→FIN)까지 정상적인 흐름입니다.";
  return "뚜렷한 특이 패턴은 없습니다. AI 판정과 같은 출발지의 다른 기록을 함께 확인하세요.";
}

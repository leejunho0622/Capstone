import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Bell,
  BrainCircuit,
  GitBranch,
  Eye,
  EyeOff,
  LayoutDashboard,
  ListChecks,
  Network,
  Pause,
  Play,
  RefreshCw,
  Search,
  Settings as SettingsIcon,
  ShieldHalf,
  Moon,
  Sun,
  Volume2,
  VolumeX,
  WifiOff,
} from "lucide-react";
import { useLiveData, type ConnectionState } from "../../store/liveData";
import { useSettings } from "../../store/settings";
import { useUi } from "../../store/ui";
import { useThreat } from "../../hooks/useThreat";
import { useHotkeys } from "../../hooks/useHotkeys";
import { THREAT_META } from "../../lib/severity";
import { fmtTime } from "../../lib/format";
import { unlockAudio } from "../../lib/alertAudio";
import { NotificationMenu, useNotifications } from "./NotificationMenu";
import { useLocalStorage } from "../../hooks/useLocalStorage";
import { DetailDrawer } from "../detail/DetailDrawer";
import { CriticalAlarm } from "../CriticalAlarm";
import { Toasts } from "../Toasts";
import { ShortcutHelp } from "../ShortcutHelp";

const NAV = [
  { to: "/", label: "관제 현황", icon: LayoutDashboard, key: "g o", end: true },
  { to: "/alerts", label: "경보 처리", icon: ListChecks, key: "g a", end: false },
  { to: "/chains", label: "공격 연관 분석", icon: GitBranch, key: "g c", end: false },
  { to: "/traffic", label: "트래픽 분석", icon: Network, key: "g t", end: false },
  { to: "/ai", label: "AI 성능 분석", icon: BrainCircuit, key: "g q", end: false },
  { to: "/settings", label: "설정", icon: SettingsIcon, key: "g s", end: false },
] as const;

const PAGE_TITLE: Record<string, string> = {
  "/": "관제 현황",
  "/alerts": "경보 처리",
  "/traffic": "트래픽 분석",
  "/chains": "공격 연관 분석",
  "/ai": "AI 성능 분석",
  "/settings": "설정",
};

export function AppShell() {
  const navigate = useNavigate();
  const location = useLocation();
  const { closeDrawer, drawer } = useUi();
  const { settings, update } = useSettings();
  const { refresh } = useLiveData();
  const { newCount } = useThreat();
  const searchRef = useRef<HTMLInputElement>(null);
  const [helpOpen, setHelpOpen] = useState(false);

  // 브라우저 자동재생 정책: 첫 상호작용 때 오디오 활성화
  useEffect(() => {
    const unlock = () => unlockAudio();
    window.addEventListener("pointerdown", unlock, { once: true });
    window.addEventListener("keydown", unlock, { once: true });
    return () => {
      window.removeEventListener("pointerdown", unlock);
      window.removeEventListener("keydown", unlock);
    };
  }, []);

  useHotkeys({
    "/": () => searchRef.current?.focus(),
    "g o": () => navigate("/"),
    "g a": () => navigate("/alerts"),
    "g t": () => navigate("/traffic"),
    "g c": () => navigate("/chains"),
    "g q": () => navigate("/ai"),
    "g s": () => navigate("/settings"),
    p: () => update({ paused: !settings.paused }),
    r: () => refresh(),
    "?": () => setHelpOpen((v) => !v),
    Escape: () => {
      if (drawer.length > 0) closeDrawer();
      else setHelpOpen(false);
      (document.activeElement as HTMLElement | null)?.blur?.();
    },
  });

  return (
    <div className="flex h-full">
      {/* ---------- 사이드바 ---------- */}
      <aside className="flex w-[64px] shrink-0 flex-col border-r border-line bg-surface xl:w-[220px]">
        <div className="flex h-14 items-center gap-2.5 border-b border-line px-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-accent to-brand text-white shadow-sm">
            <ShieldHalf size={18} />
          </div>
          <div className="hidden min-w-0 xl:block">
            <p className="text-sm font-bold leading-tight tracking-tight">관제탑</p>
            <p className="text-[10px] leading-tight text-muted">AI Network IDS · SOC</p>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-0.5 p-2" aria-label="주 메뉴">
          {NAV.map(({ to, label, icon: Icon, key, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              title={`${label} (${key})`}
              className={({ isActive }) =>
                `group relative flex h-9 items-center gap-3 rounded-md px-3 text-[13px] transition ${
                  isActive ? "bg-accent/10 font-semibold text-accent" : "text-muted hover:bg-raised hover:text-ink"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && <span className="absolute inset-y-1.5 left-0 w-1 rounded-full bg-gradient-to-b from-accent to-brand" />}
                  <Icon size={17} className="shrink-0" />
                  <span className="hidden flex-1 xl:inline">{label}</span>
                  {to === "/alerts" && newCount > 0 && (
                    <span className="absolute right-1 top-1 rounded-full bg-sev-critical px-1.5 font-mono text-[10px] font-bold leading-4 text-white xl:static">
                      {newCount > 99 ? "99+" : newCount}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="hidden border-t border-line p-3 text-[10px] leading-relaxed text-faint xl:block">
          <button className="hover:text-muted" onClick={() => setHelpOpen(true)}>
            단축키 보기 <span className="kbd ml-1">?</span>
          </button>
          <p className="mt-1">분석가: {settings.analyst}</p>
        </div>
      </aside>

      {/* ---------- 본문 ---------- */}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          title={PAGE_TITLE[location.pathname] ?? (location.pathname.startsWith("/incidents/") ? "경보 상세" : location.pathname.startsWith("/flows/") ? "플로우 상세" : "")}
          searchRef={searchRef}
        />
        <ZoomHint />
        <ConnectionBanner />
        <main className="min-h-0 flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>

      <DetailDrawer />
      <CriticalAlarm />
      <Toasts />
      {helpOpen && <ShortcutHelp onClose={() => setHelpOpen(false)} />}
    </div>
  );
}

function Topbar({
  title,
  searchRef,
}: {
  title: string;
  searchRef: React.RefObject<HTMLInputElement | null>;
}) {
  const navigate = useNavigate();
  const { openFlow } = useUi();
  const { settings, update } = useSettings();
  const { connection, lastUpdated, refresh } = useLiveData();
  const { level } = useThreat();
  const [q, setQ] = useState("");
  const [bellOpen, setBellOpen] = useState(false);
  const [lastSeen, setLastSeen] = useLocalStorage<number>("notif-seen", 0);
  const threat = THREAT_META[level];

  const submit = () => {
    const v = q.trim();
    if (!v) return;
    if (/^\d+$/.test(v)) openFlow(v); // 숫자만 → Flow ID
    else navigate(`/traffic?q=${encodeURIComponent(v)}`);
    setQ("");
    searchRef.current?.blur();
  };

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-surface px-4">
      <h1 className="mr-1 hidden text-[15px] font-semibold md:block">{title}</h1>

      <span
        className={`hidden items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1 ring-inset lg:inline-flex ${threat.className}`}
        title={threat.desc}
      >
        위협 수준 · {threat.label}
      </span>

      <form
        className="relative ml-auto w-full max-w-xs"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
        <input
          ref={searchRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="IP · 포트 · Flow ID 검색"
          aria-label="전체 검색"
          className="input w-full pl-8 pr-8"
        />
        <span className="kbd absolute right-2 top-1/2 -translate-y-1/2">/</span>
      </form>

      <LiveIndicator connection={connection} lastUpdated={lastUpdated} />

      <div className="flex items-center gap-0.5">
        <button
          className="btn btn-ghost h-8 w-8 px-0"
          onClick={() => update({ paused: !settings.paused })}
          title={settings.paused ? "실시간 갱신 재개 (P)" : "실시간 갱신 일시정지 (P)"}
          aria-label={settings.paused ? "실시간 갱신 재개" : "실시간 갱신 일시정지"}
        >
          {settings.paused ? <Play size={15} /> : <Pause size={15} />}
        </button>
        <button className="btn btn-ghost h-8 w-8 px-0" onClick={refresh} title="지금 새로고침 (R)" aria-label="새로고침">
          <RefreshCw size={15} />
        </button>
        <span className="mx-1 h-5 w-px bg-line" />
        <button
          className={`btn btn-ghost h-8 w-8 px-0 ${settings.visualAlarm ? "text-ink" : ""}`}
          onClick={() => update({ visualAlarm: !settings.visualAlarm })}
          aria-pressed={settings.visualAlarm}
          title={`시각 경보 ${settings.visualAlarm ? "켜짐" : "꺼짐"}`}
          aria-label="시각 경보 켜기/끄기"
        >
          {settings.visualAlarm ? <Eye size={15} /> : <EyeOff size={15} />}
        </button>
        <button
          className={`btn btn-ghost h-8 w-8 px-0 ${settings.soundAlarm ? "text-ink" : ""}`}
          onClick={() => {
            unlockAudio();
            update({ soundAlarm: !settings.soundAlarm, voiceAlarm: !settings.soundAlarm });
          }}
          aria-pressed={settings.soundAlarm}
          title={`청각 경보 ${settings.soundAlarm ? "켜짐" : "꺼짐"}`}
          aria-label="청각 경보 켜기/끄기"
        >
          {settings.soundAlarm ? <Volume2 size={15} /> : <VolumeX size={15} />}
        </button>
        <ThemeToggle />
        <div className="relative">
          <NotificationBell open={bellOpen} lastSeen={lastSeen} onToggle={() => setBellOpen((v) => !v)} />
          {bellOpen && (
            <NotificationMenu
              lastSeen={lastSeen}
              onMarkAllRead={() => setLastSeen(Date.now())}
              onClose={() => setBellOpen(false)}
            />
          )}
        </div>
      </div>
    </header>
  );
}

function NotificationBell({
  open,
  lastSeen,
  onToggle,
}: {
  open: boolean;
  lastSeen: number;
  onToggle: () => void;
}) {
  const unread = useNotifications(lastSeen).filter((n) => n.unread).length;
  return (
    <button
      className={`btn btn-ghost relative h-8 w-8 px-0 ${open ? "bg-raised text-ink" : ""}`}
      onClick={onToggle}
      aria-expanded={open}
      aria-label={`알림 ${unread}건`}
      title="알림"
    >
      <Bell size={15} />
      {unread > 0 && (
        <span className="absolute -right-0.5 -top-0.5 min-w-4 rounded-full bg-sev-critical px-1 font-mono text-[9px] font-bold leading-4 text-white">
          {unread > 99 ? "99+" : unread}
        </span>
      )}
    </button>
  );
}

function LiveIndicator({ connection, lastUpdated }: { connection: ConnectionState; lastUpdated: Date | null }) {
  const meta: Record<ConnectionState, { label: string; dot: string; text: string }> = {
    connecting: { label: "연결 중", dot: "bg-faint", text: "text-muted" },
    live: { label: "LIVE", dot: "bg-brand", text: "text-brand" },
    degraded: { label: "일부 지연", dot: "bg-sev-medium", text: "text-sev-medium" },
    down: { label: "연결 끊김", dot: "bg-sev-critical", text: "text-sev-critical" },
    paused: { label: "일시정지", dot: "bg-faint", text: "text-muted" },
  };
  const m = meta[connection];
  return (
    <div className="hidden shrink-0 items-center gap-2 rounded-md border border-line bg-canvas px-2.5 py-1 sm:flex" aria-live="polite">
      <span className="relative flex h-2 w-2">
        {connection === "live" && <span className={`absolute inline-flex h-full w-full animate-live-ping rounded-full ${m.dot}`} />}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${m.dot}`} />
      </span>
      <span className={`text-[11px] font-bold tracking-wider ${m.text}`}>{m.label}</span>
      <span className="font-mono text-[11px] tabular-nums text-muted">{fmtTime(lastUpdated)}</span>
    </div>
  );
}

function ConnectionBanner() {
  const { connection, errorMessage, failedEndpoints, refresh } = useLiveData();
  if (connection !== "down" && connection !== "degraded") return null;
  return (
    <div
      role="status"
      className={`flex items-center gap-2 border-b px-4 py-1.5 text-xs ${
        connection === "down"
          ? "border-sev-critical/40 bg-sev-critical/10 text-ink"
          : "border-sev-medium/40 bg-sev-medium/10 text-ink"
      }`}
    >
      <WifiOff size={14} className={connection === "down" ? "text-sev-critical" : "text-sev-medium"} />
      {connection === "down" ? (
        <span>
          {errorMessage ?? "백엔드 서버에 연결할 수 없습니다"}. 마지막으로 받은 데이터를 표시 중이며 자동으로 재시도합니다.
        </span>
      ) : (
        <span>일부 데이터를 불러오지 못했습니다: {failedEndpoints.join(", ")}</span>
      )}
      <button className="ml-auto font-semibold text-accent hover:underline" onClick={refresh}>
        지금 재시도
      </button>
    </div>
  );
}

/** 밝은 ↔ 어두운 테마 빠른 전환 (세부 설정은 설정 화면) */
function ThemeToggle() {
  const { settings, update } = useSettings();
  const isDark =
    settings.theme === "dark" ||
    (settings.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  return (
    <button
      className="btn btn-ghost h-8 w-8 px-0"
      onClick={() => update({ theme: isDark ? "light" : "dark" })}
      title={isDark ? "밝은 테마로 전환" : "어두운 테마로 전환 (관제실 벽면 모니터용)"}
      aria-label="테마 전환"
    >
      {isDark ? <Sun size={15} /> : <Moon size={15} />}
    </button>
  );
}

/**
 * 브라우저 배율 안내
 * Chrome 은 사이트별 배율을 기억하므로, 예전 화면에 맞춰 축소해 둔 배율(예: 67%)이
 * 그대로 남아 글자가 아주 작게 보일 수 있음. 일반 모니터(배율 1)에서 축소된 경우에만 안내.
 */
function ZoomHint() {
  const [ratio, setRatio] = useState(() => window.devicePixelRatio || 1);
  const [dismissed, setDismissed] = useState(() => sessionStorage.getItem("gwanjetap:zoom-hint") === "1");

  useEffect(() => {
    const onResize = () => setRatio(window.devicePixelRatio || 1);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  if (dismissed || ratio >= 0.95) return null;
  return (
    <div role="status" className="flex items-center gap-2 border-b border-accent/30 bg-accent/10 px-4 py-1.5 text-xs text-ink">
      <span>
        브라우저 화면 배율이 약 <b>{Math.round(ratio * 100)}%</b>로 축소되어 있어 글자가 작게 보입니다.{" "}
        <span className="kbd">Ctrl</span> + <span className="kbd">0</span> 을 눌러 100%로 맞추면 설계한 비율로 보입니다.
      </span>
      <button
        className="ml-auto font-semibold text-accent hover:underline"
        onClick={() => {
          sessionStorage.setItem("gwanjetap:zoom-hint", "1");
          setDismissed(true);
        }}
      >
        닫기
      </button>
    </div>
  );
}

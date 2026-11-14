import type { ReactNode } from "react";
import { BellRing, Database, Palette, RotateCcw, User, Volume2 } from "lucide-react";
import { DEFAULT_SETTINGS, useSettings, type Settings, type ThemeMode } from "../store/settings";
import { useTriage } from "../store/triage";
import { useLiveData } from "../store/liveData";
import { useUi } from "../store/ui";
import { SEVERITY_META } from "../lib/severity";
import { playAlarm, speak, unlockAudio } from "../lib/alertAudio";
import { API_BASE } from "../api/http";
import { fmtDateTime } from "../lib/format";

export default function SettingsPage() {
  const { settings, update, reset } = useSettings();
  const triage = useTriage();
  const live = useLiveData();
  const { toast } = useUi();

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4 lg:p-6">
      <Card icon={<User size={15} />} title="관제요원" desc="경보 처리 기록에 남는 이름입니다.">
        <Row label="이름">
          <input
            className="input w-56"
            value={settings.analyst}
            maxLength={30}
            onChange={(e) => update({ analyst: e.target.value })}
          />
        </Row>
      </Card>

      <Card icon={<Palette size={15} />} title="화면 테마" desc="밝은 테마가 기본입니다. 관제실 대형 모니터·야간 근무에는 어두운 테마를 권장합니다.">
        <Row label="테마">
          <div role="radiogroup" aria-label="테마" className="inline-flex rounded-md border border-line bg-canvas p-0.5">
            {(
              [
                ["light", "밝게"],
                ["dark", "어둡게"],
                ["system", "시스템 설정"],
              ] as Array<[ThemeMode, string]>
            ).map(([value, label]) => (
              <button
                key={value}
                role="radio"
                aria-checked={settings.theme === value}
                onClick={() => update({ theme: value })}
                className={`h-7 rounded px-3 text-xs font-medium transition ${
                  settings.theme === value ? "bg-surface text-accent shadow-sm" : "text-muted hover:text-ink"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </Row>
      </Card>

      <Card icon={<Database size={15} />} title="데이터 갱신">
        <Row label="갱신 주기" hint="짧을수록 빠르지만 서버 부하가 늘어납니다.">
          <select className="input w-40" value={settings.pollMs} onChange={(e) => update({ pollMs: Number(e.target.value) })}>
            {[3000, 5000, 10000, 30000].map((ms) => (
              <option key={ms} value={ms}>
                {ms / 1000}초
              </option>
            ))}
          </select>
        </Row>
        <Row label="경보 조회 범위" hint="이 기간 안에 활동한 공격을 경보 목록에 불러옵니다.">
          <select
            className="input w-40"
            value={settings.alertWindowHours}
            onChange={(e) => update({ alertWindowHours: Number(e.target.value) })}
          >
            {[1, 6, 24, 72, 168].map((h) => (
              <option key={h} value={h}>
                {h < 24 ? `최근 ${h}시간` : `최근 ${h / 24}일`}
              </option>
            ))}
          </select>
        </Row>
        <Row label="실시간 갱신">
          <Toggle checked={!settings.paused} onChange={(v) => update({ paused: !v })} label="실시간 갱신" />
        </Row>
        <Row label="연결 상태">
          <span className="text-xs text-muted">
            {live.connection === "live" ? "정상" : live.connection} · API {API_BASE || "Vite 프록시 (/api)"} · 마지막 갱신{" "}
            {fmtDateTime(live.lastUpdated)}
          </span>
        </Row>
      </Card>

      <Card icon={<BellRing size={15} />} title="경보 알림 (접근성)" desc="새 공격이 탐지되면 화면 깜빡임·경보음·음성으로 알립니다.">
        <Row label="알림 기준 등급" hint="이 등급 이상인 새 공격만 알립니다.">
          <select
            className="input w-48"
            value={settings.alarmSeverity}
            onChange={(e) => update({ alarmSeverity: e.target.value as Settings["alarmSeverity"] })}
          >
            {(["critical", "high", "medium"] as const).map((s) => (
              <option key={s} value={s}>
                {SEVERITY_META[s].label} 이상 (위험도 {SEVERITY_META[s].min}점~)
              </option>
            ))}
          </select>
        </Row>
        <Row label="시각 경보" hint="화면 전체 붉은 깜빡임 + 경보 배너">
          <Toggle checked={settings.visualAlarm} onChange={(v) => update({ visualAlarm: v })} label="시각 경보" />
        </Row>
        <Row label="경보음">
          <Toggle checked={settings.soundAlarm} onChange={(v) => update({ soundAlarm: v })} label="경보음" />
        </Row>
        <Row label="음성 안내" hint="공격 유형·위험도·출발지를 한국어로 읽어줍니다.">
          <Toggle checked={settings.voiceAlarm} onChange={(v) => update({ voiceAlarm: v })} label="음성 안내" />
        </Row>
        <Row label="음량">
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={settings.volume}
            onChange={(e) => update({ volume: Number(e.target.value) })}
            className="w-48 accent-[rgb(var(--c-accent))]"
            aria-label="음량"
          />
          <span className="w-10 text-right font-mono text-xs text-muted">{Math.round(settings.volume * 100)}%</span>
        </Row>
        <Row label="테스트">
          <button
            className="btn"
            onClick={() => {
              unlockAudio();
              playAlarm(settings.volume);
              window.setTimeout(
                () => speak("테스트 경보입니다. 경보음과 음성 안내가 정상적으로 동작합니다.", settings.volume),
                1100
              );
            }}
          >
            <Volume2 size={13} /> 경보음·음성 테스트
          </button>
        </Row>
      </Card>

      <Card icon={<RotateCcw size={15} />} title="초기화">
        <Row label="경보 처리 저장 위치">
          <span className="text-xs text-muted">
            {triage.mode === "server"
              ? "서버 (incident_triage 테이블, 팀원과 공유)"
              : "이 브라우저 (백엔드에 /api/incidents/{id}/triage 가 없음)"}
          </span>
          {triage.mode === "local" && (
            <button
              className="btn"
              onClick={() => {
                triage.clearLocal();
                toast("브라우저에 저장된 처리 기록을 지우고 서버 모드로 다시 시도합니다", "info");
              }}
            >
              로컬 기록 지우기
            </button>
          )}
        </Row>
        <Row label="설정">
          <button
            className="btn"
            onClick={() => {
              reset();
              toast("설정을 기본값으로 되돌렸습니다", "success");
            }}
            disabled={JSON.stringify(settings) === JSON.stringify(DEFAULT_SETTINGS)}
          >
            기본값으로 되돌리기
          </button>
        </Row>
      </Card>
    </div>
  );
}

function Card({ icon, title, desc, children }: { icon: ReactNode; title: string; desc?: string; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <div className="flex items-center gap-2">
          <span className="text-accent">{icon}</span>
          <div>
            <h2 className="panel-title">{title}</h2>
            {desc && <p className="text-[11px] text-muted">{desc}</p>}
          </div>
        </div>
      </header>
      <div className="divide-y divide-line/60 px-4">{children}</div>
    </section>
  );
}

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 py-3">
      <div>
        <p className="text-xs text-ink">{label}</p>
        {hint && <p className="text-[11px] text-faint">{hint}</p>}
      </div>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-9 rounded-full transition ${checked ? "bg-accent" : "bg-line"}`}
    >
      <span
        className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all ${checked ? "left-[18px]" : "left-0.5"}`}
      />
    </button>
  );
}

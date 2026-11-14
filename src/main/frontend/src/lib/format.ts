const pad = (n: number) => String(n).padStart(2, "0");

export function fmtTime(d: Date | null | undefined): string {
  if (!d) return "-";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function fmtDateTime(d: Date | null | undefined): string {
  if (!d) return "-";
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(d)}`;
}

/** 오늘이면 시각만, 아니면 월/일 + 시각 */
export function fmtSmart(d: Date | null | undefined): string {
  if (!d) return "-";
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  return sameDay ? fmtTime(d) : `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${fmtTime(d)}`;
}

export function fmtAgo(d: Date | null | undefined, now = Date.now()): string {
  if (!d) return "-";
  const sec = Math.max(0, Math.round((now - d.getTime()) / 1000));
  if (sec < 10) return "방금";
  if (sec < 60) return `${sec}초 전`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}분 전`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}시간 전`;
  return `${Math.floor(hr / 24)}일 전`;
}

export function fmtDuration(start: Date | null, end: Date | null): string {
  if (!start || !end) return "-";
  const ms = end.getTime() - start.getTime();
  if (ms < 0) return "-";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}초`;
  return `${Math.floor(s / 60)}분 ${Math.round(s % 60)}초`;
}

export function fmtNum(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "-";
  return n.toLocaleString("ko-KR");
}

export function fmtPct(ratio: number, digits = 1): string {
  return `${(ratio * 100).toFixed(digits)}%`;
}

export function endpoint(ip: string, port: number | null): string {
  return port === null || port === undefined ? ip : `${ip}:${port}`;
}

/** 사설 IP 여부 (내부/외부 구분 표시용) */
export function isPrivateIp(ip: string): boolean {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

/** 잘 알려진 포트 이름 */
const PORT_NAMES: Record<number, string> = {
  20: "FTP-DATA",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  123: "NTP",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  993: "IMAPS",
  1433: "MSSQL",
  1521: "Oracle",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  9200: "Elasticsearch",
  27017: "MongoDB",
};

export function portName(port: number | null): string | null {
  if (port === null || port === undefined) return null;
  return PORT_NAMES[port] ?? null;
}

/** 초 → "12초", "1분 5초", "1시간 3분" */
export function fmtSec(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || !Number.isFinite(sec)) return "-";
  const s = Math.round(sec);
  if (s < 60) return `${s}초`;
  if (s < 3600) return `${Math.floor(s / 60)}분${s % 60 ? ` ${s % 60}초` : ""}`;
  return `${Math.floor(s / 3600)}시간 ${Math.floor((s % 3600) / 60)}분`;
}

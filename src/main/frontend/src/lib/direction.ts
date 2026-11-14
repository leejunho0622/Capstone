/* =========================================================
   공격 방향 (Suricata HOME_NET 기준)
   AI 파이프라인 설정: HOME_NET = [192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12]
   ========================================================= */

export type Direction = "inbound" | "lateral" | "outbound" | "external" | "self";

export const DIRECTION_META: Record<
  Direction,
  { label: string; short: string; desc: string; className: string }
> = {
  inbound: {
    label: "외부 → 내부",
    short: "유입",
    desc: "외부에서 내부망으로 들어온 공격 (침입 시도)",
    className: "bg-accent/10 text-accent ring-accent/30",
  },
  lateral: {
    label: "내부 → 내부",
    short: "내부 확산",
    desc: "내부 호스트가 다른 내부 호스트를 공격 (감염 단말의 측면 이동 의심)",
    className: "bg-sev-medium/10 text-sev-medium ring-sev-medium/30",
  },
  outbound: {
    label: "내부 → 외부",
    short: "유출 의심",
    desc: "내부 호스트가 외부로 나가는 공격성 통신 (C2 교신·정보 유출 의심)",
    className: "bg-sev-high/10 text-sev-high ring-sev-high/30",
  },
  external: {
    label: "외부 → 외부",
    short: "외부",
    desc: "보호 대상(HOME_NET)과 무관한 통신",
    className: "bg-sev-info/10 text-sev-info ring-sev-info/30",
  },
  self: {
    label: "같은 호스트",
    short: "자체",
    desc: "출발지와 목적지가 같은 호스트 (점검·테스트 트래픽일 수 있음)",
    className: "bg-sev-info/10 text-sev-info ring-sev-info/30",
  },
};

const HOME_NET: Array<[number, number]> = [
  [ip4("192.168.0.0"), 16],
  [ip4("10.0.0.0"), 8],
  [ip4("172.16.0.0"), 12],
  [ip4("127.0.0.0"), 8],
];

function ip4(ip: string): number {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return NaN;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function isHomeNet(ip: string): boolean {
  const n = ip4(ip);
  if (Number.isNaN(n)) return false;
  return HOME_NET.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((base & mask) >>> 0);
  });
}

export function directionOf(src: string, dst: string): Direction | null {
  if (!src || !dst || src === "-" || dst === "-") return null;
  if (src === dst) return "self";
  const s = isHomeNet(src);
  const d = isHomeNet(dst);
  if (!s && d) return "inbound";
  if (s && d) return "lateral";
  if (s && !d) return "outbound";
  return "external";
}

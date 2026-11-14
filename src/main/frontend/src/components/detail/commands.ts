import type { Alert } from "../../api/types";
import { normalizeAttackKey } from "../../lib/attackTypes";

/**
 * 공격 유형별 즉시 대응 명령 예시
 * - 프로젝트 환경(Ubuntu 24.04 + nftables) 기준, 효과가 같은 명령은 하나만 둔다
 *   (iptables 는 24.04 에서 nftables 로 변환되어 같은 동작, fail2ban banip 도 같은 출발지 차단)
 * - 'inet filter' 테이블/체인이 있어야 동작하는 예시 명령입니다.
 * - 런타임 적용이라 재부팅하면 사라짐 → 영구 적용은 response_guide 의 설정 파일
 */
export function responseCommands(a: Pick<Alert, "attackType" | "srcIp" | "destIp" | "destPort">) {
  const key = normalizeAttackKey(a.attackType);
  const port = a.destPort ?? 80;
  const cmds: Array<{ label: string; cmd: string }> = [];

  switch (key) {
    case "SYNFlood":
      cmds.push({ label: "SYN Cookie", cmd: "sudo sysctl -w net.ipv4.tcp_syncookies=1" });
      cmds.push({
        label: "SYN 속도 제한",
        cmd: `sudo nft add rule inet filter input tcp dport ${port} tcp flags syn limit rate over 100/second drop`,
      });
      break;
    case "DDoS":
      cmds.push({
        label: "연결 속도 제한",
        cmd: `sudo nft add rule inet filter input ip daddr ${a.destIp} tcp dport ${port} limit rate over 1000/second drop`,
      });
      break;
    case "C2Beacon":
      cmds.push({ label: "외부 C&C 차단", cmd: `sudo nft add rule inet filter output ip daddr ${a.destIp} drop` });
      cmds.push({ label: "감염 의심 호스트 격리", cmd: `sudo nft add rule inet filter forward ip saddr ${a.srcIp} drop` });
      break;
    default:
      cmds.push({ label: "출발지 차단", cmd: `sudo nft add rule inet filter input ip saddr ${a.srcIp} drop` });
  }
  return cmds;
}

/** action_detail 에서 '[설정 파일: a / b]' 줄을 떼어 냄 (response_guide.config_files 와 중복) */
export function splitActionDetail(text: string | null | undefined): { message: string; files: string[] } {
  if (!text) return { message: "", files: [] };
  const files: string[] = [];
  const message = text
    .replace(/^\s*\[설정 파일:\s*([^\]]*)\]\s*$/gm, (_, list: string) => {
      list.split(/\s+\/\s+|,\s*/).map((x) => x.trim()).filter(Boolean).forEach((x) => files.push(x));
      return "";
    })
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  return { message, files };
}

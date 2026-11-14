/* =========================================================
   AI 권장 대응 코드 (response_playbook.py 의 action 값)
   ========================================================= */

export const ACTION_LABEL: Record<string, string> = {
  block_src: "출발지 차단",
  monitor_src: "출발지 집중 모니터링",
  monitor: "모니터링",
  rate_limit: "속도 제한",
  syn_cookie: "SYN 쿠키 활성화",
  lockout: "계정 잠금 + 차단",
  isolate_host: "호스트 격리",
  escalate: "보안팀 에스컬레이션",
  allow: "허용 (정상)",
};

export function actionLabel(code: string | null | undefined): string {
  if (!code || code === "-") return "-";
  return ACTION_LABEL[code] ?? code;
}

/* =========================================================
   청각 경보 (접근성)
   - 경고음: Web Audio API (외부 파일 불필요)
   - 음성 안내: Web Speech API (ko-KR)
   - 브라우저 정책상 사용자가 화면을 한 번 클릭해야 소리가 납니다.
   ========================================================= */

let ctx: AudioContext | null = null;

function getContext(): AudioContext | null {
  const Ctor =
    window.AudioContext ||
    (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  if (!ctx) ctx = new Ctor();
  return ctx;
}

/** 첫 클릭/키 입력 때 오디오를 깨워 두기 (자동재생 정책 대응) */
export function unlockAudio() {
  const c = getContext();
  if (c && c.state === "suspended") void c.resume();
}

export function playAlarm(volume = 0.6) {
  const c = getContext();
  if (!c) return;
  if (c.state === "suspended") void c.resume();

  const gain = c.createGain();
  gain.connect(c.destination);
  const t0 = c.currentTime;
  const peak = Math.max(0.0002, 0.25 * volume);

  // 두 음을 번갈아 3회: 관제실 경보음 느낌
  [0, 0.36, 0.72].forEach((offset) => {
    [
      { f: 988, d: 0 },
      { f: 784, d: 0.16 },
    ].forEach(({ f, d }) => {
      const start = t0 + offset + d;
      const osc = c.createOscillator();
      const g = c.createGain();
      osc.type = "square";
      osc.frequency.setValueAtTime(f, start);
      g.gain.setValueAtTime(0.0001, start);
      g.gain.exponentialRampToValueAtTime(peak, start + 0.015);
      g.gain.exponentialRampToValueAtTime(0.0001, start + 0.14);
      osc.connect(g).connect(gain);
      osc.start(start);
      osc.stop(start + 0.15);
    });
  });
}

export function speak(text: string, volume = 1) {
  if (!("speechSynthesis" in window)) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = "ko-KR";
  u.rate = 1;
  u.volume = Math.min(1, Math.max(0, volume));
  const voice = window.speechSynthesis.getVoices().find((v) => v.lang.startsWith("ko"));
  if (voice) u.voice = voice;
  window.speechSynthesis.speak(u);
}

export function stopSpeaking() {
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
}

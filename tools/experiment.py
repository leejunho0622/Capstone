#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
관제탑 실트래픽 탐지 성능 측정 스크립트 (experiment.py)
==========================================================

시나리오(공격/정상 트래픽)를 정해진 횟수만큼 자동으로 실행하고, 각 시험의
시작·종료 시각을 기록한 뒤 DB(flows / ai_results / attack_events)에서
아래 지표를 자동 집계한다.

  - 공격 단위 탐지율 : 시험 1회마다 '기대 유형'의 공격(attack_events)이 생겼는가 (k / n)
  - 연결 단위 정분류율: 시험 구간 연결 중 기대 유형으로 판정된 비율
  - 탐지 시간         : 공격 명령 실행 → 첫 AI 공격 판정까지 걸린 초
  - 오분류 분포       : 다른 유형으로 판정된 연결 수
  - 정상 구간 오탐률  : 정상 트래픽 연결 중 공격으로 판정된 비율, 잘못 생긴 경보 수(시간당)

결과는 화면 표 + 결과 폴더(summary.md / runs.csv / windows.json)로 저장한다.
summary.md 의 표는 결과보고서 '시험 및 평가'에 그대로 옮겨 쓸 수 있다.

기존 AI·백엔드·프론트 코드는 수정하지 않는다 (DB 는 읽기만 함).

----------------------------------------------------------------------
실행 (VM, root 필요: nmap -sS / hping3 / collector 실행 권한)

  # 1) 계획만 확인 (아무것도 실행하지 않음)
  sudo ~/ids-ai/venv/bin/python experiment.py --dry-run

  # 2) 기본 측정 (공격 시나리오 각 5회 + 정상 30분)
  sudo ~/ids-ai/venv/bin/python experiment.py

  # 3) 빠른 점검 (각 1회 + 정상 5분)
  sudo ~/ids-ai/venv/bin/python experiment.py --reps 1 --normal-min 5

  # 4) 시나리오 고르기 (목록: --list)
  sudo ~/ids-ai/venv/bin/python experiment.py --scenarios portscan_syn,synflood,normal

  # 5) 이미 측정한 구간을 다시 집계 (공격은 다시 하지 않음)
  sudo ~/ids-ai/venv/bin/python experiment.py --analyze ~/ids-ai/experiments/20261109_140000/windows.json

DB 접속 정보는 환경변수로 준다 (비밀번호가 없으면 실행 시 물어봄)
  IDS_DB_HOST(기본 localhost) IDS_DB_PORT(3306) IDS_DB_USER(ids_user) IDS_DB_NAME(ids_db) IDS_DB_PASSWORD
  예) sudo IDS_DB_PASSWORD='...' ~/ids-ai/venv/bin/python experiment.py
----------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import pwd
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# ----------------------------------------------------------------------
# 기본값
# ----------------------------------------------------------------------
DEFAULT_REPS = 5
DEFAULT_NORMAL_MIN = 30
# 시험 사이 대기: 마지막 연결이 마감·분석되는 시간(flow-timeout, 수십 초) + attack_grouper 묶음 간격(120초)보다 길게.
# 짧으면 다음 시험이 이전 공격 묶음에 합쳐진다 (실측: 150초에서 nmap 2회가 공격 1건으로 합쳐짐)
DEFAULT_COOLDOWN = 240
# 마지막 시험 후 집계 전 대기: 아직 마감되지 않은 연결이 DB 에 들어올 시간
DEFAULT_SETTLE = 120
WINDOW_MARGIN_SEC = 5  # 구간 앞뒤 여유
EVE_PATH = "/var/log/suricata/eve.json"
DRAIN_OK_BYTES = 200_000     # collector 가 읽지 않고 남은 eve.json 이 이 이하이면 '따라잡음'
DRAIN_MAX_WAIT = 1800        # 최대 30분 기다림

TS = "%Y-%m-%d %H:%M:%S"

# 정상 트래픽 생성용 (평소 사용 흉내: 웹 접속 + DNS 조회)
NORMAL_URLS = [
    "https://www.google.com", "https://www.naver.com", "https://www.daum.net",
    "https://github.com", "https://www.wikipedia.org", "https://pypi.org",
    "https://ubuntu.com", "https://www.python.org", "http://example.com",
]
NORMAL_HOSTS = ["www.google.com", "www.naver.com", "github.com", "ubuntu.com", "pypi.org", "example.com"]


# ----------------------------------------------------------------------
# 시나리오 정의
# ----------------------------------------------------------------------
@dataclass
class Scenario:
    key: str
    title: str                   # 보고서 표에 쓰는 이름
    expected: str | None         # 기대 attack_type (정상은 None)
    cmd: list[str] | None        # 실행 명령 ({ip}, {subnet}, {wordlist}, {user} 치환)
    tools: list[str]             # 필요한 실행 파일
    flow_filter: str             # self: src=dst=내 IP / src: src=내 IP / any: 전부
    dest_port: int | None = None # 연결 집계 시 목적지 포트 제한 (배경 트래픽 제외)
    default_on: bool = True
    note: str = ""


SCENARIOS: dict[str, Scenario] = {
    s.key: s
    for s in [
        Scenario("portscan_syn", "nmap SYN 스캔 (-sS, 1-1000)", "PortScan",
                 ["nmap", "-sS", "-p", "1-1000", "-T4", "{ip}"], ["nmap"], "self"),
        Scenario("portscan_connect", "nmap TCP 연결 스캔 (-sT, 1-1000)", "PortScan",
                 ["nmap", "-sT", "-p", "1-1000", "-T4", "{ip}"], ["nmap"], "self"),
        # --flood 5초는 연결 기록 약 40만 개를 만들어 collector(초당 20~50건)가 몇 시간 밀린다(1차 실측:
        # eve.json 2,138,516개 중 DB 22,667개). 판정 규칙 수정(데이터 비율) 뒤에는 속도와 무관하게
        # SYN Flood 로 판정되므로, 처리 가능한 규모(초당 1,000개 × 1초 = SYN 1,000개)로 보낸다.
        Scenario("synflood", "hping3 SYN Flood (초당 1,000개, SYN 1,000개, :80)", "SYNFlood",
                 ["hping3", "-S", "-p", "80", "-i", "u1000", "-c", "1000", "{ip}"], ["hping3"], "self", 80),
        # 무차별 대입 판정은 60초 안에 같은 출발지 연결 30개 이상이 필요 → 비밀번호를 넉넉히(200개)
        Scenario("bruteforce_ssh", "hydra SSH 무차별 대입 (비밀번호 200개)", "BruteForce",
                 ["hydra", "-l", "{user}", "-P", "{wordlist}", "-t", "4", "-I", "ssh://{ip}"], ["hydra"], "self", 22,
                 note="sshd 가 켜져 있어야 함. 존재하지 않는 계정으로 로그인 실패만 발생시킴"),
        Scenario("netscan", "nmap 호스트 탐색 (-sn, /24)", "NetworkScan",
                 ["nmap", "-sn", "-T4", "{subnet}"], ["nmap"], "src", default_on=False,
                 note="같은 /24 대역의 다른 호스트에도 ping 이 나감. 실습망(VMware NAT 등)에서만 사용"),
        Scenario("c2beacon", "C2 비콘 흉내 (10초 간격 HTTPS 12회)", "C2Beacon",
                 None, ["curl"], "src", 443, default_on=False,
                 note="외부 인터넷 필요. example.com 으로 일정 간격 요청"),
        Scenario("normal", "정상 사용", None, None, ["curl"], "src",
                 note="웹 접속·DNS 조회를 무작위 간격으로 생성 (직접 평소처럼 사용해도 됨)"),
    ]
}


# ----------------------------------------------------------------------
# 측정 결과 구조
# ----------------------------------------------------------------------
@dataclass
class Window:
    scenario: str
    rep: int
    start: str
    end: str
    my_ip: str
    rc: int | None = None
    error: str = ""


@dataclass
class RunResult:
    scenario: str
    rep: int
    start: str
    end: str
    flows_total: int = 0
    flows_expected: int = 0
    flows_attack: int = 0
    type_counts: dict = field(default_factory=dict)
    incident_detected: bool = False
    incidents: list = field(default_factory=list)  # [(id, type, subtype, flow_count)]
    detect_sec: float | None = None
    error: str = ""


# ----------------------------------------------------------------------
# 공통 유틸
# ----------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def real_home() -> Path:
    """sudo 로 실행해도 원래 사용자의 홈(~/ids-ai)을 찾는다."""
    user = os.environ.get("SUDO_USER")
    if user and user != "root":
        return Path(pwd.getpwnam(user).pw_dir)
    return Path.home()


def detect_ip() -> str:
    """기본 경로로 나가는 인터페이스의 IP (ens33 등)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))  # 실제로 패킷을 보내지 않음
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def fmt(dt: datetime) -> str:
    return dt.strftime(TS)


def parse(ts: str) -> datetime:
    return datetime.strptime(ts, TS)


def sleep_with_countdown(sec: int, label: str) -> None:
    end = time.time() + sec
    while True:
        left = int(end - time.time())
        if left <= 0:
            break
        print(f"\r    {label}: {left:4d}초 남음 ", end="", flush=True)
        time.sleep(min(5, left))
    print("\r" + " " * 60 + "\r", end="", flush=True)


# ----------------------------------------------------------------------
# DB
# ----------------------------------------------------------------------
def db_connect():
    try:
        import mysql.connector  # collector.py 와 같은 venv 에 설치되어 있음
    except ImportError:
        sys.exit("mysql-connector-python 이 없습니다. ~/ids-ai/venv/bin/python 으로 실행하세요.")
    password = os.environ.get("IDS_DB_PASSWORD")
    if password is None:
        password = getpass.getpass("DB 비밀번호 (IDS_DB_PASSWORD): ")
    return mysql.connector.connect(
        host=os.environ.get("IDS_DB_HOST", "localhost"),
        port=int(os.environ.get("IDS_DB_PORT", "3306")),
        user=os.environ.get("IDS_DB_USER", "ids_user"),
        password=password,
        database=os.environ.get("IDS_DB_NAME", "ids_db"),
        autocommit=True,
    )


def query(conn, sql: str, params: tuple = ()) -> list[tuple]:
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        cur.close()


# 구간 내 연결 + 연결별 최신 AI 판정 (ai_results 가 여러 줄이면 가장 최근 것)
SQL_FLOWS = """
SELECT f.flow_id, f.src_ip, f.dest_ip, f.dest_port, r.attack_type, r.analyzed_at
FROM flows f
JOIN ai_results r ON r.id = (SELECT MAX(r2.id) FROM ai_results r2 WHERE r2.flow_id = f.flow_id)
WHERE f.start_time BETWEEN %s AND %s
"""

# 구간과 겹치는 공격 묶음 (이전 공격에 이어 붙은 경우도 '탐지'로 인정)
SQL_EVENTS = """
SELECT id, attack_type, attack_subtype, src_ip, flow_count, first_seen, last_seen
FROM attack_events
WHERE first_seen <= %s AND last_seen >= %s
"""


def fetch_window(conn, w: Window, settle_sec: int):
    s = parse(w.start) - timedelta(seconds=WINDOW_MARGIN_SEC)
    e = parse(w.end) + timedelta(seconds=WINDOW_MARGIN_SEC)
    flows = query(conn, SQL_FLOWS, (fmt(s), fmt(e)))
    # 공격 묶음은 마감 지연을 고려해 settle 만큼 뒤까지 본다
    events = query(conn, SQL_EVENTS, (fmt(e + timedelta(seconds=settle_sec)), fmt(s)))
    return flows, events


# ----------------------------------------------------------------------
# 집계 (DB 와 분리 → 단위 시험 가능)
# ----------------------------------------------------------------------
def keep_flow(sc: Scenario, my_ip: str, src: str, dst: str, dport) -> bool:
    if sc.flow_filter == "self" and not (src == my_ip and dst == my_ip):
        return False
    if sc.flow_filter == "src" and src != my_ip:
        return False
    if sc.dest_port is not None and dport != sc.dest_port:
        return False
    return True


def analyze_run(sc: Scenario, w: Window, flows: list[tuple], events: list[tuple]) -> RunResult:
    r = RunResult(sc.key, w.rep, w.start, w.end, error=w.error)
    start = parse(w.start)
    first_attack_at: datetime | None = None

    for _fid, src, dst, dport, atype, analyzed_at in flows:
        if not keep_flow(sc, w.my_ip, src, dst, dport):
            continue
        atype = atype or "Normal"
        r.flows_total += 1
        r.type_counts[atype] = r.type_counts.get(atype, 0) + 1
        if atype != "Normal":
            r.flows_attack += 1
            if analyzed_at and (first_attack_at is None or analyzed_at < first_attack_at):
                first_attack_at = analyzed_at
        if sc.expected and atype == sc.expected:
            r.flows_expected += 1

    if first_attack_at is not None:
        r.detect_sec = round((first_attack_at - start).total_seconds(), 1)

    for eid, etype, esub, esrc, fcount, _fs, _ls in events:
        if sc.flow_filter in ("self", "src") and esrc != w.my_ip:
            continue
        r.incidents.append((eid, etype, esub, fcount))
        if sc.expected and etype == sc.expected:
            r.incident_detected = True
    return r


def pct(a: float, b: float) -> str:
    return f"{a / b * 100:.1f}%" if b else "-"


def summarize(sc: Scenario, runs: list[RunResult]) -> dict:
    n = len(runs)
    total = sum(x.flows_total for x in runs)
    if sc.expected is None:  # 정상 구간
        attack = sum(x.flows_attack for x in runs)
        minutes = sum((parse(x.end) - parse(x.start)).total_seconds() for x in runs) / 60
        incidents = [i for x in runs for i in x.incidents]
        by_type: dict[str, int] = {}
        for x in runs:
            for t, c in x.type_counts.items():
                if t != "Normal":
                    by_type[t] = by_type.get(t, 0) + c
        return {
            "scenario": sc.title, "kind": "normal", "minutes": round(minutes, 1), "flows": total,
            "fp_flows": attack, "fp_rate": pct(attack, total),
            "false_incidents": len(incidents),
            "false_incidents_per_hour": round(len(incidents) / (minutes / 60), 2) if minutes else 0,
            "fp_types": by_type,
        }
    detected = sum(1 for x in runs if x.incident_detected)
    expected = sum(x.flows_expected for x in runs)
    secs = [x.detect_sec for x in runs if x.detect_sec is not None]
    mis: dict[str, int] = {}
    for x in runs:
        for t, c in x.type_counts.items():
            if t != sc.expected:
                mis[t] = mis.get(t, 0) + c
    return {
        "scenario": sc.title, "kind": "attack", "expected": sc.expected, "reps": n,
        "incident_detect": f"{detected}/{n}", "incident_rate": pct(detected, n),
        "flows": total, "flows_expected": expected, "flow_rate": pct(expected, total),
        "detect_mean": round(statistics.mean(secs), 1) if secs else None,
        "detect_median": round(statistics.median(secs), 1) if secs else None,
        "detect_max": max(secs) if secs else None,
        "misclass": dict(sorted(mis.items(), key=lambda kv: -kv[1])),
    }


# ----------------------------------------------------------------------
# 시나리오 실행
# ----------------------------------------------------------------------
def make_wordlist(tmpdir: Path) -> Path:
    p = tmpdir / "pw200.txt"
    p.write_text("\n".join(f"wrongpass{i:03d}!" for i in range(200)) + "\n")
    return p


def run_scenario(sc: Scenario, rep: int, ctx: dict, normal_min: int) -> Window:
    """시나리오 1회 실행. 공격 도구의 출력은 logs/<시나리오>_<회차>.log 에 남긴다."""
    my_ip = ctx["ip"]
    start = datetime.now()
    rc, err = None, ""
    try:
        if sc.key == "normal":
            gen_normal_traffic(normal_min * 60)
            rc = 0
        elif sc.key == "c2beacon":
            for i in range(12):
                subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", "5", "https://example.com"], check=False)
                if i < 11:
                    time.sleep(10)
            rc = 0
        else:
            cmd = [c.format(ip=my_ip, subnet=ctx["subnet"], wordlist=ctx["wordlist"], user=ctx["user"]) for c in sc.cmd]
            log("    $ " + " ".join(cmd))
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            rc = p.returncode
            log_dir = ctx["out_dir"] / "logs"
            log_dir.mkdir(exist_ok=True)
            # hping3 --flood 는 출력이 짧고, hydra·nmap 출력은 실패 원인 확인에 필요하다
            (log_dir / f"{sc.key}_{rep}.log").write_text(
                f"$ {' '.join(cmd)}\nrc={rc}\n\n[stdout]\n{(p.stdout or '')[-20000:]}\n[stderr]\n{(p.stderr or '')[-5000:]}\n",
                encoding="utf-8")
            # timeout 은 시간이 다 되면 124 (정상), hydra 는 비밀번호를 못 찾으면 0 이 아닐 수 있음 → 오류로 보지 않음
            if rc not in (0, 124) and sc.key not in ("bruteforce_ssh",):
                tail = (p.stderr or "").strip().splitlines()
                err = tail[-1] if tail else f"rc={rc}"
    except Exception as e:  # noqa: BLE001
        err = str(e)
    end = datetime.now()
    return Window(sc.key, rep, fmt(start), fmt(end), my_ip, rc, err)


def gen_normal_traffic(seconds: int) -> None:
    """평소 사용 흉내: 무작위 간격으로 웹 접속 + DNS 조회."""
    end = time.time() + seconds
    n = 0
    while time.time() < end:
        if random.random() < 0.7:
            subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", "8", random.choice(NORMAL_URLS)], check=False)
        else:
            try:
                socket.getaddrinfo(random.choice(NORMAL_HOSTS), 443)
            except OSError:
                pass
        n += 1
        left = int(end - time.time())
        print(f"\r    정상 트래픽 생성 중: 요청 {n}회, {max(left, 0) // 60:2d}분 {max(left, 0) % 60:02d}초 남음 ", end="", flush=True)
        time.sleep(random.uniform(3, 15))
    print()


# ----------------------------------------------------------------------
# collector 관리
# ----------------------------------------------------------------------
def collector_running() -> bool:
    # 'python ... collector.py' 로 실행 중인 프로세스만 (nano collector.py 같은 편집기는 제외)
    p = subprocess.run(["pgrep", "-f", r"python[0-9.]* .*collector\.py"], stdout=subprocess.PIPE, text=True, check=False)
    own = str(os.getpid())
    return any(pid and pid != own for pid in p.stdout.split())


def start_collector(ai_dir: Path, out_dir: Path) -> subprocess.Popen | None:
    py = ai_dir / "venv" / "bin" / "python"
    script = ai_dir / "collector.py"
    if not script.exists():
        sys.exit(f"collector.py 를 찾을 수 없습니다: {script}  (--ai-dir 로 경로 지정)")
    logf = open(out_dir / "collector.log", "w")  # noqa: SIM115 - 실행 내내 열어 둠
    proc = subprocess.Popen([str(py), "-u", str(script)], stdout=logf, stderr=subprocess.STDOUT,
                            start_new_session=True)
    log(f"collector 시작 (pid {proc.pid}, 로그: {out_dir / 'collector.log'})")
    time.sleep(8)
    if proc.poll() is not None:
        sys.exit(f"collector 가 바로 종료되었습니다. 로그를 확인하세요: {out_dir / 'collector.log'}")
    return proc


def collector_backlog(eve_path: str = EVE_PATH) -> int | None:
    """
    collector 가 아직 읽지 않은 eve.json 바이트 수.
    실행 중인 collector 프로세스가 연 eve.json 의 읽기 위치(/proc/<pid>/fdinfo 의 pos)와
    파일 크기를 비교한다. 알 수 없으면 None.
    """
    p = subprocess.run(["pgrep", "-f", r"python[0-9.]* .*collector\.py"], stdout=subprocess.PIPE, text=True, check=False)
    try:
        size = os.path.getsize(eve_path)
    except OSError:
        return None
    for pid in p.stdout.split():
        fd_dir = Path(f"/proc/{pid}/fd")
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                if not os.readlink(fd).startswith(eve_path):
                    continue
                info = Path(f"/proc/{pid}/fdinfo/{fd.name}").read_text()
            except OSError:
                continue
            for line in info.splitlines():
                if line.startswith("pos:"):
                    return max(0, size - int(line.split()[1]))
    return None


def wait_for_drain(label: str) -> None:
    """collector 가 eve.json 을 다 따라잡을 때까지 기다린다 (밀린 채로 다음 시험·집계를 하지 않도록)."""
    start = time.time()
    first = collector_backlog()
    if first is None:
        log("    [주의] collector 처리 위치를 알 수 없어 따라잡기 확인을 건너뜁니다")
        return
    if first <= DRAIN_OK_BYTES:
        return
    log(f"    collector 가 밀려 있어 기다립니다 ({label}): 남은 기록 {first / 1e6:.1f}MB")
    while True:
        time.sleep(5)
        b = collector_backlog()
        if b is None or b <= DRAIN_OK_BYTES:
            print()
            log(f"    collector 따라잡음 ({int(time.time() - start)}초 대기)")
            return
        if time.time() - start > DRAIN_MAX_WAIT:
            print()
            log(f"    [주의] {DRAIN_MAX_WAIT // 60}분이 지나도 밀려 있습니다(남은 {b / 1e6:.1f}MB). 이후 결과에 누락이 있을 수 있습니다")
            return
        print(f"\r    남은 기록 {b / 1e6:7.2f}MB  ({int(time.time() - start)}초) ", end="", flush=True)


def collector_stats(log_path: Path) -> dict:
    """collector.log 의 5초 처리 현황([status] N flows/s) 에서 최대·평균 처리량을 뽑는다."""
    rates = []
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("[status]"):
                try:
                    rates.append(float(line.split()[1].replace(",", "")))
                except (IndexError, ValueError):
                    pass
    except OSError:
        pass
    busy = [r for r in rates if r >= 1]
    return {"collector_peak": max(rates) if rates else None,
            "collector_busy_avg": round(sum(busy) / len(busy), 1) if busy else None}


def model_versions(conn, start: str, end: str) -> dict:
    try:
        rows = query(conn, "SELECT model_version, COUNT(*) FROM ai_results WHERE analyzed_at BETWEEN %s AND %s "
                           "GROUP BY model_version", (start, end))
        return {str(v): int(n) for v, n in rows}
    except Exception:  # noqa: BLE001
        return {}


def stop_collector(proc: subprocess.Popen | None) -> None:
    if proc and proc.poll() is None:
        os.killpg(proc.pid, signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
        log("collector 종료")


# ----------------------------------------------------------------------
# 사전 점검
# ----------------------------------------------------------------------
def preflight(selected: list[Scenario], conn, args) -> list[Scenario]:
    if os.geteuid() != 0:
        sys.exit("root 권한이 필요합니다: sudo ~/ids-ai/venv/bin/python experiment.py")

    ok: list[Scenario] = []
    for sc in selected:
        missing = [t for t in sc.tools if shutil.which(t) is None]
        if missing:
            log(f"[건너뜀] {sc.title}: {', '.join(missing)} 없음 (sudo apt install {' '.join(missing)})")
            continue
        if sc.key == "bruteforce_ssh" and not port_open(args.ip or detect_ip(), 22):
            # Ubuntu 24.04 는 ssh.socket(소켓 활성화)이라 'systemctl is-active ssh' 가 inactive 여도
            # 22번 포트는 열려 있을 수 있음 → 서비스 상태 대신 실제 접속 가능 여부로 확인
            log("[건너뜀] SSH 무차별 대입: 22번 포트가 닫혀 있음 (sudo apt install -y openssh-server)")
            continue
        ok.append(sc)

    st = subprocess.run(["systemctl", "is-active", "suricata"], stdout=subprocess.PIPE, text=True, check=False)
    if st.stdout.strip() != "active":
        sys.exit("Suricata 가 실행 중이 아닙니다: sudo systemctl start suricata")

    # 시각 확인: 시험 구간은 VM 시각으로 기록하므로 DB 시각과 같아야 한다
    db_now = query(conn, "SELECT NOW()")[0][0]
    diff = abs((db_now - datetime.now()).total_seconds())
    if diff > 60:
        log(f"[주의] DB 시각과 VM 시각이 {diff:.0f}초 다릅니다. 집계 구간이 어긋날 수 있습니다 (DB 시간대 확인).")
    else:
        log(f"시각 확인: DB 와 VM 차이 {diff:.0f}초")
    return ok


# ----------------------------------------------------------------------
# 출력
# ----------------------------------------------------------------------
def render_markdown(summaries: list[dict], meta: dict) -> str:
    lines = [
        "# 실트래픽 탐지 성능 측정 결과", "",
        f"- 측정 일시: {meta['started']} ~ {meta['finished']}",
        f"- 환경: VM 1대 자체 공격 (IP {meta['ip']}), Suricata + collector.py 실시간 분석",
        f"- 반복: 공격 시나리오별 {meta['reps']}회, 시험 간 대기 {meta['cooldown']}초",
        f"- AI 모델 버전(판정 연결 수): {', '.join(f'{k} {v}' for k, v in (meta.get('model_versions') or {}).items()) or '-'}",
        (f"- collector 처리량: 최대 {meta['collector_peak']:,.0f} flows/s, 처리 중 평균 {meta['collector_busy_avg']:,.0f} flows/s (5초 단위)"
         if meta.get("collector_peak") else "- collector 처리량: 기록 없음 (collector 를 직접 실행한 경우)"),
        "", "## 공격 시나리오", "",
        "| 시나리오 | 기대 유형 | 반복 | 공격 단위 탐지 | 연결 단위 정분류율 | 탐지 시간 (중앙값 / 최대) | 주요 오분류 (연결 수) |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for s in summaries:
        if s["kind"] != "attack":
            continue
        mis = ", ".join(f"{k} {v}" for k, v in list(s["misclass"].items())[:3]) or "-"
        det = f"{s['detect_median']}초 / {s['detect_max']}초" if s["detect_median"] is not None else "미탐지"
        if s["flows"] == 0:
            det = "측정 실패 (해당 연결 0개 → logs/ 확인)"
        lines.append(
            f"| {s['scenario']} | {s['expected']} | {s['reps']} | {s['incident_detect']} ({s['incident_rate']}) "
            f"| {s['flow_rate']} ({s['flows_expected']}/{s['flows']}) | {det} | {mis} |"
        )
    normals = [s for s in summaries if s["kind"] == "normal"]
    if normals:
        lines += ["", "## 정상 트래픽 (오탐)", "",
                  "| 구간 | 연결 수 | 공격 오판정 연결 | 연결 단위 오탐률 | 잘못 생성된 경보 | 시간당 오경보 | 오판정 유형 |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        for s in normals:
            types = ", ".join(f"{k} {v}" for k, v in s["fp_types"].items()) or "-"
            lines.append(f"| {s['minutes']}분 | {s['flows']} | {s['fp_flows']} | {s['fp_rate']} | "
                         f"{s['false_incidents']}건 | {s['false_incidents_per_hour']}건 | {types} |")
    lines += [
        "", "## 지표 정의", "",
        "- 공격 단위 탐지: 시험 1회 동안 기대 유형의 공격 묶음(attack_events)이 생성·갱신되면 탐지 성공",
        "- 연결 단위 정분류율: 시험 구간의 공격 연결(출발지·목적지·포트로 배경 트래픽 제외) 중 기대 유형으로 판정된 비율",
        "- 탐지 시간: 공격 명령 실행 시각 → 첫 AI 공격 판정(ai_results.analyzed_at)까지. Suricata flow-timeout 대기가 대부분을 차지",
        "- 연결 단위 오탐률: 정상 구간에서 내 IP 가 만든 연결 중 Normal 이 아닌 유형으로 판정된 비율",
    ]
    return "\n".join(lines) + "\n"


def print_console(summaries: list[dict]) -> None:
    print("\n" + "=" * 78)
    print(" 측정 결과")
    print("=" * 78)
    for s in summaries:
        if s["kind"] == "attack":
            det = f"중앙값 {s['detect_median']}초, 최대 {s['detect_max']}초" if s["detect_median"] is not None else "미탐지"
            print(f"\n■ {s['scenario']}  (기대: {s['expected']})")
            if s["flows"] == 0:
                print("   ※ 해당 연결이 0개입니다. 탐지 실패가 아니라 측정 실패이므로 logs/ 의 도구 출력을 확인하세요.")
            print(f"   공격 단위 탐지   : {s['incident_detect']}  ({s['incident_rate']})")
            print(f"   연결 단위 정분류 : {s['flow_rate']}  ({s['flows_expected']}/{s['flows']})")
            print(f"   탐지 시간       : {det}")
            if s["misclass"]:
                print(f"   오분류          : {s['misclass']}")
        else:
            print(f"\n■ 정상 사용 {s['minutes']}분")
            print(f"   연결 단위 오탐률 : {s['fp_rate']}  ({s['fp_flows']}/{s['flows']})")
            print(f"   잘못 생긴 경보   : {s['false_incidents']}건 (시간당 {s['false_incidents_per_hour']}건)")
            if s["fp_types"]:
                print(f"   오판정 유형      : {s['fp_types']}")
    print()


def save_results(out_dir: Path, windows: list[Window], results: list[RunResult], summaries: list[dict], meta: dict) -> None:
    (out_dir / "windows.json").write_text(
        json.dumps({"meta": meta, "windows": [asdict(w) for w in windows]}, ensure_ascii=False, indent=2))
    with open(out_dir / "runs.csv", "w", newline="", encoding="utf-8-sig") as f:
        wr = csv.writer(f)
        wr.writerow(["scenario", "rep", "start", "end", "flows_total", "flows_expected", "flows_attack",
                     "incident_detected", "detect_sec", "type_counts", "incidents", "error"])
        for r in results:
            wr.writerow([r.scenario, r.rep, r.start, r.end, r.flows_total, r.flows_expected, r.flows_attack,
                         int(r.incident_detected), r.detect_sec if r.detect_sec is not None else "",
                         json.dumps(r.type_counts, ensure_ascii=False),
                         json.dumps(r.incidents, ensure_ascii=False, default=str), r.error])
    (out_dir / "summary.md").write_text(render_markdown(summaries, meta), encoding="utf-8")
    owner = os.environ.get("SUDO_USER")
    if owner and owner != "root":  # sudo 로 만든 파일을 원래 사용자 소유로
        uid, gid = pwd.getpwnam(owner).pw_uid, pwd.getpwnam(owner).pw_gid
        for p in [out_dir, *out_dir.rglob("*")]:
            os.chown(p, uid, gid)
    log(f"결과 저장: {out_dir}/summary.md, runs.csv, windows.json")


def analyze_all(conn, windows: list[Window], settle: int) -> tuple[list[RunResult], list[dict]]:
    results: list[RunResult] = []
    for w in windows:
        flows, events = fetch_window(conn, w, settle)
        results.append(analyze_run(SCENARIOS[w.scenario], w, flows, events))
    summaries = []
    for key in dict.fromkeys(w.scenario for w in windows):  # 실행 순서 유지
        summaries.append(summarize(SCENARIOS[key], [r for r in results if r.scenario == key]))
    return results, summaries


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="관제탑 실트래픽 탐지 성능 측정")
    ap.add_argument("--scenarios", help="쉼표로 구분 (기본: default_on 시나리오 전부). --list 로 목록 확인")
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS, help=f"공격 시나리오 반복 횟수 (기본 {DEFAULT_REPS})")
    ap.add_argument("--normal-min", type=int, default=DEFAULT_NORMAL_MIN, help=f"정상 구간 길이(분) (기본 {DEFAULT_NORMAL_MIN})")
    ap.add_argument("--cooldown", type=int, default=DEFAULT_COOLDOWN, help=f"시험 사이 대기(초) (기본 {DEFAULT_COOLDOWN})")
    ap.add_argument("--settle", type=int, default=DEFAULT_SETTLE, help=f"집계 전 대기(초) (기본 {DEFAULT_SETTLE})")
    ap.add_argument("--ip", help="공격 대상(내) IP (기본: 자동 감지)")
    ap.add_argument("--ssh-user", default="idstest_nouser", help="hydra 로그인 시도 계정 (존재하지 않는 계정 권장)")
    ap.add_argument("--ai-dir", help="ids-ai 폴더 (기본: ~/ids-ai)")
    ap.add_argument("--collector", choices=["auto", "skip"], default="auto",
                    help="auto: 꺼져 있으면 시작하고 끝나면 종료 / skip: 직접 관리")
    ap.add_argument("--analyze", metavar="WINDOWS_JSON", help="측정 없이 저장된 구간을 다시 집계")
    ap.add_argument("--dry-run", action="store_true", help="계획만 출력")
    ap.add_argument("--list", action="store_true", help="시나리오 목록")
    args = ap.parse_args()

    if args.list:
        for s in SCENARIOS.values():
            print(f"{s.key:18s} {'(기본)' if s.default_on else '(선택)':6s} {s.title}  → {s.expected or 'Normal'}"
                  + (f"\n{'':26s}※ {s.note}" if s.note else ""))
        return

    ai_dir = Path(args.ai_dir) if args.ai_dir else real_home() / "ids-ai"

    # ---- 재집계 모드 ----
    if args.analyze:
        data = json.loads(Path(args.analyze).read_text())
        windows = [Window(**w) for w in data["windows"]]
        conn = db_connect()
        results, summaries = analyze_all(conn, windows, args.settle)
        meta = data["meta"]
        print_console(summaries)
        out_dir = Path(args.analyze).parent
        save_results(out_dir, windows, results, summaries, meta)
        return

    # ---- 시나리오 선택 ----
    if args.scenarios:
        keys = [k.strip() for k in args.scenarios.split(",") if k.strip()]
        unknown = [k for k in keys if k not in SCENARIOS]
        if unknown:
            sys.exit(f"알 수 없는 시나리오: {unknown}. --list 로 확인")
        selected = [SCENARIOS[k] for k in keys]
    else:
        selected = [s for s in SCENARIOS.values() if s.default_on]
    # 실행 순서: 다른 공격 → 정상 구간 → SYN Flood(맨 마지막)
    #  - 정상 구간은 공격 직후 남은 연결이 섞이지 않도록 공격 뒤에
    #  - SYN Flood 는 연결 기록이 가장 많아 collector 처리가 밀리기 쉬우므로 맨 마지막
    #    (1차 측정: --flood 뒤 collector 가 몇 시간 밀려 직후 hydra 연결이 분석되지 않음)
    selected.sort(key=lambda s: (s.key == "synflood", s.key == "normal"))

    my_ip = args.ip or detect_ip()
    subnet = ".".join(my_ip.split(".")[:3]) + ".0/24"
    attack_count = sum(1 for s in selected if s.expected)
    est_min = (attack_count * args.reps * (args.cooldown + 40) + (args.normal_min * 60 if any(s.key == "normal" for s in selected) else 0)
               + args.settle) / 60

    print(f"대상 IP: {my_ip}   반복: {args.reps}회   시험 간 대기: {args.cooldown}초   예상 소요: 약 {est_min:.0f}분")
    for s in selected:
        reps = 1 if s.expected is None else args.reps
        print(f"  - {s.title:40s} → {s.expected or 'Normal'}  × {reps}" + (f"   ※ {s.note}" if s.note else ""))
    if args.dry_run:
        return

    conn = db_connect()
    selected = preflight(selected, conn, args)
    if not selected:
        sys.exit("실행할 시나리오가 없습니다.")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ai_dir / "experiments" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="ids-exp-"))
    ctx = {"ip": my_ip, "subnet": subnet, "wordlist": str(make_wordlist(tmp)), "user": args.ssh_user, "out_dir": out_dir}

    collector_proc = None
    if args.collector == "auto":
        if collector_running():
            log("collector 가 이미 실행 중 → 그대로 사용 (끝나도 종료하지 않음)")
        else:
            collector_proc = start_collector(ai_dir, out_dir)
    # collector 가 멈췄던 곳부터 이어 읽는 경우(11.09 개선) 밀린 기록을 먼저 처리하게 한다
    wait_for_drain("첫 시험 전")

    meta = {"started": fmt(datetime.now()), "finished": "", "ip": my_ip, "reps": args.reps,
            "cooldown": args.cooldown, "normal_min": args.normal_min}
    windows: list[Window] = []
    try:
        plan = [(s, rep) for s in selected for rep in range(1, (1 if s.expected is None else args.reps) + 1)]
        for i, (sc, rep) in enumerate(plan, 1):
            log(f"({i}/{len(plan)}) {sc.title} — {rep}회차")
            w = run_scenario(sc, rep, ctx, args.normal_min)
            windows.append(w)
            if w.error:
                log(f"    [오류] {w.error}")
            if i < len(plan):
                sleep_with_countdown(args.cooldown, "다음 시험까지 대기 (연결 마감·공격 묶음 분리)")
                wait_for_drain("다음 시험 전")
        log(f"마지막 연결이 DB 에 들어올 때까지 {args.settle}초 대기")
        sleep_with_countdown(args.settle, "집계 대기")
        wait_for_drain("집계 전")
    except KeyboardInterrupt:
        log("중단됨 → 지금까지의 구간만 집계합니다")
    finally:
        meta["finished"] = fmt(datetime.now())
        stop_collector(collector_proc)
        meta.update(collector_stats(out_dir / "collector.log"))
        meta["model_versions"] = model_versions(conn, meta["started"], meta["finished"])
        shutil.rmtree(tmp, ignore_errors=True)

    if not windows:
        return
    results, summaries = analyze_all(conn, windows, args.settle)
    print_console(summaries)
    save_results(out_dir, windows, results, summaries, meta)
    conn.close()


if __name__ == "__main__":
    main()

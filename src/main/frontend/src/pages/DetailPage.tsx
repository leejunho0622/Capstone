import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { DetailContent } from "../components/detail/DetailDrawer";

/* =========================================================
   경보·플로우 단독 페이지 (/incidents/:id, /flows/:id)
   - 상세 패널의 '새 탭' 링크로 열림. 주소를 공유하거나 발표 화면에 띄우는 용도
   - 본문은 상세 패널과 같은 컴포넌트를 넓은 배치(2단)로 사용
   ========================================================= */

export default function DetailPage({ kind }: { kind: "incident" | "flow" }) {
  const { id = "" } = useParams();
  const isIncident = kind === "incident";

  return (
    <div className="mx-auto max-w-[1280px] p-4 lg:p-5">
      <div className="panel mb-5 flex flex-wrap items-center gap-3 p-3">
        <Link to={isIncident ? "/alerts" : "/traffic"} className="btn h-8 gap-1.5 px-2.5 text-xs">
          <ArrowLeft size={14} /> {isIncident ? "경보 처리" : "트래픽 분석"}
        </Link>
        <div className="min-w-0">
          <p className="text-[11px] text-muted">{isIncident ? "경보 상세 (공격 단위)" : "플로우 상세 (연결 단위)"}</p>
          <p className="font-mono text-base font-semibold">{isIncident ? `Incident #${id}` : `Flow #${id}`}</p>
        </div>
      </div>
      {/* 상세 패널과 같은 흰 바탕 위에 표시 (섹션 상자·요약 수치 칸이 바탕색에 묻히지 않도록) */}
      <div className="panel overflow-hidden">
        <DetailContent kind={kind} id={id} />
      </div>
    </div>
  );
}

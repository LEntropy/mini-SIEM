"""Korean HTML report / dashboard for LogSentry (pure standard library)."""
from __future__ import annotations

import datetime
import html
from collections import Counter

from core import SEVERITY_RANK, sort_alerts

SEV_KO = {"critical": "긴급", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
SEV_COLOR = {"critical": "#b3123b", "high": "#d9480f", "medium": "#c08a00",
             "low": "#1c7ed6", "info": "#5c7080"}
SRC_KO = {"apache": "웹(Apache)", "auth": "인증(SSH)", "nac": "NAC", "pms": "PMS"}


def _esc(s):
    return html.escape(str(s), quote=True)


def build_report(alerts, actions=None, events=None, target="(미지정)") -> str:
    alerts = sort_alerts(list(alerts))
    actions = actions or []
    events = events or []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    sev_counts = Counter(a.severity for a in alerts)
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLOR[s]}">'
        f'<div class="num">{sev_counts.get(s,0)}</div><div class="lbl">{SEV_KO[s]} ({s})</div></div>'
        for s in ["critical", "high", "medium", "low", "info"])

    # source summary
    src_counts = Counter(e.source for e in events)
    src_rows = "".join(
        f"<tr><td>{SRC_KO.get(s,s)}</td><td>{n}</td></tr>" for s, n in src_counts.items())

    # top hostile IPs
    ip_counts = Counter(a.src_ip for a in alerts if a.src_ip)
    top_rows = "".join(
        f"<tr><td class='mono'>{_esc(ip)}</td><td>{n}</td></tr>"
        for ip, n in ip_counts.most_common(5))

    # response actions
    if actions:
        act_rows = "".join(
            f"<tr><td>{_esc(a.kind)}</td><td class='mono'>{_esc(a.target)}</td>"
            f"<td>{_esc(a.reason)}</td><td><b>{_esc(a.status)}</b></td></tr>" for a in actions)
        act_html = (f"<h2 class='sec'>대응 조치 ({len(actions)})</h2>"
                    "<table class='grid'><tr><th>조치</th><th>대상</th><th>사유</th><th>상태</th></tr>"
                    f"{act_rows}</table>")
    else:
        act_html = ""

    rows = []
    for i, a in enumerate(alerts, 1):
        enr = ""
        if a.enrichment:
            chips = []
            if a.enrichment.get("device_managed") is False:
                chips.append("<span class='chip bad'>NAC: 미관리 디바이스</span>")
            if a.enrichment.get("asset_patched") is False:
                miss = ", ".join(a.enrichment.get("missing_patches", []))
                chips.append(f"<span class='chip bad'>PMS: 미패치 ({_esc(miss)})</span>")
            if a.enrichment.get("http_status") == 200:
                chips.append("<span class='chip'>HTTP 200 (성공 가능)</span>")
            enr = "<div class='chips'>" + "".join(chips) + "</div>"
        resp = ""
        if a.responses:
            resp = "<div class='resp'><b>권고 대응</b><ul>" + \
                   "".join(f"<li>{_esc(r)}</li>" for r in a.responses) + "</ul></div>"
        rows.append(f"""
        <section class="alert">
          <h3><span class="badge" style="background:{SEV_COLOR[a.severity]}">{SEV_KO[a.severity]} · {a.severity.upper()}</span>
              {i}. {_esc(a.category)} <small>({_esc(a.technique)})</small></h3>
          <p class="msg">{_esc(a.message)}</p>
          <table class="meta"><tr><th>규칙</th><td>{_esc(a.rule_id)}</td>
             <th>출발지</th><td class="mono">{_esc(a.src_ip) or '-'}</td>
             <th>대상</th><td class="mono">{_esc(a.host) or '-'}</td></tr>
             <tr><th>시각</th><td>{_esc(a.when) or '-'}</td>
             <th>근거</th><td colspan="3" class="mono">{_esc(a.evidence)}</td></tr></table>
          {enr}{resp}
          <div class="fix"><b>조치 권고</b> {_esc(a.recommendation)}</div>
        </section>""")

    total = len(alerts)
    ch = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    verdict = ("긴급·높음 경보가 발생했습니다. 상관분석 결과 미관리 디바이스/미패치 자산과 연계된 "
               "공격이 포함되어 즉시 대응(격리·패치)이 필요합니다." if ch else
               ("중간 이하 위주로, 지속 모니터링을 권고합니다." if total else "유효한 위협이 탐지되지 않았습니다."))

    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogSentry 위협 탐지 리포트</title>
<style>
 :root{{color-scheme:light}}
 body{{font-family:-apple-system,"Segoe UI",Roboto,"Noto Sans KR",sans-serif;margin:0;background:#f4f5f7;color:#1a1d21;line-height:1.6}}
 .wrap{{max-width:960px;margin:0 auto;padding:24px 16px 64px}}
 header.top{{background:#0b1b34;color:#fff;padding:26px 24px;border-radius:12px}}
 header.top h1{{margin:0 0 6px;font-size:1.45rem}} header.top .m{{opacity:.85;font-size:.9rem}}
 .cards{{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}}
 .card{{flex:1 1 110px;background:#fff;border-radius:10px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .card .num{{font-size:1.8rem;font-weight:700}} .card .lbl{{font-size:.78rem;color:#5c7080}}
 .verdict{{background:#fff;border-left:5px solid #0b1b34;padding:14px 18px;border-radius:8px;margin-bottom:18px}}
 .two{{display:flex;gap:14px;flex-wrap:wrap}} .two>div{{flex:1 1 260px}}
 h2.sec{{border-bottom:2px solid #dfe3e8;padding-bottom:6px;margin-top:30px}}
 table.grid{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;font-size:.86rem}}
 table.grid th,table.grid td{{text-align:left;padding:7px 10px;border-bottom:1px solid #eef1f4}}
 table.grid th{{background:#f0f3f7;color:#333}}
 .alert{{background:#fff;border-radius:10px;padding:14px 16px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
 .alert h3{{font-size:1.02rem;margin:0 0 6px}} .alert .msg{{margin:.2rem 0 .5rem}}
 .badge{{color:#fff;font-size:.72rem;padding:2px 8px;border-radius:20px;margin-right:8px}}
 table.meta{{width:100%;border-collapse:collapse;font-size:.84rem;margin:4px 0}}
 table.meta th{{text-align:left;color:#5c7080;width:56px;padding:2px 8px;font-weight:600;vertical-align:top}}
 table.meta td{{padding:2px 8px}}
 .mono{{font-family:ui-monospace,Consolas,monospace;word-break:break-all}}
 .chips{{margin:6px 0}} .chip{{display:inline-block;background:#eef2f7;border-radius:14px;padding:2px 10px;font-size:.76rem;margin:2px 4px 2px 0}}
 .chip.bad{{background:#ffe3e3;color:#b3123b}}
 .resp{{background:#fff7e6;border-radius:8px;padding:6px 12px;margin:6px 0;font-size:.86rem}} .resp ul{{margin:4px 0 0 18px}}
 .fix{{background:#eef6ff;border-radius:8px;padding:7px 12px;margin-top:6px;font-size:.86rem}}
 footer{{color:#5c7080;font-size:.8rem;margin-top:28px;text-align:center}}
</style></head><body><div class="wrap">
 <header class="top"><h1>LogSentry · 로그 기반 위협 탐지 리포트</h1>
  <div class="m">대상: {_esc(target)} &nbsp;·&nbsp; 생성: {now} &nbsp;·&nbsp; 수집 이벤트 {len(events)}건</div>
  <div class="m">멀티소스(웹·인증·NAC·PMS) 상관분석 + 자동 대응(NAC 격리 / PMS 패치)</div></header>
 <div class="cards">{cards}</div>
 <div class="verdict"><b>종합.</b> 경보 {total}건. {verdict}</div>
 <div class="two">
   <div><h2 class="sec">수집 소스</h2><table class="grid"><tr><th>소스</th><th>이벤트</th></tr>{src_rows or '<tr><td>-</td><td>0</td></tr>'}</table></div>
   <div><h2 class="sec">주요 공격 출발지</h2><table class="grid"><tr><th>IP</th><th>경보수</th></tr>{top_rows or '<tr><td>-</td><td>0</td></tr>'}</table></div>
 </div>
 {act_html}
 <h2 class="sec">탐지 경보 ({total})</h2>
 {''.join(rows) if rows else '<p>탐지된 위협이 없습니다.</p>'}
 <footer>Generated by LogSentry · 인가된 보안 모니터링 결과</footer>
</div></body></html>"""


def write_report(alerts, path, actions=None, events=None, target="(미지정)"):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_report(alerts, actions=actions, events=events, target=target))
    return path

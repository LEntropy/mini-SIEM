# LogSentry

**로그 기반 위협 탐지 엔진 (mini-SIEM) — 멀티소스 상관분석 + 자동 대응**

웹·인증·**NAC**·**PMS** 로그를 한곳에서 수집·정규화하고, **소스를 교차 상관분석**해 위협을 탐지합니다. 단순 시그니처 매칭을 넘어 "미관리 디바이스가 미패치 자산을 공격" 같은 **맥락**을 잡아내고, **NAC 격리 / PMS 패치**까지 자동으로 도출·실행합니다.

> 공격 재현(discord 랩) → 취약점 진단(websec-assessor) → **탐지·상관·대응(LogSentry)** 으로 이어지는 블루팀 축을 담당하는 프로젝트입니다. 공군 정보보호병(CERT) 경험의 "로그 모니터링·침해대응"을 코드로 구현했습니다.

---

## 핵심 차별점 — 교차 소스 상관분석

| 상관 규칙 | 결합 소스 | 결과 |
|---|---|---|
| **미관리 디바이스 공격** | NAC(`managed=false`) + 웹 공격 로그 | 위험도 상향 + **NAC 격리** 권고/실행 |
| **미패치 자산 대상 공격** | PMS(`patched=false`) + 웹 공격 로그 | **긴급** 격상 + **PMS 패치** 요청 |
| **성공 가능성 판정** | 공격 시그니처 + HTTP 200 | "성공 가능" 태그, 우선순위 ↑ |
| **무차별 대입(brute-force)** | 인증 로그(sshd) | 임계 초과 시 경보 (+NAC 연계) |
| **스캐닝/정찰** | 4xx 폭주 · 스캐너 User-Agent | 정찰 경보 |

## 구성

```
sources.py      멀티소스 파서 → 정규화 Event (apache access/error, sshd auth, NAC/PMS JSONL)
detect.py       시그니처 탐지(SQLi·XSS·LFI·웹셸·민감파일·스캐너) + 교차소스 상관분석
integrations.py NAC/PMS 커넥터 — Mock(오프라인) + HTTP 어댑터(실서비스 연결)
respond.py      대응 엔진(SOAR) — 기본 dry-run, --respond 시 실제 격리/패치
report.py       통합 한글 리포트/대시보드
sentry.py       CLI
samples/        멀티소스 샘플 로그(공격/정상)
tests/          자동 테스트 (외부 서비스 불필요)
```

## 사용법

```bash
# 멀티소스 분석 + 리포트 (대응은 계획만, 안전)
python sentry.py analyze \
    --access samples/access.log --host web01 \
    --auth samples/auth.log --nac samples/nac.log --pms samples/pms.log \
    --out report.html

# 실제 대응 실행(NAC 격리 / PMS 패치) — 실서비스 엔드포인트 지정
python sentry.py analyze --access /var/log/apache2/access.log --host web01 \
    --nac samples/nac.log --pms samples/pms.log \
    --respond --nac-url http://nac.internal:8080 --pms-url http://pms.internal:9090

# 한 줄 데모(샘플 로그로 리포트 생성)
python demo.py
```

## NAC / PMS 연동 계약 (HTTP 어댑터)

실제 NAC(`NAC-dev`)·PMS(`pms-dev`) 앞단에 얇은 shipper를 두고 아래 REST를 맞추면 그대로 연동됩니다. 로그 수집은 JSON lines 포맷을 따릅니다(아래 예시).

```
NAC  GET  /device?ip=<ip>     -> {"ip":..,"managed":bool}
     POST /quarantine         <- {"ip":..,"reason":..}  -> {"ok":bool}
PMS  GET  /asset?host=<host>  -> {"host":..,"patched":bool,"missing":[..]}
     POST /patch-jobs         <- {"host":..,"reason":..} -> {"ok":bool}
```

```jsonc
// NAC 로그(JSONL)
{"ts":"...","event":"access_deny","device_id":"..","ip":"203.0.113.9","managed":false,"reason":"unknown_device"}
// PMS 로그(JSONL)
{"ts":"...","event":"inventory","asset_id":"..","host":"web01","patched":false,"missing":["CVE-2024-1234"]}
```

## 테스트

```bash
python tests/test_sources.py   # 멀티소스 파서
python tests/test_detect.py    # 시그니처 + 교차소스 상관분석(정상 로그 무탐지 포함)
python tests/test_respond.py   # 대응 엔진(계획/실행, mock 커넥터)
python tests/test_report.py    # 리포트 생성
# 또는
python -m pytest -q
```

## 안전장치
- 대응은 **기본 dry-run(계획만)**. 실제 격리/패치는 `--respond` + 실엔드포인트에서만 동작합니다.
- 전 과정 **순수 표준 라이브러리**, 외부 서비스 없이 테스트/데모 가능.
- 인가된 환경에서만 사용하십시오.

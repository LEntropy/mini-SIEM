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
| **미끼 접촉** | [LureTrace](https://github.com/LEntropy/LureTrace) 활동 기록 | 자격 증명 시도나 공격 기법이 있으면 높음 + **NAC 격리** 계획 |
| **미끼 접촉 후 실서버 활동** | LureTrace + 인증·웹 로그 | 실서버 로그인 시 **긴급**, 기존 경보 위험도 상향 |

## 구성

```
sources.py      멀티소스 파서 → 정규화 Event (apache access/error, sshd auth, NAC/PMS/LureTrace JSONL)
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

## LureTrace 연동

사람이 쓸 이유가 없는 미끼에 접촉한 출발지는 그 자체로 신뢰도 높은 공격 신호입니다. LureTrace가 내보낸 기록을 함께 분석하면, 같은 출발지가 실제 서버에서 한 행동의 위험도를 다시 판단합니다.

```bash
# LureTrace가 실행 중일 때 기록을 받아 함께 분석
curl -o luretrace-events.jsonl http://127.0.0.1:8088/api/v1/export/events.jsonl
python sentry.py analyze --access access.log --host web01 --auth auth.log \
    --luretrace luretrace-events.jsonl --out report.html

# 사내 취약점 스캐너처럼 미끼에 닿아도 되는 출발지는 제외
python sentry.py analyze --luretrace luretrace-events.jsonl --trusted-ip 10.0.0.50
```

| 규칙 | 조건 | 위험도 |
|---|---|---|
| `DECOY-CONTACT-001` | 미끼에 접속만 함 | 중간 |
| `DECOY-CONTACT-001` | 미끼에 자격 증명을 넣거나 공격 기법을 사용 | 높음 |
| `DECOY-PIVOT-001` | 미끼에 접촉한 출발지가 실서버 로그에도 있음 | 높음 |
| `DECOY-AUTH-001` | 미끼에 접촉한 출발지가 실서버 로그인에 성공 | 긴급 |

- 미끼 기록은 실서버 트래픽으로 세지 않습니다. 미끼에 몰린 요청이 웹 스캔이나 SSH 무차별 대입 경보를 만들지 않습니다.
- 격리는 다른 대응과 같이 기본값이 계획만(dry-run)입니다. 정상 스캐너가 격리되지 않도록 `--trusted-ip`로 제외하세요.
- syslog 시각에는 연도와 시간대가 없어 **행동 순서는 판단하지 않습니다.** 같은 로그 묶음에 함께 나타났다는 뜻입니다.
- LureTrace 내보내기에는 비밀번호 원문과 요청 전문이 없고, 지문(HMAC)만 있습니다.

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

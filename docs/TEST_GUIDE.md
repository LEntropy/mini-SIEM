# LogSentry 입문 테스트 가이드

처음 보는 사람도 그대로 따라 하면 **멀티소스 로그를 분석하고, 상관분석 경보를 보고, 리포트를 만들고, 대응 동작을 확인**할 수 있도록 단계별로 설명합니다.

---

## 0. 준비물
- **Python 3.8 이상** (표준 라이브러리만 사용 — 설치할 패키지 없음)
- NAC·PMS 실서비스나 DB는 **필요 없습니다.** 샘플 로그와 오프라인 목(mock) 커넥터로 전부 동작합니다.

```bash
python --version
```

---

## 1. 테스트 실행

```bash
python tests/test_sources.py   # 로그 파서 (웹/인증/NAC/PMS)
python tests/test_detect.py    # 탐지 + 교차소스 상관분석
python tests/test_respond.py   # 대응 엔진 (계획/실행)
python tests/test_report.py    # 리포트 생성
```
각 파일은 마지막에 `ALL PASS` 를 출력합니다. Windows는 `./run_tests.ps1` 로 한 번에 실행됩니다.

> **무엇을 검증하나요?** ① 각 소스 로그가 공통 형식(Event)으로 정규화되는지, ② 공격 로그에서 모든 위협 범주가 탐지되고 **정상 로그에서는 긴급/높음이 0건**인지, ③ 미관리 디바이스(NAC)·미패치 자산(PMS) 상관분석이 위험도를 올리고 대응을 도출하는지, ④ 대응이 기본 계획(dry-run)이며 `--respond` 에서만 실제 호출되는지.

---

## 2. 데모 리포트 만들기

```bash
python demo.py
```
출력 예:
```
report: docs/sample_report.html | events: 44 | alerts: {'critical': 6, 'high': 1, 'medium': 9} | planned actions: 2
```
`docs/sample_report.html` 을 브라우저로 열면 수집 소스 요약, 주요 공격 출발지, **대응 조치(NAC 격리/PMS 패치)**, 심각도별 경보(상관분석 태그 포함)를 볼 수 있습니다.

---

## 3. 직접 분석해 보기

### 3-1. 멀티소스 분석 (대응은 계획만 — 안전)
```bash
python sentry.py analyze \
    --access samples/access.log --host web01 \
    --auth samples/auth.log --nac samples/nac.log --pms samples/pms.log \
    --out report.html
```
요약과 함께 긴급/높음 경보가 출력됩니다. `203.0.113.9`(NAC 미관리) 가 `web01`(PMS 미패치) 를 공격한 건이 **긴급**으로 올라오는지 확인하세요.

### 3-2. 상관분석 효과 비교
NAC·PMS 로그를 빼고 돌려 보면(아래), 같은 웹 공격이라도 위험도·대응 권고가 달라집니다 — 상관분석의 효과를 눈으로 확인할 수 있습니다.
```bash
python sentry.py analyze --access samples/access.log --host web01 --auth samples/auth.log
```

### 3-3. 실제 대응 실행 (주의)
```bash
# 오프라인 목으로 실행 흐름 확인
python sentry.py analyze --access samples/access.log --host web01 \
    --nac samples/nac.log --pms samples/pms.log --respond

# 실서비스 연동 (실제 격리/패치가 일어남)
python sentry.py analyze --access /var/log/apache2/access.log --host web01 \
    --nac nac.log --pms pms.log --respond \
    --nac-url http://nac.internal:8080 --pms-url http://pms.internal:9090
```

---

## 4. 모듈 구조

| 파일 | 역할 |
|---|---|
| `sources.py` | 웹/인증/NAC/PMS 로그를 공통 `Event` 로 파싱 |
| `detect.py` | 시그니처 탐지 + 교차소스 상관분석 |
| `integrations.py` | NAC/PMS 커넥터(Mock/HTTP) |
| `respond.py` | 대응 엔진(격리/패치, 기본 dry-run) |
| `report.py` | 한글 리포트/대시보드 |
| `sentry.py` | CLI |

---

## 5. 테스트 중 발견한 문제와 개선 방향

- **문제 1 — 상관분석 과대경보.** 초기에는 PMS 미패치 자산에 대한 *실패한 404 스캔*까지 긴급으로 올렸습니다. → 긴급 격상을 **실제 공격 범주(SQLi/RCE/LFI) 또는 HTTP 200 성공** 건으로 한정하고, 정찰/404 노이즈는 중간으로 유지하도록 보정했습니다.
- **문제 2 — 외부 서비스 의존.** NAC/PMS 실연동 없이 테스트가 어려웠습니다. → 커넥터를 인터페이스로 분리하고 오프라인 **Mock 구현**을 두어, 외부 서비스 없이 탐지·상관·대응 전 과정을 결정적으로 테스트하도록 했습니다.
- **문제 3 — 대응의 안전성.** 자동 격리/패치는 위험할 수 있습니다. → **기본 dry-run(계획만)** 으로 두고, `--respond` 와 실엔드포인트가 모두 있을 때만 실제 동작하도록 했습니다.

---

## 6. 주의
인가된 환경에서만 사용하세요. 자동 대응(`--respond`)은 실제 네트워크 격리/패치를 유발합니다.

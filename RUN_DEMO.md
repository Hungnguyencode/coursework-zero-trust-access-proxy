# RUN_DEMO.md — Hướng dẫn chạy và trình diễn Zero Trust Access Proxy

Tài liệu này tách riêng phần **vận hành, chạy lab và demo** khỏi `README.md`.

Mục tiêu là giúp người chấm hoặc người thuyết trình có thể đi theo một flow rõ ràng mà không phải đọc toàn bộ phần kiến trúc trước.

---

## 1. Mục tiêu của demo

Demo nên chứng minh được các điểm sau:

1. Login thành công không đồng nghĩa với toàn quyền truy cập.
2. Device trust và business role là hai control độc lập.
3. Heartbeat/posture được đánh giá theo current state.
4. LOW / MEDIUM / HIGH có yêu cầu policy khác nhau.
5. HIGH data cần cả role phù hợp và healthy trusted device.
6. `DENY` xảy ra trước khi sensitive payload được fetch.
7. `ALLOW` path có request correlation tới Internal API.
8. Security Center cập nhật realtime và lưu audit evidence.
9. SOC/IT có thể provision identity, quản lý device trust và role.
10. Demo posture control là simulation, không thay đổi cấu hình Windows thật.

---

## 2. Yêu cầu môi trường

Khuyến nghị:

- Windows 10/11;
- Docker Desktop hoặc Docker Engine;
- Docker Compose v2;
- Python 3;
- PowerShell;
- Git.

Kiểm tra nhanh:

```powershell
docker --version
docker compose version
python --version
git --version
```

---

## 3. Clone và vào project

```powershell
git clone https://github.com/Hungnguyencode/coursework-zero-trust-access-proxy.git
cd .\coursework-zero-trust-access-proxy
```

Nếu đã có project local thì chỉ cần mở PowerShell tại thư mục project.

---

## 4. Chuẩn bị Python environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\device_agent\requirements.txt
```

Nếu environment đã tồn tại:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 5. Tạo local secret

Có thể copy `.env.example` thành `.env`, hoặc tạo secret ngẫu nhiên:

```powershell
$jwtSecret = python -c "import secrets; print(secrets.token_urlsafe(48))"
$internalSecret = python -c "import secrets; print(secrets.token_urlsafe(48))"

@"
JWT_SECRET=$jwtSecret
INTERNAL_SHARED_SECRET=$internalSecret
"@ | Set-Content .\.env -Encoding ascii
```

Lưu ý:

```text
.env không được commit.
```

Kiểm tra:

```powershell
git status --short
```

`.env` không nên xuất hiện trong Git status nếu `.gitignore` đúng.

---

## 6. Validate Docker Compose

```powershell
docker compose config -q
```

Nếu lệnh không in lỗi, cấu hình Compose hợp lệ.

---

## 7. Build và khởi động toàn bộ stack

```powershell
docker compose up -d --build
```

Kiểm tra service:

```powershell
docker compose ps
```

Các service chính:

```text
postgres
opa
internal-api
access-proxy
dashboard
nginx
data-vault
```

### Không dùng `down -v` trong demo thông thường

Không chạy:

```powershell
docker compose down -v
```

trừ khi bạn **cố ý reset toàn bộ database**.

`-v` xóa Docker volume PostgreSQL, đồng nghĩa có thể mất:

- user provision thủ công;
- device state;
- posture history;
- access logs;
- security events;
- realtime-event history.

Nếu chỉ cần restart:

```powershell
docker compose down
docker compose up -d
```

hoặc:

```powershell
docker compose restart
```

---

## 8. Địa chỉ UI

```text
Security Center : http://localhost:8081
Data Vault      : http://localhost:8082
```

---

## 9. Tài khoản demo

| Username | Password | Device | Role |
|---|---|---|---|
| `alice` | `alice123` | `DEV-001` | `analyst` |
| `bob` | `bob123` | `DEV-002` | `viewer` |
| `socadmin` | `socadmin123` | `SOC-001` | `security-admin` |

Credential chỉ dùng cho local academic lab.

---

## 10. Chạy Device Agent

### Terminal 1 — DEV-001

```powershell
.\.venv\Scripts\Activate.ps1
python .\device_agent\agent.py
```

### Terminal 2 — DEV-002

```powershell
.\.venv\Scripts\Activate.ps1
python .\device_agent\agent.py --device-id DEV-002
```

### Terminal 3 — device được provision thêm

```powershell
.\.venv\Scripts\Activate.ps1
python .\device_agent\agent.py --device-id DEV-003
```

Một agent process đại diện cho một logical managed device.

Nếu chạy nhiều logical device trên cùng một máy Windows, mỗi `device_id` cần một terminal/agent instance riêng để duy trì heartbeat `FRESH`.

---

## 11. Flow demo chính được khuyến nghị

Đây là flow phù hợp nhất để trình bày toàn bộ ý tưởng của project.

### Bước 1 — Mở Security Center

Truy cập:

```text
http://localhost:8081
```

Quan sát:

- active identity/device;
- trust state;
- heartbeat;
- posture;
- access decision;
- security event timeline;
- device posture evidence timeline.

---

### Bước 2 — Provision một business identity mới

Từ:

```text
Identity & Access Administration
```

Provision một user demo mới với:

```text
username  = tùy chọn
device_id = DEV-003
role      = viewer
```

Expected state:

```text
identity created
+ registered managed device
+ role = VIEWER
+ trust = UNTRUSTED
```

Đây là trạng thái least-privilege ban đầu.

---

### Bước 3 — User login vào Data Vault

Mở:

```text
http://localhost:8082
```

Login bằng user vừa tạo và `DEV-003`.

Khi device còn `UNTRUSTED`, thử request:

```text
LOW
MEDIUM
HIGH
```

Expected behavior:

```text
LOW    → có thể ALLOW nếu các điều kiện LOW đạt
MEDIUM → DENY vì device chưa trusted
HIGH   → DENY vì device chưa trusted và/hoặc role không đủ
```

Reason có thể thấy:

```text
DEVICE_UNTRUSTED
```

---

### Bước 4 — Start Device Agent cho DEV-003

Mở terminal mới:

```powershell
.\.venv\Scripts\Activate.ps1
python .\device_agent\agent.py --device-id DEV-003
```

Quay lại Security Center.

Expected:

```text
heartbeat → FRESH
posture evidence → xuất hiện
firewall → healthy nếu máy Windows đang healthy
patch evidence → được báo cáo
device trust → vẫn UNTRUSTED
```

Điểm cần nói khi demo:

> Healthy posture không tự động biến device thành trusted. Trust là một quyết định control-plane riêng.

---

### Bước 5 — SOC TRUST DEV-003

Trong Security Center:

```text
UNTRUSTED → TRUSTED
```

Thử request lại.

Expected:

```text
MEDIUM → ALLOW
HIGH   → vẫn DENY nếu role = viewer
```

HIGH expected reason:

```text
ROLE_DENIED_FOR_HIGH_DATA
```

Điểm cần nhấn mạnh:

> Device trust không thay thế business authorization.

---

### Bước 6 — Grant ANALYST

Trong Identity & Access Administration:

```text
VIEWER → ANALYST
```

Xác nhận role elevation qua confirmation modal.

Không cần login lại trong prototype.

Quay lại Data Vault và request HIGH lần nữa.

Expected:

```text
HIGH → ALLOW
```

nếu đồng thời:

```text
device trusted
heartbeat fresh
firewall enabled
patch compliant
no pending reboot
context allowed
```

Điểm cần nhấn mạnh:

> Request tiếp theo được reevaluate bằng current role/current device state.

---

### Bước 7 — Inspect ALLOW request

Trong Security Center mở Decision Inspector của request vừa ALLOW.

Kiểm tra:

```text
request_id
identity snapshot
device snapshot
posture snapshot
resource sensitivity
OPA decision
access log
realtime event
Internal API fetch evidence
```

Expected invariant:

```text
ALLOW
→ request_id propagate tới Internal API
→ DATA_API_FETCHED có evidence
```

---

### Bước 8 — Tạo DENY và inspect

Có thể dùng một trong các cách:

- revoke trust;
- simulate firewall off;
- simulate patch old;
- simulate heartbeat loss;
- dùng Bob với HIGH data;
- chuyển role về viewer.

Sau đó request protected resource.

Expected:

```text
DENY
→ có decision reason
→ không có protected payload
→ không có DATA_API_FETCHED
```

Trong Decision Inspector, denied path từ OPA tới Data API được biểu diễn dạng đứt đoạn để minh họa việc sensitive fetch không xảy ra.

---

## 12. Demo nhanh bằng Alice và Bob

### Alice

```text
username = alice
password = alice123
device   = DEV-001
role     = analyst
```

Khi DEV-001 healthy + trusted:

```text
HIGH → 200 ALLOW
```

### Bob

```text
username = bob
password = bob123
device   = DEV-002
role     = viewer
```

Khi DEV-002 healthy + trusted:

```text
HIGH → DENY
reason → ROLE_DENIED_FOR_HIGH_DATA
```

Scenario này rất phù hợp để chứng minh:

```text
healthy device ≠ authorized business role
```

---

## 13. Demo posture simulation

### 13.1. Firewall

```text
NORMAL
→ SIMULATE OFF
```

Sau đó request HIGH.

Expected:

```text
DENY
→ FIREWALL_DISABLED
```

Trả lại:

```text
SIMULATE OFF
→ NORMAL
```

### 13.2. Patch

```text
NORMAL
→ SIMULATE OLD
```

Expected HIGH result:

```text
DENY
→ PATCH_TOO_OLD
```

hoặc reason liên quan patch evidence tùy state.

Sau demo:

```text
SIMULATE OLD
→ NORMAL
```

### 13.3. Heartbeat/Posture loss

```text
NORMAL
→ SIMULATE LOSS
```

Expected sau khi evidence trở nên stale/missing:

```text
DENY
→ DEVICE_STALE
```

Sau demo:

```text
SIMULATE LOSS
→ NORMAL
```

### Quan trọng

Ba simulation trên **không thay đổi Windows Firewall hoặc Windows Update thật**.

Chúng chỉ thay đổi telemetry/evidence trong môi trường demo.

---

## 14. Device Trust khác posture simulation như thế nào?

Device Trust:

```text
TRUSTED / REVOKE
```

là một control-plane state thực sự được policy sử dụng.

Trong khi đó:

```text
SIMULATE OFF
SIMULATE OLD
SIMULATE LOSS
```

là telemetry simulation phục vụ việc trình diễn.

Có thể giải thích ngắn:

```text
Trust = quyết định quản trị
Posture = bằng chứng kỹ thuật của endpoint
```

---

## 15. Realtime monitoring cần quan sát gì?

Khi thực hiện request hoặc thay đổi posture/trust:

- Decision Summary cập nhật;
- Security Event Timeline có event mới;
- Device Posture Evidence Timeline thay đổi;
- realtime decision xuất hiện;
- Decision Inspector có request mới;
- access log được persist.

Mô hình realtime:

```text
SSE → wake-up
REST → authoritative state
Polling → fallback
PostgreSQL → durable source of truth
```

---

## 16. Chạy policy regression

Yêu cầu:

- Docker stack đang chạy;
- OPA reachable;
- Python environment đã activate.

Chạy:

```powershell
python .\tests\policy_regression.py
```

QA checkpoint đã xác nhận:

```text
14 / 14 PASS
```

Test này gọi trực tiếp OPA HTTP API và kiểm tra policy logic.

---

## 17. Chạy API regression

Yêu cầu:

- toàn bộ Docker stack đang chạy;
- Access Proxy reachable;
- database state phù hợp với test fixture.

Chạy:

```powershell
python .\tests\api_regression.py
```

QA checkpoint đã xác nhận:

```text
15 / 15 PASS
```

Test này đi qua Access Proxy thật và kiểm tra enforcement end-to-end.

---

## 18. Regression scenario đã xác nhận

```text
Alice + healthy trusted DEV-001 + HIGH
→ 200 ALLOW
```

```text
Bob + healthy trusted DEV-002 + HIGH
→ DENY
→ ROLE_DENIED_FOR_HIGH_DATA
```

Đây là hai scenario tốt để dùng làm smoke test trước buổi bảo vệ.

---

## 19. Benchmark

Nếu cần chạy benchmark:

```powershell
python .\benchmark.py
```

Artifact hiện có:

```text
zt_benchmark_v14.csv
zt_benchmark_v14_summary.json
```

Kết quả tham chiếu:

| Scenario | Average | Median | P95 |
|---|---:|---:|---:|
| Direct Internal API | 2.868 ms | 2.646 ms | 4.258 ms |
| OPA-only | 2.773 ms | 2.391 ms | 4.362 ms |
| Full Zero Trust | 72.211 ms | 65.526 ms | 99.045 ms |

Không trình bày benchmark này như production performance hoặc scalability benchmark.

---

## 20. Flow demo ngắn 5–7 phút

Nếu thời gian thuyết trình ngắn:

```text
1. Mở Security Center
2. Mở Data Vault
3. Bob → HIGH → DENY vì viewer
4. Alice → HIGH → ALLOW
5. Revoke Alice device trust → request lại → DENY
6. Trust lại → HIGH → ALLOW
7. Mở Decision Inspector
8. Chỉ ra request_id + OPA + audit + Internal API evidence
```

Thông điệp:

```text
login không đủ
role không đủ
device trust không đủ
posture không đủ
→ cần current state của tất cả tín hiệu liên quan
```

---

## 21. Flow demo đầy đủ 10–15 phút

```text
1. Provision user mới
2. VIEWER + DEV-003 UNTRUSTED
3. Login Data Vault
4. MEDIUM/HIGH DENY
5. Start DEV-003 agent
6. Heartbeat FRESH nhưng vẫn UNTRUSTED
7. TRUST device
8. MEDIUM ALLOW
9. HIGH DENY vì VIEWER
10. GRANT ANALYST
11. HIGH ALLOW không cần login lại
12. Simulate firewall OFF
13. HIGH DENY
14. Restore NORMAL
15. HIGH ALLOW
16. Inspect request correlation
17. Show event timeline + posture timeline
```

Flow này thể hiện đầy đủ nhất thiết kế của project.

---

## 22. Checklist trước khi demo/bảo vệ

```text
[ ] Docker Desktop đang chạy
[ ] docker compose ps không có service lỗi
[ ] Security Center mở được
[ ] Data Vault mở được
[ ] .env tồn tại local và không bị Git track
[ ] DEV-001 agent chạy nếu demo Alice
[ ] DEV-002 agent chạy nếu demo Bob
[ ] DEV-003 agent chạy nếu demo user provision mới
[ ] Device heartbeat đang FRESH
[ ] Demo control đã trở về NORMAL trước khi bắt đầu
[ ] Test account login được
[ ] HIGH ALLOW scenario đã smoke test
[ ] HIGH DENY scenario đã smoke test
[ ] Decision Inspector hiển thị đúng
[ ] Không chạy docker compose down -v
```

---

## 23. Troubleshooting

### 23.1. Device hiển thị STALE

Nguyên nhân phổ biến:

- Device Agent chưa chạy;
- agent chạy nhầm `device_id`;
- terminal agent đã bị đóng;
- heartbeat quá 90 giây.

Khắc phục:

```powershell
python .\device_agent\agent.py --device-id DEV-XXX
```

với đúng device ID.

### 23.2. HIGH vẫn DENY dù device healthy

Kiểm tra:

```text
role
trust
heartbeat
firewall
patch compliance
pending reboot
context
```

Nếu reason:

```text
ROLE_DENIED_FOR_HIGH_DATA
```

thì user cần business role `analyst`.

### 23.3. MEDIUM DENY nhưng posture trông healthy

Kiểm tra device trust.

Healthy posture không tự động đồng nghĩa:

```text
trusted = true
```

### 23.4. User vừa được grant ANALYST nhưng UI chưa cập nhật

Thử:

- gửi protected request mới;
- đợi realtime refresh;
- refresh browser nếu cần.

Prototype reevaluate role ở request tiếp theo; không bắt buộc login lại.

### 23.5. Event realtime không xuất hiện ngay

Security Center dùng:

```text
SSE + REST reconciliation + polling fallback
```

Nếu SSE reconnect, polling vẫn có thể cập nhật state sau đó.

### 23.6. Database/history biến mất

Kiểm tra xem trước đó có chạy:

```powershell
docker compose down -v
```

hay không.

Lệnh này xóa PostgreSQL volume.

Nếu không có backup ngoài volume thì history/user thủ công cũ không thể khôi phục nguyên trạng chỉ từ source code.

### 23.7. Light/Dark theme hiển thị cũ

Hard refresh:

```text
Ctrl + F5
```

Nếu Data Vault vừa được build lại:

```powershell
docker compose up -d --build data-vault
```

---

## 24. Dọn môi trường sau demo

Nếu muốn dừng container nhưng giữ database:

```powershell
docker compose down
```

Khởi động lại:

```powershell
docker compose up -d
```

Chỉ xóa volume khi thực sự muốn reset lab:

```powershell
docker compose down -v
```

---

## 25. Evidence nên chụp cho báo cáo

Nên có screenshot của:

1. Security Center overview.
2. Data Vault catalog.
3. Identity Administration.
4. User ở trạng thái VIEWER + UNTRUSTED.
5. Device heartbeat/posture FRESH.
6. `ROLE_DENIED_FOR_HIGH_DATA`.
7. Successful HIGH `ALLOW`.
8. Decision Inspector của ALLOW.
9. Decision Inspector của DENY.
10. Security Event Timeline.
11. Device Posture Evidence Timeline.
12. Light theme.
13. Dark theme.
14. Regression test output.
15. `docker compose ps`.

---

## 26. Kết quả QA tham chiếu

Backend/policy QA checkpoint:

```text
Policy regression : 14 / 14 PASS
API regression    : 15 / 15 PASS
Clean deploy       : PASS
Smoke test         : PASS
```

Manual scenarios:

```text
Alice HIGH healthy → ALLOW
Bob HIGH healthy   → DENY / ROLE_DENIED_FOR_HIGH_DATA
```

UI final acceptance:

```text
Light theme        → PASS
Dark theme         → PASS
Decision trace     → PASS
DENY dashed path   → PASS
Modal clarity      → PASS
Identity UI        → PASS
```

---

## 27. Thông điệp kết thúc demo

Có thể kết luận bằng câu:

> **Zero Trust không hỏi “user đã đăng nhập chưa?” một lần duy nhất. Hệ thống phải liên tục hỏi “request này, tại thời điểm này, từ identity này, trên device này, với posture này, tới resource này, có được phép hay không?”**

Liên hệ với implementation:

```text
Identity
+ Device
+ Posture
+ Business role
+ Context
+ Resource sensitivity
        ↓
     OPA/Rego
        ↓
   ALLOW / DENY
        ↓
 Enforcement + Audit Evidence
```

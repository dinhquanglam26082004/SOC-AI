# SOC-AI · Wazuh Endpoint Operations

## Bắt đầu ở đây khi tải từ GitHub

1. Chạy các dịch vụ trên máy chính theo mục **Khởi động máy chính** bên dưới.
2. Làm theo [Cấu hình máy ảo Ubuntu: Wazuh + Zeek](docs/ubuntu-victim-setup.md)
   để chọn IP/NIC, cài Agent, đăng ký, cấu hình Zeek và gửi log về SOC-AI.
3. Mở `http://localhost:8100` → **Logs** để xem dữ liệu Zeek và Wazuh chung.

Clone repository và chạy Docker chưa làm máy ảo tự gửi log. Người dùng phải cài
và cấu hình Agent/sensor trên VM theo hướng dẫn. Mật khẩu mỗi lần cài được sinh
riêng; không dùng mật khẩu hoặc địa chỉ IP cố định của người khác.

## Tổng quan

Tiếp nhận **cảnh báo mới qua Wazuh**, bao gồm toàn bộ file log Zeek nếu Agent đã cấu hình
đọc `/opt/zeek/logs/current/*.log` theo [hướng dẫn](docs/zeek-notice-alerts.md).
Mục [Logs chung](docs/unified-logs.md) hiển thị Zeek và Wazuh trên một dòng thời gian,
lọc theo nguồn và loại log; notice đồng thời xuất hiện trong Alerts. Máy Agent riêng tạo sự kiện; Manager Docker
thu nhận và áp dụng rules; SOC-AI lưu bằng chứng rồi dùng Ollama + RAG để giải thích,
phân biệt bằng chứng, suy luận, điều chưa xác minh và đề xuất. Response chưa thực thi (HTTP 501).

```text
Agent Windows/Linux, IP riêng, Wazuh Agent 4.14.5
  → TCP 1514: data / TCP 1515: enrollment
Máy chính Windows 16 GB / Docker Desktop Linux containers
  Wazuh Manager 4.14.5 → custom integration → SQLite spool volume
  → forwarder → POST /wazuh + X-Webhook-Token
  → SQLite events + ai_jobs (commit trước HTTP 202)
  → worker AI (1) → Ollama qwen3:8b + ChromaDB
  → dashboard: cảnh báo nguồn và suy luận AI tách biệt
```

Manager chạy trong Docker trên máy chính. Ubuntu VM là endpoint/sensor được giám sát;
không cần cài thêm Manager hoặc Agent trên Windows host cho mô hình này.

## Khởi động máy chính

Yêu cầu: Docker Desktop Linux containers; Python 3.12 cho script cấu hình/native;
LAN tới Agent. Dự trù 15–25 GB đĩa trống cho images/model/dependencies; dung lượng log
cần theo dõi riêng. Thay mọi IP ví dụ bằng IP thật của máy chính/Agent.

```powershell
git clone https://github.com/dinhquanglam26082004/SOC-AI.git
cd SOC-AI
# Nếu chưa có môi trường: py -3.12 -m venv .venv
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe scripts\configure_local.py
docker compose --profile app config --quiet
docker compose --profile app up -d --build
docker compose exec ollama ollama pull qwen3:8b
# Chỉ ingest lần đầu nếu collection rỗng, hoặc khi chủ động rebuild KB:
docker compose exec soc-ai-app python -m rag.ingest
docker compose ps
Invoke-RestMethod http://localhost:8100/health
Invoke-RestMethod http://localhost:8100/api/sources/status
Invoke-RestMethod http://localhost:8100/api/system/status
```

Mở `http://localhost:8100`, không mở file HTML trực tiếp. Dừng backend native cũ trước
khi chạy container app: không để hai process cùng ghi SQLite/ChromaDB. Ingest RAG xây
lại collection nên không chạy lại tùy tiện. Dữ liệu hiện có được bind mount `data/`
và `rag/chroma_db/`, không thay bằng volume rỗng.

Script sinh `.env` và `secrets/authd.pass` mà không in secrets; giữ token hiện có, đặt
model về cấu hình lab nhỏ. Đọc mật khẩu enrollment riêng để nhập vào Agent. Cả hai bị
loại khỏi Git/build context. `.env.example` liệt kê toàn bộ biến. Không tự cài software
lên Agent khi chưa có quyền.

```powershell
docker compose logs --tail 100 wazuh-manager wazuh-forwarder
docker compose logs --tail 100 soc-ai-app
docker compose exec wazuh-manager /var/ossec/bin/wazuh-control status
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l
docker stats --no-stream
# Dừng bình thường; giữ volumes và enrollment:
docker compose --profile app stop
```

`down` không có `-v` cũng giữ volumes. **Không thêm `-v` khi dừng thông thường**:
xóa volumes làm mất Agent keys, spool và model. Backup trước khi chủ động reset.

## Chạy backend native Windows

Manager và forwarder vẫn ở Docker. Trong `.env`:

```env
WAZUH_FORWARDER_TARGET_URL=http://host.docker.internal:8100/wazuh
SOC_BIND_HOST=0.0.0.0
OLLAMA_HOST=http://localhost:11434
RUNTIME_DB_PATH=./data/soc_runtime.sqlite3
```

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
docker compose up -d --build wazuh-manager wazuh-forwarder
# Ollama native đã cài: chạy terminal riêng ollama serve; ollama pull qwen3:8b
.\.venv\Scripts\python.exe main.py
```

Native mặc định bind 127.0.0.1; Docker gọi Windows cần bind như trên và giới hạn firewall
cho Docker subnet. Không dùng `localhost` trong container để trỏ Windows. Dashboard
Compose chỉ publish 127.0.0.1:8100; 55000 không publish ra LAN. API dashboard hiện không
có login, giữ trong local/Docker subnet; webhook luôn yêu cầu token riêng. CORS mặc định
chỉ localhost:8100 và 127.0.0.1:8100. CORS không thay thế firewall.

## Agent và demo

Làm theo [runbook Windows/Linux](docs/wazuh-live-demo.md), bắt đầu bằng FIM. Agent dùng
IP LAN của máy chính, không dùng tên service Compose. Dashboard chỉ báo thời điểm nhận
alert cuối; không suy ra Agent online/offline từ im lặng. Xác minh Agent thực tế bằng
`agent_control -l` trong Manager.

## Cấu hình và chính sách

| Biến | Mặc định / ý nghĩa |
| --- | --- |
| WAZUH_ENABLED | true; thiếu WAZUH_WEBHOOK_TOKEN thì startup thất bại |
| WAZUH_WEBHOOK_TOKEN | Bắt buộc, header X-Webhook-Token |
| WAZUH_FORWARDER_TARGET_URL | http://soc-ai-app:8100/wazuh; native dùng host.docker.internal |
| WAZUH_FORWARD_MIN_LEVEL | 3, lọc chuyển tiếp, độc lập AI |
| WAZUH_FORWARD_GROUP_ALLOWLIST | Rỗng: mọi group đạt ngưỡng; có giá trị: chỉ các group này |
| WAZUH_AI_MIN_LEVEL | 7; đây là chính sách điều tra, không phải nhãn tấn công |
| WAZUH_AI_RULE_ALLOWLIST | Rule ID bổ sung đủ điều kiện AI |
| WAZUH_AI_GROUP_ALLOWLIST | syscheck; FIM vẫn điều tra dù dưới ngưỡng |
| AI_MAX_CONCURRENCY | 1; worker và Copilot dùng chung semaphore; tối đa 4 |
| AI_QUEUE_LIMIT | 1000 queued/running; đầy trả 503 để forwarder giữ và retry |
| WAZUH_MAX_PAYLOAD_BYTES | 262144; lớn hơn trả 413, forwarder đưa DLQ |
| WAZUH_SPOOL_MAX_BYTES | 268435456; 256 MiB cho file spool |
| AI_CONTEXT_CHARS / AI_ALERT_CHARS | 6000 / 5000; raw_event vẫn lưu đầy đủ |
| OLLAMA_NUM_CTX / OLLAMA_NUM_PREDICT | 4096 / 768 |
| AGENT_MODEL | qwen3:8b; cấu hình tên model đã cài |

Manager integration và log_alert_level cùng mặc định ≥3. Muốn chuyển mức thấp hơn phải
sửa cả hai trong `docker/wazuh/ossec.conf`, cùng WAZUH_FORWARD_MIN_LEVEL. Không dùng ngưỡng
AI làm ngưỡng chuyển FIM. Recreate container để nạp biến thay đổi.

## Độ bền, migration và giới hạn

ID nội bộ là SHA256(Manager name + alert ID nguồn), không dùng rule ID làm khóa.
Alert và job commit trong một transaction trước HTTP 202. Duplicate sau restart không
tạo event/job/case mới. Job running được phục hồi thành queued; lỗi AI/RAG giữ raw_event,
đánh failed, không dựng báo cáo. Retry thủ công cooldown 10s, tối đa 5 lần; completed
không tự xếp lại. Chạy một Uvicorn process; không dùng nhiều workers/replicas.

Migration thêm events/cases/ai_jobs, nhập snapshot cũ một lần; không đổi nguồn gốc hay
xóa lịch sử. Bảng runtime_state và response history cũ được giữ nguyên. Backup khi app
dừng, hoặc dùng SQLite backup API; không copy riêng main DB khi đang WAL.

Custom integration ghi SQLite spool (FULL synchronous) trước khi exit thành công.
Không tail file nên không có checkpoint/rotation race; lần đầu chỉ nhận callback mới,
không tự nhập log cũ. Forwarder timeout 10s, backoff 2–256s; retry kết nối/5xx/408/425/429.
4xx khác vào DLQ để sửa cấu hình; chỉ xóa khỏi pending khi backend trả durable=true.
Gửi ít nhất một lần + chống trùng ở backend. Một forwarder instance cho mỗi spool.

Spool đầy/disk hỏng: integration trả lỗi, ghi marker integration-error và health báo lỗi.
Không giả định Wazuh tự retry callback: alert chưa spool có thể mất nếu Manager logs
hết retention. Không thể cam kết zero-loss khi disk đầy hoặc downtime quá dài. Xem
runbook để phục hồi JSONL còn giữ và gửi lại DLQ. DLQ cũng chiếm dung lượng spool.
Heartbeat gồm pending/dead_letter/errors/sent/last_success; stale sau 30s. Native không
mount heartbeat thì dashboard ghi chưa biết; kiểm tra bằng docker exec.

## Mô hình điều tra

[Chính sách AI chỉ xử lý cảnh báo bảo mật](docs/alert-only-ai.md): log thường,
thống kê Zeek, xoay vòng log, cài gói và SCA chỉ được lưu để tra cứu; không gọi AI.

Mặc định dùng **Qwen3-8B**, xem [cấu hình, tài nguyên và chuyển model](docs/qwen3-8b.md).
Model tải qua Ollama; trọng số không nằm trong repository.

## Ngân sách RAM

Ước tính để lập kế hoạch, cần đo `docker stats` + Task Manager: Windows/app nền 4–6 GB;
Docker VM overhead 1–2 GB; Manager 1–3 GB; backend + embedding/ChromaDB 1–3 GB; Ollama
Qwen3-8B bản Q4_K_M tải khoảng 5.2 GB; RAM chạy còn gồm context và bộ nhớ xử lý.
Forwarder dưới 128 MB. Compose cap lần lượt 3 GB/3 GB/7 GB/128 MB; đây là giới hạn
tối đa, không phải lượng RAM đặt trước. Docker VM cần đủ bộ nhớ cho tất cả dịch vụ.
Ingest/model context lớn có thể OOM. Nếu Agent là VM trên cùng máy, cộng RAM VM đó;
ưu tiên Agent máy riêng. Không cam kết đủ 16 GB khi chưa đo đủ workload.

Manager/Agent pin **4.14.5**, image đã đối chiếu tag chính thức. Upstream chứa Filebeat;
Dockerfile lab gỡ supervisor/initializer Filebeat, tắt indexer/vulnerability detection.
Không có Indexer, Wazuh Dashboard hay tính năng inventory/vulnerability đầy đủ. Manager
có thể ghi inventory-harvester warnings vì không có Indexer; kiểm tra readiness/FIM riêng.

## Mã nguồn và API

`api/app.py`: API chung/worker; `wazuh_integration/`: mapper/spool/forwarder;
`common/event_store.py`: SQLite migration/jobs; `common/runtime_store.py`: snapshot lịch sử;
`agents/`: điều tra/đề xuất; `docker/wazuh/`: Manager; `web/index.html`: dashboard điều tra và Logs chung.
Module nguồn cũ, endpoint nhận cũ, mapper, JSON replay và API/nút điều khiển demo đã gỡ.

API giữ: GET /health; GET /api/logs (Zeek + Wazuh), /api/zeek/logs;
GET /api/alerts, /api/alerts/timeseries, /api/alerts/{id};
POST /api/alerts/{id}/investigate; GET/POST/PATCH cases; GET /api/sources/status,
/api/system/status, /api/response/history; POST /api/response/execute (501).
Nguồn mới duy nhất: POST /wazuh.

## Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
New-Item -ItemType Directory artifacts -Force
.\.venv\Scripts\python.exe -m pytest tests -q --basetemp artifacts/pytest-run
docker compose --profile app config --quiet
```

Xem [kết quả thực nghiệm](docs/validation.md). Fixture chỉ kiểm tra pipeline, không phải
bằng chứng thu log live; FIM end-to-end cần Agent riêng và quyền thao tác trên Agent.

## Nguồn chính thức

- [Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Source Docker tag v4.14.5](https://github.com/wazuh/wazuh-docker/tree/v4.14.5)
- [Custom integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)
- [FIM basic settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html)

Trang current có thể đổi theo bản mới; lab đối chiếu thêm source tag và chạy Manager
thực tế. Khi nâng version phải kiểm tra lại Agent/config.

Chức năng hỏi đáp Copilot và endpoint `/api/chat` đã được gỡ bỏ. RAG tiếp tục phục vụ
AI điều tra cảnh báo và đề xuất playbook.

# Sổ tay lệnh PowerShell — SOC-AI

Các lệnh dành cho **PowerShell trên máy Windows chạy dự án**. Chạy từng khối theo nhu cầu; không dán chạy toàn bộ tài liệu. Trong khối `@' ... '@`, nội dung là Python được chuyển vào container; bạn vẫn chạy cả khối từ PowerShell.

**Quy ước:** **XEM** = đọc thông tin; **THAY ĐỔI** = khởi động, build, ghi file hoặc tạo yêu cầu xử lý. Các lệnh API trong phần xem chỉ dùng GET. Theo dõi liên tục bằng `-f` kết thúc bằng **Ctrl + C**, không dừng container.

## Mục lục

1. [Chuẩn bị cửa sổ PowerShell](#1-chuẩn-bị-cửa-sổ-powershell)
2. [Kiểm tra nhanh hằng ngày](#2-kiểm-tra-nhanh-hằng-ngày)
3. [Xem code và phiên bản Git](#3-xem-code-và-phiên-bản-git)
4. [Docker: image, container và tài nguyên](#4-docker-image-container-và-tài-nguyên)
5. [Xem log hoạt động của dịch vụ](#5-xem-log-hoạt-động-của-dịch-vụ)
6. [Wazuh Manager và Agent](#6-wazuh-manager-và-agent)
7. [Tìm và đọc rule](#7-tìm-và-đọc-rule)
8. [Log Wazuh, Zeek và forwarder](#8-log-wazuh-zeek-và-forwarder)
9. [API log và cảnh báo](#9-api-log-và-cảnh-báo)
10. [AI và kết quả điều tra](#10-ai-và-kết-quả-điều-tra)
11. [Ollama, model và GPU](#11-ollama-model-và-gpu)
12. [Knowledge / RAG](#12-knowledge--rag)
13. [SQLite và DB Browser](#13-sqlite-và-db-browser)
14. [Cổng mạng và kết nối VM](#14-cổng-mạng-và-kết-nối-vm)
15. [Khởi động, cập nhật và dừng](#15-khởi-động-cập-nhật-và-dừng)
16. [Áp dụng rule Zeek đã sửa](#16-áp-dụng-rule-zeek-đã-sửa)
17. [Cài đặt lần đầu](#17-cài-đặt-lần-đầu)
18. [Tra lỗi theo triệu chứng](#18-tra-lỗi-theo-triệu-chứng)

## 1. Chuẩn bị cửa sổ PowerShell

**Chạy phần này đầu tiên trong mỗi cửa sổ PowerShell mới.** Thay đường dẫn nếu bạn clone dự án ở nơi khác.

```powershell
Set-Location 'E:\Pictures\SOC-AI'

# Máy này có override để dùng GPU và volume database riêng.
# Máy không có file override sẽ dùng docker-compose.yml mặc định.
$ComposeArgs = @('--profile', 'app')
if (Test-Path -LiteralPath '.\data\local-runtime.compose.yml') {
    $ComposeArgs = @('-f', 'docker-compose.yml', '-f', 'data/local-runtime.compose.yml', '--profile', 'app')
}
$SocUrl = 'http://localhost:8100'
```

`@ComposeArgs` truyền bộ tham số trên vào Docker Compose. Tiếp tục dùng cùng bộ tham số khi xem, build, restart và cập nhật. Không bỏ override của một hệ thống đang dùng volume riêng: bỏ nó có thể khiến ứng dụng mở một database khác.

**XEM — kiểm tra công cụ và file cấu hình có tồn tại:**

```powershell
Get-Location
git --version
docker version
docker compose version
Test-Path -LiteralPath '.env'
Test-Path -LiteralPath '.\secrets\authd.pass'
docker compose @ComposeArgs config --quiet
docker compose @ComposeArgs config --services
```

`config --quiet` không in gì khi cấu hình hợp lệ. Tránh chia sẻ đầu ra `docker compose config` đầy đủ, toàn bộ `docker inspect` hoặc nội dung `.env`: chúng có thể chứa secrets.

## 2. Kiểm tra nhanh hằng ngày

**XEM:**

```powershell
# Container đang chạy / dừng / healthy hay không.
docker compose @ComposeArgs ps -a

# Backend và worker AI.
Invoke-RestMethod "$SocUrl/health" | ConvertTo-Json -Depth 8

# Sự kiện nhận gần nhất, hàng chờ, forwarder và investigations.
Invoke-RestMethod "$SocUrl/api/sources/status" | ConvertTo-Json -Depth 12

# Ollama, model được chọn, ChromaDB và trạng thái embedding.
Invoke-RestMethod "$SocUrl/api/system/status" | ConvertTo-Json -Depth 10

# Trạng thái Agent do Manager ghi nhận.
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/agent_control -l

# CPU / RAM của container tại thời điểm chạy lệnh.
docker stats --no-stream
```

**THAY ĐỔI giao diện đang mở — mở Dashboard:**

```powershell
Start-Process "$SocUrl/"
```

`Backend online` không chứng minh Agent đang Active. `Up` cũng không đồng nghĩa container đã healthy. Không có log mới chưa đủ để kết luận máy bị mất kết nối.

## 3. Xem code và phiên bản Git

**XEM:**

```powershell
Get-ChildItem
Get-ChildItem .\docs
git status --short
git branch --show-current
git remote -v
git log -5 --oneline
git diff --stat
git diff -- web/index.html

Get-Content .\README.md
Get-Content .\Dockerfile
Get-Content .\docker-compose.yml
Get-Content .\docker\wazuh\Dockerfile
Get-Content .\docker\forwarder.Dockerfile
```

Các file chính:

| File | Vai trò |
| --- | --- |
| `docker-compose.yml` | Dịch vụ, cổng, volume và môi trường Docker |
| `docker/wazuh/ossec.conf` | Cấu hình Manager |
| `docker/wazuh/zeek-notice-rules.xml` | Rule Zeek của dự án |
| `wazuh_integration/mapper.py` | Chuẩn hóa dữ liệu và chính sách chọn cảnh báo cho AI |
| `wazuh_integration/forwarder.py` | Gửi dữ liệu về SOC-AI |
| `api/app.py` | API, tiếp nhận log và worker |
| `common/event_store.py`, `common/log_index.py` | Lưu và truy vấn dữ liệu |
| `agents/investigation_graph.py`, `agents/investigation_tools.py` | Luồng điều tra AI và các tool |
| `rag/query.py`, `rag/browse.py` | RAG và đọc dữ liệu Knowledge |
| `web/index.html` | Giao diện |

**XEM — chỉ in một số cấu hình không phải mật khẩu:**

```powershell
Get-Content .\.env | Where-Object {
    $_ -match '^(AI_WORKFLOW|AI_MAX_CONCURRENCY|AI_GRAPH_MAX_ROUNDS|AI_GRAPH_MAX_MODEL_CALLS|AI_GRAPH_MAX_TOOL_CALLS|AI_GRAPH_TIMEOUT|AGENT_MODEL|OLLAMA_MODEL|OLLAMA_NUM_CTX|OLLAMA_NUM_PREDICT|WAZUH_AI_MIN_LEVEL|WAZUH_AI_GROUP_ALLOWLIST|WAZUH_ARCHIVES_ENABLED|RUNTIME_DB_PATH|CHROMA_PATH)='
}
```

Đây là cấu hình trên đĩa; container chỉ nhận biến môi trường đã áp dụng lúc nó được tạo. Xem runtime bằng API và phần database bên dưới.

## 4. Docker: image, container và tài nguyên

**XEM:**

```powershell
docker compose @ComposeArgs ps -a
docker compose @ComposeArgs images
docker image ls
docker volume ls
docker network ls
docker system df
docker stats --no-stream
```

Lệnh không có `compose` có thể hiển thị cả dự án Docker khác trên máy.

**XEM — trạng thái và các chỗ lưu dữ liệu của app; không in môi trường chứa secrets:**

```powershell
$AppContainerId = docker compose @ComposeArgs ps -q soc-ai-app
if ($AppContainerId) {
    docker inspect $AppContainerId --format '{{json .State}}'
    docker inspect $AppContainerId --format '{{json .Mounts}}'
    docker inspect $AppContainerId --format '{{.RestartCount}}'
}
```

`OOMKilled=true` nghĩa tiến trình đã bị hệ thống dừng do thiếu bộ nhớ. `.Mounts` cho biết database/model nằm trong volume hay thư mục Windows được gắn vào container.

## 5. Xem log hoạt động của dịch vụ

**XEM — 100 dòng gần nhất:**

```powershell
docker compose @ComposeArgs logs --tail 100 soc-ai-app
docker compose @ComposeArgs logs --tail 100 wazuh-manager
docker compose @ComposeArgs logs --tail 100 wazuh-forwarder
docker compose @ComposeArgs logs --tail 100 ollama
```

**XEM — theo dõi trực tiếp, Ctrl + C để thoát:**

```powershell
docker compose @ComposeArgs logs -f --tail 50 soc-ai-app wazuh-forwarder
```

**XEM — lọc lỗi của app trong 15 phút:**

```powershell
docker compose @ComposeArgs logs --since 15m --tail 1000 soc-ai-app 2>&1 |
    Select-String -Pattern 'ERROR|Traceback|failed|timeout|unavailable' -Context 2,6
```

Log Docker là log hoạt động của chương trình. Các sự kiện an ninh được lưu riêng trong Manager và database SOC-AI.

## 6. Wazuh Manager và Agent

**XEM:**

```powershell
# Các tiến trình Wazuh.
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/wazuh-control status

# Danh sách Agent và trạng thái kết nối.
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/agent_control -l

# Đổi 001 thành ID thật lấy từ danh sách trên.
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/agent_control -i 001

# Cấu hình Manager đang nằm trong container.
docker compose @ComposeArgs exec wazuh-manager cat /var/ossec/etc/ossec.conf

# Log nội bộ Manager.
docker compose @ComposeArgs exec wazuh-manager tail -n 80 /var/ossec/logs/ossec.log

# Theo dõi log nội bộ; Ctrl + C để thoát.
docker compose @ComposeArgs exec wazuh-manager tail -f /var/ossec/logs/ossec.log
```

Manager không trực tiếp đọc `/opt/zeek/logs/current/` trên máy ảo. Wazuh Agent trên VM đọc file được cấu hình rồi gửi về Manager. Lệnh `cat /var/ossec/etc/ossec.conf` ở trên xem cấu hình **Manager**, không phải cấu hình Agent trên VM.

## 7. Tìm và đọc rule

### 7.1. File trong mã nguồn Windows — XEM

```powershell
Get-Content .\docker\wazuh\zeek-notice-rules.xml
Get-Content .\docker\wazuh\ossec.conf

# Rule DoS 100142 trong file dự án; đổi ID khi cần.
Select-String -Path .\docker\wazuh\zeek-notice-rules.xml -Pattern 'id="100142"' -Context 0,15

# Tìm các khai báo ngưỡng / thời gian trong rule Zeek.
Select-String -Path .\docker\wazuh\zeek-notice-rules.xml -Pattern '<rule|frequency=|timeframe=|ignore='
```

### 7.2. File trong container Manager — XEM

```powershell
docker compose @ComposeArgs exec wazuh-manager ls -lh /var/ossec/ruleset/rules/
docker compose @ComposeArgs exec wazuh-manager ls -lh /var/ossec/etc/rules/
docker compose @ComposeArgs exec wazuh-manager cat /var/ossec/etc/rules/soc-ai-zeek-notice.xml
docker compose @ComposeArgs exec wazuh-manager ls /var/ossec/ruleset/decoders/
docker compose @ComposeArgs exec wazuh-manager ls /var/ossec/etc/decoders/
```

| Nơi | Nội dung |
| --- | --- |
| `/var/ossec/ruleset/rules/` | Rule Wazuh có sẵn |
| `/var/ossec/etc/rules/` | Rule tùy chỉnh |
| `/var/ossec/etc/rules/soc-ai-zeek-notice.xml` | Bản rule Zeek dự án đã cài vào Manager |

File trên Windows là bản nguồn. File trong container là bản được cung cấp cho Manager; Manager cần nạp thành công thì thay đổi mới có hiệu lực.

### 7.3. Tìm chính xác rule theo ID, tránh lỗi dấu nháy PowerShell — XEM

Sửa duy nhất dòng `rule_id = "202"` thành `100142`, `5404`, `550` hoặc ID cần tìm. Khối này in file, số dòng và nội dung rule; không sửa rule.

```powershell
@'
from pathlib import Path
import re
rule_id = "202"
pattern = re.compile(rf"""\bid\s*=\s*["']{re.escape(rule_id)}["']""")
found = False
for folder in ("/var/ossec/ruleset/rules", "/var/ossec/etc/rules"):
    for path in sorted(Path(folder).rglob("*.xml")):
        text = path.read_text(errors="replace")
        for match in re.finditer(r"<rule\b[^>]*>.*?</rule>", text, re.S):
            opening = match.group().split(">", 1)[0]
            if pattern.search(opening):
                found = True
                line = text.count("\n", 0, match.start()) + 1
                print(f"\n{path}:{line}\n{match.group()}\n")
if not found:
    print("Rule ID not found in configured standard/local folders")
'@ | docker compose @ComposeArgs exec -T wazuh-manager /var/ossec/framework/python/bin/python3 -
```

### 7.4. Chạy kiểm tra rule theo yêu cầu — KHÔNG tự chạy khi chỉ muốn xem

Kiểm tra cấu hình/rule bằng công cụ Wazuh, không restart dịch vụ:

```powershell
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t
```

Thử một dòng log bằng công cụ tương tác; dán log khi công cụ yêu cầu, sau đó Ctrl + C để thoát:

```powershell
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/wazuh-logtest
```

`wazuh-logtest` kiểm tra decoder/rule trong phiên thử riêng. Nó không chứng minh Agent đang gửi dữ liệu thật hoặc đường truyền tới SOC-AI hoạt động. Không dùng thời gian chạy logtest để suy ra tốc độ AI.

## 8. Log Wazuh, Zeek và forwarder

**XEM:**

```powershell
# Cảnh báo đạt điều kiện ghi alert.
docker compose @ComposeArgs exec wazuh-manager tail -n 3 /var/ossec/logs/alerts/alerts.json

# Sự kiện được Manager lưu vào archives, gồm cả các sự kiện không tạo alert.
docker compose @ComposeArgs exec wazuh-manager tail -n 3 /var/ossec/logs/archives/archives.json

# Theo dõi cảnh báo mới; Ctrl + C để thoát.
docker compose @ComposeArgs exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json

# Trạng thái forwarder, archives reader và hàng chờ chuyển tiếp.
docker compose @ComposeArgs exec wazuh-forwarder cat /spool/status.json

# Dấu hiệu integration gặp lỗi; không có file này không nhất thiết là lỗi.
docker compose @ComposeArgs exec wazuh-manager ls -lh /spool/
```

**XEM — đếm các trạng thái hàng chờ forwarder bằng SQLite ở chế độ chỉ đọc:**

```powershell
@'
from pathlib import Path
import os, sqlite3
path = Path(os.getenv("WAZUH_SPOOL_PATH", "/spool/queue.sqlite3"))
with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=15) as db:
    for row in db.execute("SELECT state,COUNT(*) FROM queue GROUP BY state"):
        print(row)
'@ | docker compose @ComposeArgs exec -T wazuh-forwarder python -
```

`archives.json` bao gồm dữ liệu Manager nhận và xử lý, không phải mọi hoạt động trên victim. Raw log có thể chứa IP, tài khoản và dữ liệu riêng; xem tại máy, cân nhắc trước khi chia sẻ.

## 9. API log và cảnh báo

**XEM — 5 log gần nhất:**

```powershell
$LogPage = Invoke-RestMethod "$SocUrl/api/logs?limit=5"
$LogPage | ConvertTo-Json -Depth 15
```

**XEM — lọc nguồn / loại:**

```powershell
Invoke-RestMethod "$SocUrl/api/logs?source=zeek&log_type=http&limit=5" | ConvertTo-Json -Depth 15
Invoke-RestMethod "$SocUrl/api/logs?source=wazuh&limit=5" | ConvertTo-Json -Depth 15
Invoke-RestMethod "$SocUrl/api/logs?kind=alert&limit=5" | ConvertTo-Json -Depth 15

$Keyword = [uri]::EscapeDataString('192.168.19.129')
Invoke-RestMethod "$SocUrl/api/logs?q=$Keyword&limit=5" | ConvertTo-Json -Depth 15
```

Thay IP tìm kiếm bằng IP thật của môi trường. API trả trang dữ liệu, không phải toàn bộ log. Dùng `next_cursor` làm `before` để lấy trang tiếp theo nếu cần:

```powershell
if ($LogPage.next_cursor) {
    $Cursor = [uri]::EscapeDataString([string]$LogPage.next_cursor)
    Invoke-RestMethod "$SocUrl/api/logs?limit=5&before=$Cursor" | ConvertTo-Json -Depth 15
}
```

**XEM — cảnh báo và một cảnh báo cụ thể:**

```powershell
$AlertPage = Invoke-RestMethod "$SocUrl/api/alerts?limit=5"
$AlertPage.alerts | Select-Object id, severity, ai_status, @{Name='Description';Expression={$_.rule.description}}

$AlertId = $AlertPage.alerts | Select-Object -First 1 -ExpandProperty id
if ($AlertId) {
    $AlertIdUrl = [uri]::EscapeDataString([string]$AlertId)
    Invoke-RestMethod "$SocUrl/api/alerts/$AlertIdUrl" | ConvertTo-Json -Depth 20
}
```

## 10. AI và kết quả điều tra

**XEM — hàng chờ và các hồ sơ cần analyst review:**

```powershell
Invoke-RestMethod "$SocUrl/health" | ConvertTo-Json -Depth 8
Invoke-RestMethod "$SocUrl/api/investigations?limit=20&offset=0" | ConvertTo-Json -Depth 15
```

`/api/investigations` là danh sách **đang chờ review**, không phải toàn bộ lịch sử AI.

**XEM — hồ sơ của `$AlertId` đã chọn ở mục 9:**

```powershell
if ($AlertId) {
    $AlertIdUrl = [uri]::EscapeDataString([string]$AlertId)
    $Investigation = Invoke-RestMethod "$SocUrl/api/alerts/$AlertIdUrl/investigation"
    $Investigation | ConvertTo-Json -Depth 15
}
```

Nếu cảnh báo chưa từng chạy graph thì API có thể trả 404. Để xem chi tiết, lấy ID hồ sơ từ trường `id` trong kết quả trên rồi nhập khi được hỏi:

```powershell
$IncidentId = Read-Host 'Nhap ID ho so dieu tra (khong phai ID alert)'
if ($IncidentId) {
    $IncidentIdUrl = [uri]::EscapeDataString($IncidentId)
    Invoke-RestMethod "$SocUrl/api/investigations/$IncidentIdUrl`?section=activity&limit=20" | ConvertTo-Json -Depth 20
    Invoke-RestMethod "$SocUrl/api/investigations/$IncidentIdUrl`?section=evidence&limit=20" | ConvertTo-Json -Depth 20
    Invoke-RestMethod "$SocUrl/api/investigations/$IncidentIdUrl`?section=tools&limit=20" | ConvertTo-Json -Depth 20
    Invoke-RestMethod "$SocUrl/api/investigations/$IncidentIdUrl`?section=models&limit=20" | ConvertTo-Json -Depth 20
}
```

Các section có phân trang bằng `offset`. `completed` nghĩa workflow đã kết thúc, không bảo đảm kết luận đúng hoặc đã thực thi phản ứng. `inconclusive` nghĩa chưa đủ bằng chứng kết luận. Lệnh GET không tự yêu cầu AI điều tra lại.

## 11. Ollama, model và GPU

**XEM:**

```powershell
docker compose @ComposeArgs exec ollama ollama list
docker compose @ComposeArgs exec ollama ollama ps
docker compose @ComposeArgs logs --tail 100 ollama

# GPU NVIDIA trên Windows; cần driver và công cụ tương ứng.
nvidia-smi

# Chỉ hoạt động nếu container được cấp GPU NVIDIA.
docker compose @ComposeArgs exec ollama nvidia-smi
```

`ollama list` liệt kê model đã tải. `ollama ps` liệt kê model đang được nạp và thông tin processor mà phiên bản Ollama cung cấp. Danh sách trống khi model không nạp không đồng nghĩa chưa cài model. GPU có trên Windows không tự chứng minh container đã được cấp GPU.

**THAY ĐỔI — tải Qwen3 nếu chưa có, không cần tải lại mỗi lần cập nhật code:**

```powershell
docker compose @ComposeArgs exec ollama ollama pull qwen3:8b
```

## 12. Knowledge / RAG

**XEM — tài liệu nguồn trên Windows:**

```powershell
Get-ChildItem .\rag\documents -Directory
Get-ChildItem .\rag\documents\playbooks -File
Get-ChildItem .\rag\documents\policies -File
```

**XEM — dữ liệu thực sự đã nạp vào ChromaDB:**

```powershell
$KnowledgePage = Invoke-RestMethod "$SocUrl/api/knowledge/chunks?limit=5&offset=0"
$KnowledgePage | ConvertTo-Json -Depth 10

Invoke-RestMethod "$SocUrl/api/knowledge/chunks?doc_type=playbooks&limit=5" | ConvertTo-Json -Depth 10

$SearchText = [uri]::EscapeDataString('RDP')
Invoke-RestMethod "$SocUrl/api/knowledge/chunks?doc_type=playbooks&q=$SearchText&limit=5" | ConvertTo-Json -Depth 10

$ChunkId = $KnowledgePage.items | Select-Object -First 1 -ExpandProperty id
if ($ChunkId) {
    $ChunkIdUrl = [uri]::EscapeDataString([string]$ChunkId)
    $Chunk = Invoke-RestMethod "$SocUrl/api/knowledge/chunk?id=$ChunkIdUrl"
    $Chunk.metadata | ConvertTo-Json -Depth 8
    $Chunk.text
}
```

Tìm kiếm nội dung ở API này phân biệt hoa/thường và không gọi model. `total_indexed` là số **chunk**, không phải số file nguồn. Có file trong `rag/documents` chưa chứng minh nó đã được ingest. Model embedding chưa được nạp (`available=null`) không tự có nghĩa RAG hỏng; cần xem `initialized` và `error`.

**THAY ĐỔI dữ liệu — chỉ chạy khi cài lần đầu hoặc chủ động nạp lại Knowledge:**

```powershell
docker compose @ComposeArgs exec soc-ai-app python -m rag.ingest
```

Ingest có thể xây lại collection; sao lưu kho tri thức và chọn lúc không có điều tra AI đang dùng RAG. Không dùng lệnh này chỉ để xem tài liệu hoặc mỗi lần `git pull`.

## 13. SQLite và DB Browser

### 13.1. Xác định database thực tế, bảng và số bản ghi — XEM

Không mặc định mọi máy đều dùng `data/soc_runtime.sqlite3` trên Windows. Máy có override có thể lưu database ở volume riêng. Khối sau đọc biến runtime **bên trong container** và mở SQLite bằng `mode=ro`, tránh vô tình tạo database rỗng.

```powershell
@'
from pathlib import Path
import os, sqlite3
path = Path(os.environ["RUNTIME_DB_PATH"])
print("Runtime database:", path)
print("Exists:", path.is_file())
with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=15) as db:
    print("Tables:", [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")])
    for table in ("events", "zeek_logs", "log_index", "cases", "ai_jobs"):
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            print(table, db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    print("AI queue:", db.execute("SELECT state,COUNT(*) FROM ai_jobs GROUP BY state").fetchall())
'@ | docker compose @ComposeArgs exec -T soc-ai-app python -
```

`log_index` là chỉ mục truy vấn chung; không cộng số bản ghi của nó với `events`/`zeek_logs` để tính tổng log.

### 13.2. Xuất bản sao nhất quán để xem — THAY ĐỔI: tạo file backup

Khối này dùng SQLite Backup API, không xóa dữ liệu. Nó xuất database log và, nếu có, audit/checkpoint AI sang `/app/data/exports`, tương ứng `data\exports` trên Windows theo Compose hiện tại. Mỗi database có một bản sao nhất quán riêng; đây không phải snapshot đồng thời của cả ba database.

```powershell
@'
from pathlib import Path
from datetime import datetime, timezone
import os, sqlite3
runtime = Path(os.environ["RUNTIME_DB_PATH"])
output = Path("/app/data/exports")
output.mkdir(parents=True, exist_ok=True)
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
for name in (runtime.name, "soc_investigations.sqlite3", "soc_checkpoints.sqlite3"):
    source = runtime.with_name(name)
    if not source.is_file():
        continue
    target = output / f"{source.stem}-{stamp}.sqlite3"
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True, timeout=30) as src:
        with sqlite3.connect(target) as dst:
            src.backup(dst)
    print(target)
'@ | docker compose @ComposeArgs exec -T soc-ai-app python -

Get-ChildItem .\data\exports\*.sqlite3 | Sort-Object LastWriteTime -Descending
```

Mở **DB Browser for SQLite → Open Database → chọn bản sao `soc_runtime-…sqlite3` vừa xuất → Browse Data → chọn bảng**. Bản sao không tự cập nhật khi hệ thống nhận log mới; xuất lại khi cần.

Nếu Windows đã liên kết `.sqlite3` với DB Browser, có thể mở bằng:

```powershell
$DatabaseCopy = Get-ChildItem .\data\exports\soc_runtime-*.sqlite3 | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($DatabaseCopy) { Invoke-Item -LiteralPath $DatabaseCopy.FullName }
```

Không chép riêng file SQLite đang ghi bằng `Copy-Item` rồi bỏ qua `-wal`: có thể thiếu giao dịch mới. `data/` bị Git ignore; bản backup có thể chứa thông tin nhạy cảm và không nên đẩy lên GitHub.

## 14. Cổng mạng và kết nối VM

**XEM:**

```powershell
Get-NetIPConfiguration
Get-NetTCPConnection -State Listen | Where-Object LocalPort -In 8100,1514,1515
Test-NetConnection 127.0.0.1 -Port 8100
Test-NetConnection 127.0.0.1 -Port 1514
Test-NetConnection 127.0.0.1 -Port 1515

# Đổi địa chỉ theo máy victim thực tế.
Test-Connection -ComputerName 192.168.19.129 -Count 4
```

8100 là giao diện/API; 1514 là nhận sự kiện Agent; 1515 là đăng ký Agent. Kiểm tra từ Windows không thay thế kiểm tra đường mạng từ VM đến Manager. Ping thành công không chứng minh Wazuh enrollment hay luồng log hoạt động, và không tự sinh cảnh báo tấn công.

**XEM — tìm tiến trình đang giữ cổng 8100 khi gặp WinError 10048:**

```powershell
$Listeners = Get-NetTCPConnection -LocalPort 8100 -State Listen -ErrorAction SilentlyContinue
$Listeners | Select-Object LocalAddress,LocalPort,OwningProcess
$Listeners | ForEach-Object { Get-Process -Id $_.OwningProcess }
```

Không dừng tiến trình chỉ vì nó đang giữ cổng. Nếu app Docker đã chạy, mở giao diện đó; không chạy thêm `python main.py` trên cùng cổng/database.

## 15. Khởi động, cập nhật và dừng

Tất cả các lệnh phần này **THAY ĐỔI trạng thái hệ thống**. Xem `/health` trước khi cập nhật; chọn lúc không có điều tra AI đang chạy.

**Khởi động các dịch vụ bằng image hiện có:**

```powershell
docker compose @ComposeArgs up -d
```

**Cập nhật code và build lại riêng app/giao diện:**

```powershell
git status --short
git pull --ff-only origin main
docker compose @ComposeArgs up -d --build --no-deps soc-ai-app
```

Nếu `git pull` báo xung đột hoặc local changes, xử lý thay đổi của bạn trước; không tự dùng reset để xóa chúng. Giữ `.env`, volume và thư mục dữ liệu. `--no-deps` phù hợp khi các dịch vụ phụ thuộc đã chạy.

**Khi sửa cấu hình `.env` của app:**

```powershell
docker compose @ComposeArgs up -d --no-deps --force-recreate soc-ai-app
```

Nếu sửa biến chỉ dùng cho forwarder thì tạo lại đúng dịch vụ đó:

```powershell
docker compose @ComposeArgs up -d --no-deps --force-recreate wazuh-forwarder
```

`restart` đơn thuần không nạp lại biến môi trường hoặc code đã chép vào image.

**Restart khi không thay image hoặc biến môi trường:**

```powershell
docker compose @ComposeArgs restart soc-ai-app
docker compose @ComposeArgs restart wazuh-forwarder
```

**Dừng mà giữ container và dữ liệu, rồi chạy lại:**

```powershell
docker compose @ComposeArgs stop
docker compose @ComposeArgs start
```

**Sau cập nhật — XEM:**

```powershell
docker compose @ComposeArgs ps -a
Invoke-RestMethod "$SocUrl/health" | ConvertTo-Json -Depth 8
docker compose @ComposeArgs logs --tail 60 soc-ai-app
```

Mở trình duyệt và nhấn **Ctrl + F5** để tải lại frontend. Không dùng `down -v`, `volume prune`, reset database hay xóa model trong quy trình cập nhật thông thường.

## 16. Áp dụng rule Zeek đã sửa

**THAY ĐỔI — chỉ chạy sau khi bạn đã chủ động sửa file rule.** Quy trình này tạo lại Manager, có thể gián đoạn nhận sự kiện trong lúc khởi động. Không xóa các volume chứa Agent keys/log.

```powershell
# Xem phần đã sửa trước khi áp dụng.
git diff -- docker/wazuh/zeek-notice-rules.xml

# Dockerfile chép bản nguồn vào image; startup cài vào thư mục rule của Manager.
docker compose @ComposeArgs up -d --build --no-deps wazuh-manager

# Xem tình trạng và lỗi nạp rule; chạy lại khi Manager đã khởi động.
docker compose @ComposeArgs ps -a wazuh-manager
docker compose @ComposeArgs logs --tail 100 wazuh-manager
docker compose @ComposeArgs exec wazuh-manager cat /var/ossec/etc/rules/soc-ai-zeek-notice.xml
docker compose @ComposeArgs exec wazuh-manager /var/ossec/bin/wazuh-control status
```

Lệnh `up` trả về không đồng nghĩa Manager đã healthy. Nếu lỗi XML, rule ID hoặc quan hệ rule, sửa nguồn rồi áp dụng lại. Muốn kiểm chứng rule, dùng mục 7.4. Rule mới áp dụng cho sự kiện được xử lý sau khi nạp; không tự phân tích lại toàn bộ log lịch sử.

## 17. Cài đặt lần đầu

**THAY ĐỔI — chỉ dành cho máy chưa thiết lập dự án.** Cần Docker Desktop đang chạy Linux containers và Python 3.12.

```powershell
git clone https://github.com/dinhquanglam26082004/SOC-AI.git
Set-Location .\SOC-AI
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe .\scripts\configure_local.py
```

Sau đó chạy lại **mục 1** với đường dẫn clone thật. Script cấu hình tạo `.env` và file enrollment, giữ secrets hiện có nếu đã có nhưng cũng đặt một số cấu hình model/lab; không chạy tùy tiện trên hệ thống đã tùy chỉnh.

```powershell
docker compose @ComposeArgs config --quiet
docker compose @ComposeArgs up -d --build
docker compose @ComposeArgs exec ollama ollama pull qwen3:8b

# Chỉ sau khi soc-ai-app đã khởi động và collection chưa được nạp.
docker compose @ComposeArgs exec soc-ai-app python -m rag.ingest
docker compose @ComposeArgs ps -a
```

Clone code chưa làm VM gửi log. Cấu hình Agent + Zeek theo `docs/ubuntu-victim-setup.md`. Không dùng IP hoặc mật khẩu của người khác.

## 18. Tra lỗi theo triệu chứng

| Triệu chứng | Bắt đầu xem ở đâu? |
| --- | --- |
| Không mở được giao diện | `ps -a`, cổng 8100, log `soc-ai-app`, `/health` |
| WinError 10048 | Mục 14; có thể một backend khác đã chạy |
| Manager Up nhưng unhealthy | Log Docker Manager và `/var/ossec/logs/ossec.log` |
| Agent chưa Active | `agent_control -l`, cổng 1514/1515, địa chỉ Manager trong cấu hình Agent |
| Manager có log nhưng SOC chưa có | `archives.json`, `alerts.json`, `/spool/status.json`, log forwarder, `/api/sources/status` |
| Có log nhưng không có alert | Xem decoder/rule/ngưỡng; không phải mọi log đều là cảnh báo |
| Có alert nhưng AI skipped | Xem chính sách AI và `ai_skip_reason` của alert; không đồng nghĩa model hỏng |
| AI queued lâu | `/health`, worker đang sống, số job running, log app/Ollama |
| AI failed | Chi tiết alert, AI activity, log app, model đã tải và Knowledge |
| GPU chưa được dùng | `ollama ps`, `nvidia-smi`, Compose override GPU |
| Knowledge trống/không mở được | `/api/system/status`, `/api/knowledge/chunks`, log app, collection đã ingest chưa |
| DB Browser hiển thị Tables (0) | Có thể mở sai file/rỗng; xác định runtime path và xuất backup theo mục 13 |
| Giao diện chưa đổi sau cập nhật | Pull đúng nhánh, build/tạo lại `soc-ai-app`, Ctrl + F5 |

Tài liệu này lưu lệnh tham khảo; việc thêm file **không tự chạy** các lệnh restart, ingest, kiểm thử rule, tải model hay cập nhật Git/Docker.

# Báo cáo tối ưu truy vấn log — 25/10/2026

## 1. Đo trước/sau

Đo trong Docker app, trên cùng database volume Linux và cùng số dòng: 201
`events`, 67.669 `zeek_logs`, 67.832 sự kiện hợp nhất. Baseline 3 lượt, sau triển
khai 5 lượt; bảng dùng trung vị, đơn vị ms. Không gọi model AI để benchmark.

| Hạng mục | Trước | Sau |
| --- | ---: | ---: |
| `list_logs(limit=100)` toàn hàm | 1246,30 | 35,23 |
| SQL lấy trang, chưa tính tải/parse payload | 436,01 | 0,35 |
| SQL COUNT theo bộ lọc mặc định | 244,00 | 5,89 |
| SQL COUNT total_all | 245,49 | 3,96 |
| SQL DISTINCT log_type | 303,45 | 16,76 |
| `list_events()` | 5,32 | 5,09 |
| `list_zeek_logs()` | 12,94 | 13,89 |
| `queue_stats()` | 0,62 | 0,66 |

`list_logs` nhanh hơn khoảng **35,4 lần**. Hai hàm cuối vốn đã nhẹ; dao động nhỏ
không được coi là cải thiện hay suy giảm có ý nghĩa. `list_events` hiện mặc định
giới hạn 100 dòng; dữ liệu thật chỉ có 19 cảnh báo nên hai lượt vẫn đọc cùng số
cảnh báo. Kết quả trên không phải benchmark tải đồng thời/sustained ingestion.

Trình duyệt: tải dữ liệu và dựng bảng 100 dòng khoảng **224 ms**; tìm IP trong
metadata khoảng **227 ms**. Đây là số đo tại hàm tải bảng, không bao gồm toàn bộ
thời gian mở ứng dụng, font hay mạng WAN. Ảnh: `data/log-query-optimized.png`.

Tìm kiếm metadata trên DB thật: IP phổ biến 75,66 ms, tên Agent 56,40 ms,
từ khóa không tồn tại 171,89 ms (trung vị 3 lượt toàn hàm).
Đo riêng COUNT từ khóa 5 lượt: 30,18 / 27,31 / 37,02 ms, đều dưới 50 ms.

Raw artifacts (local, ignored by Git):

- `data/bench-before.json`: baseline + EXPLAIN 4 truy vấn.
- `data/bench-after.json`: kết quả trên database thật sau triển khai.
- `data/bench-isolated-linux-after.json`: so sánh toàn bộ phân trang trên bản sao.

## 2. Xác nhận nguyên nhân và EXPLAIN

Trước: CTE UNION chạy bốn lần, `SCAN e`, `SCAN z`, `SCAN unified`,
`USE TEMP B-TREE FOR ORDER BY` và DISTINCT. Các truy vấn metadata chiếm phần lớn
thời gian; payload chỉ tải theo trang nhưng bước chọn trang vẫn phải hợp nhất.

Sau, trang mặc định:

```text
SCAN log_index USING INDEX log_index_time
```

Đây là đọc index theo thứ tự để lấy 101 dòng, không phải quét payload `events`.
Không còn `SCAN events` hay `TEMP B-TREE` trong truy vấn lấy trang. Kiểm thử cũng
kiểm tra các tổ hợp origin/type/kind thông dụng. Các truy vấn đếm/loại chỉ đọc
metadata/index; tìm từ khóa có thể quét metadata nhỏ khi từ khóa hiếm.

Các nơi gọi trước tối ưu:

| Caller | Trước | Sau |
| --- | --- | --- |
| `/api/logs` → `list_logs` | CTE 4 lần/request | Chỉ mục + payload trang |
| LogsWorkspace.load | Tối đa 10 × 500 dòng; lọc q/thời gian trong browser | Một request, đúng 25/50/100; server lọc |
| Nav log counter | `/api/logs?limit=1` mỗi khoảng 15 giây | Dùng log_total trong status nhẹ |
| `/api/alerts` → `list_events` | Tải/parse toàn bộ cảnh báo | limit/before, metrics aggregate riêng |
| `/api/alerts/timeseries` | `list_events()` full payload | Chỉ chiếu created_at/timestamp/severity |
| `/api/sources/status` | `list_events` + `list_zeek_logs` | `log_stats` + trạng thái AI gọn |
| refreshAll timer | Nhiều API đầy đủ mỗi 3 giây | Poll status 12 giây, dừng khi tab ẩn |

Nạp danh sách đầy đủ chỉ khi mở view, bấm Refresh hoặc có cảnh báo mới. Tiến độ
AI nhận cập nhật nhẹ; trạng thái thay đổi sẽ tải chi tiết cảnh báo tương ứng.
Trang Logs dùng Latest/Refresh/bộ lọc để tải dữ liệu, không liên tục tải lại toàn
bộ danh sách khi đang xem. Alerts có nút **Load older alerts**.

## 3. Các file thay đổi

| File | Lý do |
| --- | --- |
| `common/log_index.py` | Schema/index additive, backup, backfill, chuẩn hóa UTC, metadata search |
| `common/event_store.py` | Cập nhật index cùng giao dịch; truy vấn có phân trang; summary nhẹ; ai_jobs_state |
| `api/app.py` | since/until/q, phân trang cảnh báo, endpoint status không tải payload log |
| `web/index.html` | Bỏ scan 10×500, server filters, poll nhẹ 12 giây, dừng khi ẩn, tải thêm cảnh báo |
| `scripts/bench_logs.py` | Benchmark, EXPLAIN, backup, WAL và so sánh toàn bộ dữ liệu |
| `tests/test_log_queries.py` | Tương đương, cursor, migration, filter, upgrade, rollback và query plan |
| `scripts/reset_runtime.py` | Khi người dùng chủ động reset thì phải xóa metadata cùng dữ liệu, tránh index mồ côi; **không chạy reset** |
| `.dockerignore` | Loại data/ và DB benchmark khỏi Docker build context/image |
| `docs/log-query-performance.md` | Báo cáo này |

Không thay đổi bảng cũ hay logic claim/finish/retry. Dữ liệu nguồn không bị xóa
hoặc viết lại. Chuẩn hóa chỉ nằm trong log_index.

## 4. Quyết định triển khai

- **Metadata thay FTS5:** `search_text` chỉ gồm log_type, Agent/name/IP,
  source/destination IP, username, rule description, HTTP host, DNS query, TLS
  server name. Casefold và AND giữa các từ. Không tìm mọi trường/raw payload;
  không dùng `LIKE '%...%'` trên payload. IP/hostname giữ tìm chuỗi con.
- **Không cache số đếm:** mọi truy vấn COUNT/DISTINCT đo được dưới 50 ms,
  kể cả COUNT có q. Giữ totals chính xác trong cùng read transaction, không có
  vấn đề invalidation/stale cache khi có dữ liệu mới.
- **Index thêm theo bộ lọc:** time, origin/type/kind, origin/time,
  origin/type/time, origin/kind/time, type/time, kind/time; có id làm khóa phụ
  để thứ tự ổn định. `ai_jobs_state` chỉ tăng tốc tra cứu, không đổi chính sách AI.
- **UTC cố định:** `YYYY-MM-DDTHH:MM:SS.ffffffZ` trong metadata; timestamp cũ
  `+00:00` hoặc offset khác được đổi theo thời gian thực. Cursor vẫn base64
  `[received_at,id]`, chấp nhận cursor cũ có timezone và báo 400 nếu sai.
- Backfill giữ CTE gốc để xác định origin/type/kind và khử trùng; payload ưu tiên
  events. Ngày rỗng trong dữ liệu rất cũ dùng mốc UTC năm 1, ngày không rỗng nhưng
  không hợp lệ làm migration rollback thay vì âm thầm bỏ log. Việc sửa thứ tự
  timestamp sai định dạng có thể thay thứ tự lexical cũ; dataset thật đã so sánh
  và giữ đúng cả thứ tự cũ lẫn thứ tự UTC.
- Migration marker `log_index_v1`, giao dịch atomic, chạy lại không nhân đôi;
  backup bằng SQLite backup API trước khi thay đổi schema trên DB có sẵn.

Backup trước migration trên Windows:

```text
E:\Pictures\SOC-AI\data\backups\before-log-index-2026-10-25.sqlite3
```

Startup cũng giữ backup trong Docker runtime volume:
`/app/runtime/backups/pre-log-index-20261024T171856263768.sqlite3`
(tên chứa giờ UTC; tương ứng ngày 25/10 tại Việt Nam).

## 5. Kiểm thử và đồng bộ/async

**38 passed**: bộ log query mới, pipeline Wazuh và alert timeseries hiện có.
Kiểm tra ID/thứ tự/tổng/type, nhiều trang không trùng/sót, payload alert mới nhất,
archive nâng cấp, since/until/q, cursor cũ/sai, migration hai lần, timestamp cũ,
queue đầy rollback source/index cùng nhau. JavaScript qua `node --check`.
So sánh toàn bộ **67.832 sự kiện** trên bản sao dữ liệu thật cũng đạt.

API đọc DB là `def` đồng bộ, được FastAPI chạy threadpool. Webhook `async def`
đã gọi `store.accept` qua `asyncio.to_thread`; worker cũng dùng to_thread.
Startup vẫn tạo EventStore/backfill đồng bộ trong lifespan: chỉ chặn startup,
không chặn request đang phục vụ. Với DB lớn hơn nên chạy migration ở maintenance
window hoặc chuyển khởi tạo sang thread và vẫn chờ hoàn tất trước khi nhận traffic.

## 6. WAL, dung lượng và quyết định còn lại

- File DB: **286,88 → 415,80 MiB**, tăng khoảng **128,92 MiB** do metadata/index.
- WAL trước/sau đo: **0 byte**; `wal_autocheckpoint=1000` trang.
- `PRAGMA wal_checkpoint(PASSIVE)` trước/sau: `(0,0,0)`; không ép TRUNCATE.
- **Giữ synchronous=FULL.** Trong DB tạm trên cùng volume, 20 giao dịch ghi 4 KiB:
  trước 2,18 ms/giao dịch (commit 2,12 ms), sau 2,33 ms (commit 2,28 ms).
  Commit chiếm khoảng 97–98% mẫu này. Đây không phải benchmark tốc độ ingest
  thực tế có HTTP/index/AI hay so sánh FULL với NORMAL.
- Chưa thay đổi retention, batch ingestion, mức đồng bộ hoặc cấu hình AI.
- Cần người dùng quyết định sau: retention/loại telemetry cần giữ và có chấp nhận
  thay đổi độ bền ghi để đánh giá NORMAL hay không. Không tự chuyển NORMAL.
- Từ khóa hiếm vẫn quét metadata; khi dữ liệu tăng nhiều cần cân nhắc FTS5,
  index search chuyên biệt hoặc cache có invalidation được đo và kiểm thử riêng.
- Các tab mở trước triển khai còn JS cũ: **Ctrl+F5 tất cả tab SOC-AI** để dừng
  vòng poll/scan cũ. Code chưa tự đẩy GitHub trong tác vụ này.

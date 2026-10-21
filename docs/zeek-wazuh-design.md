# Thiết kế thu thập Zeek và Wazuh trên Ubuntu victim

Đã triển khai phương án thu toàn bộ log qua Wazuh Agent: xem
[Thu toàn bộ log Zeek](zeek-notice-alerts.md). Backend có bảng zeek_logs,
API /api/zeek/logs và mục Zeek Logs. Notice vẫn nằm trong Alerts.

Thiết kế collector độc lập/HTTPS riêng dưới đây là phương án mở rộng,
chưa triển khai và không cần thiết cho luồng Wazuh hiện tại.

## 1. Phạm vi và sơ đồ

Lab hiện tại: Windows host 192.168.19.1, Ubuntu victim 192.168.19.129.
Địa chỉ phải cấu hình được, không dùng IP làm danh tính thiết bị cố định.

```text
Máy khác ── lưu lượng mạng ──> Ubuntu victim
                               ├─ Zeek đọc NIC của victim
                               │   → JSONL → collector + SQLite spool
                               │   → HTTPS ingestion → SOC-AI /api/ingest/zeek
                               └─ Wazuh Agent → TCP 1514 → Wazuh Manager
                                   → forwarder → SOC-AI /wazuh
SOC-AI → kho sự kiện → quy tắc phát hiện → cảnh báo → hàng đợi AI
       → liên kết bằng chứng hai nguồn → báo cáo được kiểm tra → đề xuất phản ứng
```

Zeek ở victim thấy lưu lượng đi qua NIC đó; không tự thấy mọi máy trên VMnet8.
Giám sát toàn mạng cần sensor riêng và mirror/SPAN/TAP. Không cần promiscuous mode
để quan sát lưu lượng gửi/nhận của chính victim. Lưu lượng loopback cần điểm thu riêng.
Zeek trên victim cũng có thể bị gián đoạn nếu victim bị kiểm soát: cần heartbeat,
nhưng không dùng heartbeat collector để suy ra packet capture vẫn hoạt động.

## 2. Cảm biến Zeek

- Xác định NIC thật bằng `ip -br addr`; không mặc định `eth0` hoặc `ens33`.
- Cấu hình standalone qua ZeekControl; chọn subnet local và phiên bản cố định khi triển khai.
- Ghi JSONL thay vì TSV: `@load policy/tuning/json-logs` trong local.zeek.
- Tách quyền: Zeek có quyền capture cần thiết; collector chỉ đọc log và ghi spool.
- Thu conn, dns, http, ssl và notice trước; bổ sung ssh, weird khi có nhu cầu.
- Đường dẫn log lấy từ cấu hình ZeekControl, không giả định prefix /opt/zeek luôn đúng.
- Theo dõi capture drops, tiến trình, thời điểm dòng log cuối và dung lượng đĩa riêng.
- Kiểm tra checksum offloading khi chỉ thấy một chiều. Chỉ dùng -C trong lab sau khi
  xác định nguyên nhân; ghi nhận việc bỏ kiểm tra checksum trong cấu hình sensor.

SSH/TLS mã hóa: Zeek không tự đọc mật khẩu SSH hoặc nội dung HTTPS.
Không suy ra SSH đăng nhập thành công chỉ từ kết nối TCP. HTTP/3/QUIC không được
coi là đã quan sát đầy đủ chỉ vì có bộ phân tích TLS/TCP.

## 3. Collector trên victim

Một dịch vụ systemd đọc các file JSONL được cho phép, không nhận đường dẫn tùy ý
từ request. Mỗi dòng hoàn chỉnh trở thành một event envelope.

Các trường: schema_version, sensor_id, sensor_boot_id, asset_id, log_type,
event_id, observed_at, collected_at, raw_event. Server bổ sung received_at.
Giữ nguyên tên trường Zeek và dữ liệu gốc; trường chuẩn hóa gồm orig/resp IP,
port, protocol, uid và hướng lưu lượng theo cấu hình subnet.

Không dùng UID một mình làm event_id: nhiều loại log và nhiều bản ghi cùng UID.
Sinh ID ổn định từ sensor_id + file generation + byte offset + hash dòng gốc.
Theo dõi file generation qua định danh file, fingerprint và trạng thái rotation;
không chỉ dựa inode vì inode có thể tái sử dụng.

Transaction SQLite phải ghi spool và checkpoint cùng lúc, rồi mới đọc tiếp.
Dòng chưa kết thúc giữ lại tới lần đọc sau. Rotation tiếp tục đọc file cũ tới EOF,
rồi đọc file mới; phát hiện truncate và báo khoảng dữ liệu có thể mất.
Restart đọc lại an toàn nhờ ID ổn định và dedup ở server.

Gửi theo batch giới hạn số dòng và byte. ACK chỉ sau khi server commit bền vững.
503/429/network error retry có backoff và jitter; 401/403 báo cấu hình và giữ dữ liệu;
422 đưa dòng không hợp lệ vào DLQ có metadata. Không retry vô hạn payload lỗi.
Spool đầy phải báo mất khả năng thu nhận và giữ file nguồn trong retention;
không tuyên bố giao nhận không mất dữ liệu khi file nguồn đã bị rotation xóa.

Đề xuất lab ban đầu: batch 100 dòng, tối đa 1 MiB, flush 2 giây; các giá trị cần đo
và chỉnh theo tài nguyên. Không tự xóa log chưa đọc để giải phóng spool.

## 4. Tiếp nhận trên máy chính

Endpoint mới dự kiến: `POST /api/ingest/zeek`. Không gửi JSON Zeek vào `/wazuh`
và không tạo rule Wazuh giả để vượt qua mapper hiện có.

Dashboard hiện chỉ bind localhost:8100 nên victim không thể dùng địa chỉ này.
Thiết kế thêm HTTPS reverse proxy tại 192.168.19.1:8443, chỉ cho phép đường dẫn
ingest/heartbeat. Giữ dashboard/API quản trị trên localhost. Firewall giới hạn subnet
lab hoặc IP collector. Token riêng theo sensor, không tái sử dụng enrollment password.
Xác minh chứng chỉ TLS, không dùng verify=false. Token gắn sensor_id phía server,
không tin sensor_id do client tự khai. Bí mật không đưa vào log hoặc payload.

Kho telemetry có bảng riêng và retention riêng; không đưa mọi conn.log vào bảng
cảnh báo hoặc ai_jobs. Unique(source,sensor_id,event_id) bảo đảm retry không tạo bản
ghi lặp. Phản hồi nêu accepted/duplicate và ACK rõ từng dòng khi chấp nhận một phần.

## 5. Phát hiện, liên kết và điều tra AI

- Ping bình thường: hiển thị ở Network Events với protocol ICMP, không tạo incident.
  conn.log có thể chỉ xuất hiện sau timeout/đóng flow, không phải từng gói ngay tức thì.
- DNS/HTTP/TLS bình thường: lưu làm ngữ cảnh, không tự gọi AI từng dòng.
- notice.log: ứng viên cảnh báo theo loại notice và chính sách, không đồng nhất mọi
  notice với tấn công đã xác nhận.
- Quét cổng: detector có phiên bản, cửa sổ thời gian, số đích/cổng và danh sách loại trừ;
  ngưỡng là tham số lab cần đánh giá, không hard-code thành kết luận tấn công.
- SSH: Wazuh cung cấp bằng chứng xác thực; Zeek cung cấp thông tin phiên kết nối.
- Liên kết theo asset_id, địa chỉ tại thời điểm sự kiện, protocol/port, thời gian UTC
  và độ lệch đồng hồ. Zeek UID chỉ liên kết trong nguồn Zeek, không có UID chung với Wazuh.
- NAT có thể đổi IP nguồn; liên kết không rõ phải ghi chưa xác minh, không đoán thủ phạm.

AI chỉ nhận evidence bundle giới hạn có cấu trúc, không cắt chuỗi JSON làm mất
result của SCA. RAG lọc hệ điều hành, loại sự kiện và tài liệu đạt tiêu chí liên quan.
Đưa SCA sang luồng compliance; ưu tiên sự cố xác thực và phát hiện mạng có căn cứ.
Chặn báo cáo mâu thuẫn dữ liệu xác định; giữ trạng thái sinh báo cáo và xác minh riêng.
Không tuyên bố bộ kiểm tra tự động có thể bảo đảm mọi câu văn AI đều đúng.
Playbook chỉ là đề xuất; hệ thống hiện chưa có adapter thực thi.

## 6. Dashboard cần bổ sung

1. Network Events: bộ lọc nguồn, sensor, protocol, IP, log_type, thời gian; dữ liệu gốc.
2. Alerts: chỉ các phát hiện, hiển thị detector/rule thật và evidence IDs.
3. Investigations: selected evidence, suy luận, điều chưa biết, citations, trạng thái
   queued/running/completed/failed và verification riêng.
4. Response: proposed/approved/executed/failed; chỉ hiện executed khi có kết quả adapter.
5. Source Health: Zeek capture, collector heartbeat, last event, spool/DLQ, drops;
   không gộp backend online thành mọi nguồn đều đang hoạt động.

## 7. Các phần cần triển khai trong repository

- `zeek_integration/`: collector, checkpoint/spool, mapper, schema và config mẫu.
- `api/app.py`: thêm ingestion có xác thực và truy vấn telemetry có phân trang.
- `common/`: kho telemetry, detector và correlation; migration bổ sung có backup.
- `agents/`: evidence bundle và kiểm tra mâu thuẫn, playbook theo loại sự kiện.
- `web/index.html`: Network Events, nguồn dữ liệu, trạng thái xác minh báo cáo.
- `docker-compose.yml`: ingress proxy và cấu hình secret sensor.

Ưu tiên sửa độ tin cậy báo cáo AI song song với thu thập. Lộ trình: thu và lưu đúng
→ hiển thị telemetry → detector/liên kết → AI có kiểm tra → adapter phản ứng sau.
Không phục hồi các fixture/demo Zeek cũ để làm dữ liệu live.

## 8. Tiêu chí nghiệm thu đề xuất (chưa thực hiện)

Ping từ Windows xuất hiện là telemetry ICMP; HTTP lab xuất hiện với endpoint đúng;
SSH thất bại có bằng chứng Wazuh và ngữ cảnh Zeek nếu capture quan sát được.
Thử restart/rotation/network outage không tạo bản ghi lặp; overflow/drop phải hiển thị.
Kiểm tra token sai và sensor giả bị từ chối. SCA failed không được thành compliant.
Kiểm tra lưu lượng ingestion không gây vòng lặp sinh alert; chỉ có một sensor cho NIC
trong lab ban đầu và có chính sách nhận diện lưu lượng quản trị.

## Tài liệu chính thức

- https://docs.zeek.org/en/current/quickstart.html
- https://docs.zeek.org/en/current/tutorial/invoking-zeekctl.html
- https://docs.zeek.org/en/current/tutorial/logs.html
- https://docs.zeek.org/en/current/reference/logs/conn.html

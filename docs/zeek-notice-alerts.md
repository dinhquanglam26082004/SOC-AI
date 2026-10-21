# Thu toàn bộ log Zeek qua Wazuh

Giao diện hiện gộp Zeek và Wazuh tại **Logs · Zeek + Wazuh**; hướng dẫn API và
lọc dữ liệu xem [Logs chung](unified-logs.md). Các mô tả Zeek Logs phía dưới nói
về nguồn dữ liệu Zeek, không còn là một màn hình riêng.

Phạm vi cập nhật: thu mọi dòng trong `/opt/zeek/logs/current/*.log`, gồm conn,
dns, http, ssl, notice, weird, stats và log vận hành khác đang được Zeek sinh.
Không chỉ notice.log. Không thu PCAP, file nhị phân hoặc file .gz lịch sử bằng wildcard này.
Không thể bảo đảm không mất dòng trong mọi tình huống: Wazuh có giới hạn độ dài dòng,
hàng đợi, EPS và số file; rotation khi Agent dừng hoặc đĩa đầy cần đối chiếu nguồn.

## Cấu hình đã áp dụng cho lab hiện tại

Manager đã nhận cấu hình tập trung từ `docker/wazuh/zeek-all-agent.conf`, chỉ áp dụng
cho Agent có tên chính xác `ubuntu-agent`. File được kiểm tra bằng verify-agent-conf
trước khi thay agent.conf; bản cũ được backup trong /var/ossec/backup. Cấu hình shared
nằm trong volume wazuh_etc nên tồn tại qua recreate. Agent tự nhận và reload khi đồng bộ.
Không thêm block local lần nữa nếu cấu hình tập trung đã có hiệu lực.
Nếu đã thêm riêng notice.log ở local, bỏ block đó để tránh trùng phạm vi theo dõi.

Các bước dưới đây dùng cho cài đặt khác hoặc khi Agent không nhận remote config.

## Trên Ubuntu victim

Trong `/var/ossec/etc/ossec.conf`, thay localfile Zeek notice.log cũ bằng block
sau, đặt bên trong ossec_config. Không giữ cả block notice riêng và wildcard để
tránh thu trùng cùng file. Không xóa localfile của auth.log hoặc nguồn khác.

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/*.log</location>
  <only-future-events>no</only-future-events>
</localfile>
```

syslog ở đây là chế độ đọc từng dòng, nhận cả JSON và text startup/stderr. Wazuh
vẫn tự giải mã dòng JSON; Zeek nên giữ `@load policy/tuning/json-logs` để có trường
mạng có cấu trúc. Các dòng không giải mã được vẫn giữ trong full_log. Không có
trường hợp lệ thì không đoán IP, cổng hoặc thời gian nguồn.

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 60 /var/ossec/logs/ossec.log
```

Agent cần quyền đọc file hiện tại và file mới sau rotation; không chmod 777.
Wazuh quét lại wildcard khi file mới xuất hiện nên có thể có độ trễ phát hiện file.
`only-future-events=no` cho phép đọc nội dung hiện có theo checkpoint và giới hạn
đọc của Agent, không tự nhập mọi file archive cũ. Mặc định giới hạn đọc bù max-size
của Wazuh là 10MB; đây không phải cam kết backfill toàn bộ lịch sử.

## Luồng trên máy chính

Zeek → Wazuh Agent → Manager → integration/spool SQLite → forwarder → POST /wazuh
→ bảng zeek_logs. Notice đồng thời vào bảng events/Alerts; log thường không vào AI.

Rule 100121 level 3 chỉ là envelope truyền tải để integration Wazuh nhận được
mọi dòng, KHÔNG phải detector tấn công. Vì Wazuh dùng alert pipeline để chuyển tiếp,
Manager alerts.json cũng chứa các record truyền tải này; SOC-AI tách chúng khỏi Alerts.
Rule con 100120 level 5 nhận note namespace::type trong notice.log. Level là mức quy
ước Wazuh, không phải Zeek gán severity. Không tự coi mọi notice là tấn công đã xác nhận.

source nội bộ là wazuh, source_product là zeek, transport là wazuh. Giữ Agent,
location, full_log, decoded data và timestamp nguồn nếu được Zeek cung cấp. Rule
telemetry bỏ qua bộ lọc forward level/group để yêu cầu thu mọi log không bị lọc ngầm;
custom integration phải giữ level 3 như cấu hình repository. Không bật AI cho từng log.

Trước khi áp dụng database migration nên backup bằng SQLite backup API. Dữ liệu
cũ không bị xóa; zeek_logs là bảng bổ sung. Chỉ các notice mới tiếp nhận được lưu ở
cả hai kho, không tự tạo lại log Zeek lịch sử từ dữ liệu demo.

```powershell
cd E:\Pictures\SOC-AI
docker compose --profile app build wazuh-manager soc-ai-app wazuh-forwarder
docker compose --profile app up -d --no-deps --wait wazuh-manager soc-ai-app wazuh-forwarder
```

## Giao diện và API

- Zeek Logs: tất cả dòng đã nhận, lọc loại file, phân trang cursor, nội dung gốc.
- Alerts: notice và cảnh báo Wazuh; telemetry không làm tăng số cảnh báo.
- GET /api/zeek/logs?limit=100&log_type=conn: dữ liệu và next_cursor.
- GET /api/zeek/logs?limit=100&before=123: trang cũ hơn theo cursor.
- GET /api/sources/status: zeek.total, log_types, last_received_at. Last received
  không chứng minh sensor vẫn chạy hoặc packet capture đầy đủ.

Khả năng thu thập chỉ được xác nhận sau khi Agent thực sự đọc wildcard và có
log từ victim đến kho. Container healthy không chứng minh đầu cuối thành công.
Kiểm tra số dòng theo từng file, quyền đọc, logcollector errors, dropped events,
spool pending/dead-letter và dung lượng ổ đĩa. Không xóa log nguồn chưa đối chiếu.
Wazuh không bảo đảm retry callback integration; cần import lại alerts.json còn giữ
nếu spool từng đầy. Không tự xóa telemetry vì có thể mất bằng chứng; phải cấu hình
retention/archival phù hợp dung lượng trước khi tăng lưu lượng.

## Tài liệu

- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- https://docs.zeek.org/en/current/tutorial/logs.html

## Ghi nhận triển khai ngày 21/10/2026

Các container đã khởi động healthy. Agent ubuntu-agent thuộc nhóm default đã nhận
cấu hình tập trung; kho SOC-AI đã nhận log thật thuộc conn, dns, telemetry và weird.
API Zeek trả HTTP 200. Đây là xác nhận bước đầu trên dữ liệu thật, chưa phải đối
chiếu không mất dòng của mọi file, mọi lần rotation hoặc log lịch sử.

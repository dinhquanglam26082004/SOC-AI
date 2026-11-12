# AI chỉ điều tra cảnh báo bảo mật

AI dùng Qwen3-8B. Ba lớp chặn được áp dụng ở ingestion, thao tác điều tra thủ công
và worker. Trạng thái ai_allowed được xác định từ quy tắc nguồn, không do mô hình
tự đánh giá trước khi chạy.

Không gọi model cho:

- Log thường Zeek, bao gồm telemetry, conn/dns/http/statistics.
- Notice chất lượng capture: CaptureLoss và ChecksumOffloading.
- SCA compliance, inventory và dpkg/package management.
- Xoay vòng log (rule 591), phiên PAM bình thường (5501/5502), sudo thành công (5402).

Các sự kiện này vẫn có trong Logs, event_kind=telemetry, không nằm trong Alerts
hoặc Investigations. Không thể dùng nút retry để vượt qua chính sách.

Cảnh báo đủ điều kiện: các nhóm xác thực thất bại, invalid_login, FIM/syscheck,
rootcheck, malware, dấu hiệu tấn công hoặc notice Zeek không thuộc nhóm vận hành.
Wazuh rule mức từ 7 trở lên cũng có thể là cảnh báo sau khi loại trừ nhóm vận hành.
Quy tắc xác định cảnh báo nằm trong is_security_alert ở wazuh_integration/mapper.py.
Cấu hình WAZUH_AI_RULE_ALLOWLIST có thể bổ sung rule chưa nhận diện; không vượt qua
chặn log thường hoặc nhóm vận hành. Không dùng mức cảnh báo làm bằng chứng tấn công.

Sau bước phân loại, AI tự động chỉ điều tra cảnh báo đạt WAZUH_AI_MIN_LEVEL
(mặc định 7), sau khi áp dụng các điều kiện loại trừ khác. Nhóm syscheck và
rule allowlist không vượt ngưỡng tự động. Cảnh báo mức thấp chưa tự điều tra
vẫn có thể được xếp hàng thủ công nếu ai_allowed=true. Rule allowlist chỉ ảnh
hưởng bước nhận diện cảnh báo đủ điều kiện điều tra thủ công, không tự xếp hàng.

## Dọn dữ liệu vận hành

Ngừng các bên ghi dữ liệu rồi dùng scripts/reset_runtime.py --confirm để tạo backup
và dọn events, zeek_logs, ai_jobs, cases, runtime_state. Giữ marker migration để không
khôi phục dữ liệu demo cũ. Lưu reset_before để bỏ qua event nguồn có thời gian trước
lần dọn nếu forwarder gửi lại. Receipt ignored=true nghĩa là áp dụng chính sách dọn,
không phải một log mới đã được thêm vào kho. Xóa cả hàng đợi spool cũ trong đợt dọn
nếu muốn tránh gửi lại backlog, chỉ sau khi dừng Manager/forwarder và backup spool.

Không dùng docker compose down -v; lệnh đó xóa cả Agent keys/model. Không xóa kho RAG
để dọn cảnh báo. Backup nằm data/backups và volume spool; không đưa lên GitHub.
Log gốc ở victim và Manager vẫn được giữ; việc này dọn dữ liệu hiển thị trong SOC-AI.
Các file archive nguồn không được tự import lại sau reset. Agent mới/Manager phải đồng
bộ thời gian; cutoff không thay thế kiểm tra lệch đồng hồ.

Sau khi khởi động lại, các log mới có thể xuất hiện ngay vì thu thập vẫn chạy.
AI sẽ không chạy chỉ vì Logs có dữ liệu mới.
# Grouping repeated DoS investigations

Automatic queueing groups retained Zeek rule 100142 alerts by agent, rule,
source, destination and destination port when the event times are within
five minutes of an existing queued, running or completed investigation. Rule
100145 is grouped by agent, rule, destination and port, without source IP.
Each alert and its log is retained; grouped alerts show the representative
investigation and can be queued manually. Failed representative jobs do not
suppress the next alert. Missing required fields prevent grouping. Grouping is
anchored to an investigated alert, not a sliding attack-duration detector;
a long incident can therefore generate another investigation after five minutes.
This is a noise-control policy, not a determination that alerts are the same
attack. Historical alerts and existing queued jobs are not changed.


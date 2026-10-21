# Logs chung cho Zeek và Wazuh

Mục **Logs · Zeek + Wazuh** thay cho màn hình Zeek Logs riêng. Đây là một dòng
thời gian chung, sắp xếp theo thời điểm SOC-AI nhận sự kiện, mới nhất trước.

- Zeek: toàn bộ log đã nhận từ các file `.log` trên victim.
- Wazuh: các cảnh báo/sự kiện Wazuh đã chuyển tới SOC-AI; không phải mọi log hệ
  điều hành thô. Phạm vi thu thập Agent không thay đổi bởi việc gộp màn hình.
- Bộ lọc nguồn Zeek/Wazuh, loại log/file và cảnh báo/log thường.
- Chọn dòng để xem dữ liệu gốc; cảnh báo có nút mở điều tra AI.
- Zeek notice có trong cả zeek_logs và events chỉ hiện một lần theo ID nguồn.
  Bản ghi hợp nhất lấy báo cáo và trạng thái AI mới nhất từ events.
- Không gộp các sự kiện khác nhau chỉ vì cùng IP hoặc thời điểm. Không dùng dữ liệu
  demo/historical cũ làm log Wazuh live trong màn hình này.

## API

`GET /api/logs?limit=100&source=wazuh&kind=alert`

Tham số:

| Tham số | Ý nghĩa |
| --- | --- |
| limit | 1–500, mặc định 100 |
| source | zeek hoặc wazuh; bỏ trống lấy cả hai |
| log_type | Loại log Zeek hoặc location Wazuh đã ghi nhận |
| kind | alert hoặc telemetry |
| before | Cursor từ next_cursor của trang trước |

Response gồm logs, next_cursor, total (khớp bộ lọc), total_all (toàn bộ sau dedup)
và log_types. Mỗi log có log_origin, log_type, event_kind và payload gốc. Timestamp
nguồn vẫn được giữ trong record; dùng received_at để sắp xếp chung, tránh suy luận
thứ tự hành vi khi các máy có đồng hồ lệch nhau. Cursor dựa trên received_at + id,
giúp các trang cũ không bị dịch chuyển khi log mới đến.

API /api/zeek/logs vẫn được giữ cho client đang dùng; giao diện chính chuyển sang
/api/logs. Kho hiện có không bị xóa hoặc sao chép lại; câu truy vấn hợp nhất hai kho
và loại bản ghi trùng. Log thường không tự tạo ai_jobs hoặc tăng số Alerts.

Không cần sửa Wazuh Agent hay cấu hình Zeek trên victim để dùng màn hình gộp.

# Công cụ điều tra của SOC-AI

Mỗi mô tả trong `agents/investigation_tools.py` cho model biết công cụ đọc dữ liệu gì,
khi nào hữu ích, ví dụ rule liên quan và giới hạn cần lưu ý. Các rule trong bảng dưới
đây là **ví dụ**, không phải danh sách bắt buộc: AI vẫn tự chọn công cụ theo cảnh báo
và câu hỏi cần xác minh. Việc chọn đúng chưa được đảm bảo chỉ nhờ mô tả.

Hiện có **16 công cụ được định nghĩa**. Hệ thống tự gọi `get_alert` khi bắt đầu;
15 công cụ còn lại được đưa vào danh sách model có thể chọn. Với rule `100142`,
hệ thống còn thử gọi `summarize_zeek_flows` ngay ở bước đầu khi có đủ tham số.

## Công cụ theo loại bằng chứng

| Công cụ | Khi nào dùng; ví dụ rule | Dữ liệu và giới hạn |
| --- | --- | --- |
| `get_alert` | Bắt đầu điều tra mọi cảnh báo. | Đọc cảnh báo gốc của chính cuộc điều tra: rule, agent, thời gian và trường đã ghi nhận. Hệ thống tự gọi; model không chọn trong danh sách mặc định. |
| `search_auth_events` | Sai mật khẩu hoặc nghi SSH brute force; ví dụ Wazuh `2502`, Zeek `100172`. | Các sự kiện xác thực thành công/thất bại đã lưu; thống kê theo agent, tài khoản và IP nguồn. Số bản ghi không nhất thiết là số phiên riêng biệt; thành công sau thất bại không tự chứng minh xâm nhập. |
| `search_related_alerts` | Cần tìm cảnh báo khác trên cùng agent trong khoảng điều tra, với bất kỳ rule nào. | Trả các cảnh báo đã lưu; có thể lọc IP trong phạm vi hoặc tên người dùng. Kết quả có thể chứa chính cảnh báo gốc; cùng thời gian chưa chứng minh có quan hệ nhân quả. |
| `search_zeek_connections` | Điều tra kết nối quanh scan (`100141`, `100143`), DoS (`100142`, `100145`) hoặc DNS. | Mẫu Zeek `conn.log` lịch sử như trạng thái, hai đầu kết nối, packet/byte nếu có. Bộ lọc IP khớp một trong hai đầu; tool này không có bộ lọc cổng, không xem socket trực tiếp hay gán PID. |
| `summarize_zeek_flows` | Cần đếm flow TCP hoặc tốc độ trung bình của một nguồn, ví dụ DoS `100142`. | Tổng hợp flow, trạng thái, packet, IP byte, thiếu trường và bản trùng xác định được. IP nguồn, IP đích và cổng đích phải khớp chính xác cảnh báo; không tổng hợp toàn bộ nguồn của DDoS và không chứng minh ảnh hưởng dịch vụ. |
| `search_zeek_http` | Xem request/response liên quan cảnh báo web `100130`–`100134`. | Lọc chính xác host, method, status, UID; `uri_contains` là chuỗi con nguyên văn. Dữ liệu HTTPS có thể không có nội dung; status HTTP không chứng minh khai thác thành công. |
| `search_zeek_dns` | Xem mẫu truy vấn và phản hồi cho DNS bất thường/tunneling, ví dụ `100151`, `100153`, `100156`, `100157`, `100181`. | Lọc `query` theo **toàn bộ tên chính xác**, không phân biệt hoa thường; lọc chính xác `rcode_name` hoặc UID. Không hỗ trợ tìm toàn bộ subdomain bằng query dạng wildcard. |
| `summarize_dns_activity` | Đếm DNS liên quan một domain và các subdomain, ví dụ `100153`, `100156`, `100157`. | Có số bản ghi, tên truy vấn/subdomain khác nhau, loại query, mã phản hồi, độ dài query, số lượng theo phút và tối đa 5 mẫu. Các bản trùng có thể còn; không tự chứng minh tunneling hay truyền dữ liệu. |
| `compare_dns_baseline` | So sánh DNS trong khoảng nghi vấn với khoảng trước đó trong cùng cuộc điều tra. | Hai cửa sổ phải cùng thời lượng, không chồng lấn, baseline nằm trước và cả hai đều trong phạm vi điều tra. Đây không phải baseline nhiều ngày; kết quả rỗng không chứng minh giai đoạn đó thực sự không có DNS. |
| `search_process_events` | Tìm lệnh/tiến trình đã ghi nhận khi điều tra DNS, SSH hoặc thay đổi file. | Chỉ đọc bản ghi Wazuh thuộc nhóm `audit_command` đã được thu thập; không liệt kê tiến trình đang chạy. Không có kết quả cũng có thể do chưa cấu hình hoặc chưa lưu audit. |
| `search_file_access` | Tìm bằng chứng đọc file khi nghi thu thập hoặc truyền dữ liệu. | Chỉ đọc nhóm `audit_watch_read` đã lưu. `file_path` khớp chính xác trường đường dẫn đã giải mã; FIM thay đổi file không phải log đọc file. |
| `search_file_changes` | Xem thay đổi file FIM, ví dụ rule `550`, hoặc tìm file cấu hình/persistence quanh cảnh báo. | Đọc `syscheck`; có thể lọc đường dẫn chính xác. Chỉ gán người hoặc tiến trình nếu bản ghi có thông tin who-data. |
| `search_privilege_events` | Tìm hoạt động `sudo`/`su` quanh sự cố, chẳng hạn sau đăng nhập đáng ngờ. | Đọc sự kiện `sudo`/`su` đã lưu; `actor_user` là `srcuser`, `target_user` là `dstuser`. Yêu cầu hay lần thất bại không chứng minh lệnh đã thực thi. |
| `get_event_details` | Cần xem thêm chi tiết khi tóm tắt bằng chứng của một bản ghi chưa đủ. | Cần `evidence_id` của bản ghi đã được thu thập trong chính cuộc điều tra. Không dùng ID tùy ý, tài liệu hướng dẫn hoặc tổng hợp làm ID bản ghi gốc; chi tiết có thể bị cắt hoặc bản ghi nguồn đã bị xóa. |
| `search_runbook` | Cần tài liệu điều tra hoặc gợi ý phản ứng phù hợp với sự cố. | Tra cứu playbook trong kho tri thức cục bộ. Hướng dẫn không phải bằng chứng sự kiện và công cụ không thực thi phản ứng. |
| `search_rootkit_evidence` | Rule Wazuh `521`, hoặc cảnh báo nhóm `rootcheck` có mô tả chứa `rootkit`/`hidden`. | Tìm cảnh báo liên quan và snapshot endpoint **đã lưu** cho agent trong cửa sổ. Nếu truyền PID, PID phải khớp cảnh báo gốc; không quét trực tiếp và cảnh báo lặp lại không phải bằng chứng độc lập. |

Trong cấu hình lab, rule Wazuh `40111` tương quan 9 sự kiện thuộc nhóm
`authentication_failed` từ cùng IP trong 160 giây; `40112` giữ nguyên cửa sổ
240 giây để phát hiện đăng nhập thành công sau chuỗi thất bại. Rule `2502`
được giữ ở level 5 như tín hiệu phụ. Ngưỡng đếm sự kiện log khớp rule, không
đảm bảo tương ứng chính xác với số lần người dùng nhập mật khẩu; hãy xác minh
bằng log thực tế và `wazuh-logtest`.

## Phạm vi chung

- Các công cụ tra log đọc SQLite SOC ở chế độ chỉ đọc, chỉ đối chiếu agent của
  cảnh báo và mặc định trong **15 phút trước đến 15 phút sau** thời điểm cảnh báo.
  Nếu cung cấp IP hoặc khoảng thời gian, tham số phải nằm trong phạm vi được phép.
  `get_alert` và `search_runbook` có cách truy vấn riêng.
- `agent_id` là mã agent, ví dụ `001`, không phải địa chỉ IP. `since`, `until` và
  các thời điểm baseline cần theo ISO 8601 có múi giờ, ví dụ
  `2026-11-17T10:00:00Z`. Công cụ tổng hợp yêu cầu các thời điểm này và các
  tham số phạm vi khác; công cụ tìm kiếm có thể dùng phạm vi mặc định.
- Công cụ tìm kiếm thường trả tối đa 20 bản ghi mặc định, có thể yêu cầu 1–100.
  `truncated` cho biết số bản ghi chi tiết được trả đã bị giới hạn; `total_matched`
  là số bản ghi lưu khớp bộ lọc, không phải số gói tin hoặc số phiên duy nhất.
- Các thống kê phản ánh dữ liệu SOC đã lưu, có thể thiếu hoặc trùng. Kết quả rỗng
  không chứng minh nguồn đã được cấu hình hay hành vi không xảy ra.
- Mô tả gửi model được viết ngắn bằng tiếng Anh để hạn chế chiếm cửa sổ ngữ cảnh;
  hướng dẫn trả lời bằng tiếng Việt vẫn nằm trong system prompt của quy trình điều tra.
  Mô tả này không thay đổi rule, chính sách lọc, quyền của tool hay thứ tự gọi tool.

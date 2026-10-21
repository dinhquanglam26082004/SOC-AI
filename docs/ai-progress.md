# Theo dõi tiến độ điều tra AI

Thanh tiến độ có tại Dashboard, Investigations và cửa sổ chi tiết cảnh báo.
Giao diện lấy trạng thái từ backend mỗi 3 giây, cập nhật đồng hồ mỗi giây.

Luồng gồm 6 bước:

1. Tra cứu bằng chứng RAG (policy và MITRE).
2. Model tạo báo cáo điều tra.
3. Kiểm tra cấu trúc và nội dung bắt buộc của báo cáo.
4. Tra cứu playbook và policy phản ứng.
5. Model tạo đề xuất phản ứng.
6. Lưu kết quả.

Mỗi đoạn sáng thể hiện một bước; đoạn nhấp nháy là bước đang chạy.
Các bước có thời lượng khác nhau, vì vậy số đoạn không tương đương phần trăm
khối lượng tính toán. Khi gọi model, thời gian bước bao gồm thời gian nạp model,
xử lý prompt và sinh nội dung. Chưa có dự đoán thời gian còn lại.

Giao diện hiển thị thời gian chờ hàng đợi riêng, thời gian đã chạy, thời gian
ở bước hiện tại, giờ bắt đầu và giờ kết thúc. Khi hoàn tất, tổng thời gian được
giữ lại. Báo cáo điều tra đã hợp lệ được lưu và hiển thị trước khi tạo xong
đề xuất phản ứng; lỗi playbook vẫn giữ báo cáo này.

Backend lưu `ai_progress` trong payload cảnh báo tại SQLite
`data/soc_runtime.sqlite3`, gồm thời gian Unix, bước, model, thời lượng từng
bước (`stage_seconds`) và tổng thời gian (`elapsed_seconds`). Trạng thái này
cũng có trong API chi tiết cảnh báo và danh sách Alerts.

Sau khi backend bị gián đoạn, lượt đang chạy được đưa lại vào hàng đợi.
Đồng hồ tính từ lượt chạy mới và giao diện ghi rõ việc khởi động lại.
Cảnh báo lịch sử chưa lưu mốc thời gian sẽ hiển thị thông báo chưa có dữ liệu,
không suy đoán thời gian từ ngày phát sinh log.

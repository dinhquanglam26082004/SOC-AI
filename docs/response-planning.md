# Kế hoạch phản ứng do AI đề xuất (bước 7–9)

## Luồng

```text
Điều tra đã hoàn tất → analyst bấm "AI lập kế hoạch phản ứng"
  → tra playbook phù hợp → AI đề xuất hành động, dẫn evidence_id và đoạn playbook
  → cổng chính sách (code) chặn hành động thiếu căn cứ
  → analyst duyệt / từ chối từng hành động
  → thực thi CHẾ ĐỘ MÔ PHỎNG → ghi lịch sử phản ứng
```

Không có hành động nào chạy tự động hoặc tác động lên máy thật.

## Phân vai

| Việc | Ai làm |
| --- | --- |
| Chọn hành động, mục tiêu, lý do, bằng chứng dẫn | AI (`agents/response_planner.py`, một lượt gọi model + tối đa 1 lần sửa JSON hoặc trích dẫn) |
| Chọn đoạn hướng dẫn cho từng hành động | AI chọn `guidance_ids` từ các đoạn RESPONSE/ESCALATION của playbook; code kiểm tra ID có tồn tại |
| Mức ảnh hưởng, khả năng hoàn tác, mitigation MITRE, lệnh sẽ chạy, cách hoàn tác | Code (danh mục `CATALOG`) |
| Kiểm tra mục tiêu có thật trong bằng chứng, chặn hành động gây gián đoạn khi verdict chưa malicious, chặn mục tiêu được bảo vệ | Code (`gate`) |
| Duyệt từng hành động | Analyst |
| Thực thi (mô phỏng) và ghi lịch sử | Code (`agents/response_store.py`) |

## Danh mục hành động

| Hành động | Mục tiêu | Pha | Ảnh hưởng |
| --- | --- | --- | --- |
| `collect_forensics` | agent của cảnh báo | Bảo toàn chứng cứ | thấp |
| `block_domain` | domain có trong bằng chứng | Ngăn chặn | thấp |
| `block_ip` | IP có trong bằng chứng | Ngăn chặn | trung bình |
| `isolate_host` | agent của cảnh báo | Ngăn chặn | cao |
| `disable_account` | user có trong bằng chứng | Ngăn chặn | cao |
| `kill_process` | tiến trình có trong bằng chứng | Loại bỏ | cao |
| `disable_service` | đường dẫn persistence có trong bằng chứng | Loại bỏ | cao |
| `increase_monitoring` | agent của cảnh báo | Phục hồi | thấp |

Model không thể thêm hành động ngoài danh mục: schema JSON của Ollama và Pydantic đều giới hạn `action`.

## Cổng chính sách

Một hành động bị đánh dấu `rejected` (analyst không thể duyệt) khi:

- dẫn `evidence_id` không thuộc cuộc điều tra, hoặc chỉ dẫn tài liệu hướng dẫn;
- không dẫn đoạn playbook hợp lệ hoặc dẫn một `guidance_id` không có trong nguồn đã cấp;
- đoạn được dẫn không có từ ngữ thể hiện loại hành động theo kiểm tra đơn giản của hệ thống;
- không dẫn bằng chứng nào (trừ `collect_forensics`, `increase_monitoring`);
- mục tiêu không xuất hiện trong bằng chứng được dẫn hoặc cảnh báo gốc;
- mục tiêu host không phải agent của cảnh báo;
- mục tiêu nằm trong danh sách bảo vệ (`127.0.0.1`, tên manager, `RESPONSE_PROTECTED_TARGETS`);
- hành động không phải loại ảnh hưởng thấp trong khi verdict chưa là `malicious`.

Verdict lấy theo đánh giá của analyst nếu đã review, nếu chưa thì theo báo cáo của model. Verdict `benign` không lập kế hoạch.

Kế hoạch lưu tên/ID playbook, tên tệp, SHA-256 nội dung và bản chụp các đoạn RESPONSE
đã cấp cho model, bao gồm mục ESCALATION khi có. UI hiển thị đoạn model chọn cùng từng hành động. Kiểm tra chủ đề
và ID trích dẫn không chứng minh nội dung đoạn thực sự phù hợp; analyst cần đọc
nguồn và bằng chứng trước khi quyết định. Bộ kiểm tra từ ngữ có thể bỏ sót diễn đạt
hợp lệ hoặc chấp nhận đoạn chưa phù hợp về ngữ cảnh; đó không phải kiểm định ngữ nghĩa.
Tài liệu hướng dẫn không phải bằng chứng
cho sự cố. Nếu kho không khả dụng, không tìm thấy playbook phù hợp, hoặc playbook
thiếu mục RESPONSE, hệ thống báo lỗi và không tạo kế hoạch. Kế hoạch cũ chưa có
trích dẫn không thể được duyệt hoặc thực thi mô phỏng; cần lập lại kế hoạch.

Sau khi điều tra, hệ thống tra playbook và gọi model thêm một lượt (có thể có một
lượt sửa) để tạo gợi ý ngắn có trích dẫn. Các lượt này được ghi vào hoạt động AI
và nằm ngoài số lượt của graph điều tra. UI và Telegram chỉ hiển thị các gợi ý
vượt qua kiểm tra bằng chứng, trích dẫn và chính sách; chúng cùng dùng dữ liệu
`grounded_response` gắn với đúng incident. Báo cáo gốc của model vẫn được lưu,
nhưng các khuyến nghị cũ không được tự gán nguồn sau khi sinh. Nếu không có nguồn,
model lỗi hoặc không có hành động đủ điều kiện, trạng thái được báo rõ và không
thay thế bằng gợi ý không nguồn. Lập kế hoạch phản ứng chi tiết vẫn do analyst
khởi tạo và chỉ hỗ trợ mô phỏng.

Với thay đổi tài khoản Linux, rule 101201/101202 dùng playbook leo thang đặc quyền;
rule 101200 và Wazuh 5901 dùng playbook quản lý tài khoản. Chọn nguồn này là
deterministic, không phụ thuộc thứ hạng RAG. `no_actions` có nghĩa không có hành động
nào đồng thời đủ bằng chứng, trích dẫn và điều kiện chính sách; không có nghĩa là
không tìm thấy alert hoặc playbook. Không tự tạo hành động chỉ để tránh kết quả rỗng.

## API

| Endpoint | Mục đích |
| --- | --- |
| `POST /api/alerts/{id}/response/plan` | AI lập kế hoạch (cảnh báo gộp dùng điều tra của cảnh báo đại diện) |
| `GET /api/alerts/{id}/response/plan` | Kế hoạch mới nhất |
| `POST /api/response/plans/{plan_id}/decision` | `{"approve": [...], "decline": [...], "notes": "..."}` |
| `POST /api/response/execute` | `{"plan_id": "..."}` — thực thi mô phỏng các hành động đã duyệt, mỗi kế hoạch một lần |
| `GET /api/response/history` | Lịch sử hành động đã thực thi (mô phỏng) |

## Cấu hình

| Biến | Mặc định |
| --- | --- |
| `RESPONSE_EXECUTION_MODE` | `simulate`; giá trị khác trả HTTP 501 vì chưa có adapter thực thi thật |
| `RESPONSE_PROTECTED_TARGETS` | rỗng; danh sách IP/host/domain không bao giờ được đề xuất, phân cách bằng dấu phẩy |
| `RESPONSE_CONTEXT_CHARS` | `3500`; ký tự bằng chứng đưa vào prompt lập kế hoạch |

## Giới hạn

- Thực thi chỉ là mô phỏng: lịch sử ghi lệnh sẽ chạy và cách hoàn tác, không có lệnh nào chạy trên host.
- Mục tiêu chỉ được kiểm tra là *có xuất hiện* trong bằng chứng; điều đó không chứng minh hành động là đúng. Analyst vẫn là người quyết định.
- Lập kế hoạch dùng chung một lượt model với điều tra (`AI_MAX_CONCURRENCY`), nên có thể phải chờ khi worker đang điều tra.

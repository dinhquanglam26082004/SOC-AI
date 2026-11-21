SOC-AI - Tool Selection & Cache Optimization (bản vá có kiểm tra)

Nguồn đối chiếu: nhánh main công khai (20/11/2026), không phải bản local của bạn.
Chỉ tác động mã nguồn: agents/investigation_graph.py và tạo agents/tool_call_policy.py.
Không thay đổi schema SQLite, Wazuh, Zeek, Dashboard, Ollama, Docker volume, lịch sử Git.

HƯỚNG DẪN TRÊN WINDOWS
1. Trong GitHub Desktop: tạo branch 'fix/tool-call-optimization'.
2. Lưu apply_socai_tool_optimization.py vào thư mục gốc C:\Users\ADMIN\SOC-AI.
3. Tại PowerShell trong VS Code (đứng trong thư mục SOC-AI):
   py -3.12 .\apply_socai_tool_optimization.py --check
4. Chỉ khi thấy "OK: patch applies cleanly; no files changed.":
   py -3.12 .\apply_socai_tool_optimization.py --apply
5. Kiểm tra (có thể thiếu các dependency ở Python Windows; nếu có, dùng môi trường container):
   py -3.12 -m compileall -q agents
   git diff --check
   git diff -- agents/investigation_graph.py
   git status --short
6. Nếu code đúng, kiểm thử bằng pytest trong dự án nếu sẵn có, rồi build:
   docker compose --profile app up -d --build --no-deps soc-ai-app
7. Kiểm tra một cuộc điều tra mới Rootkit Rule 521, FIM và Zeek. Chỉ push khi chạy ổn.

THAY ĐỔI
- Khóa audit tool được tính từ Pydantic defaults và thời gian UTC chuẩn hóa.
- Giữ nguyên kiểm tra quyền agent/IP/time trong LocalTools.execute.
- Không gọi lại truy vấn cùng scope/args; truy vấn bị trùng sẽ được thông báo skipped.
- Tool chỉ được truy vấn lại với phạm vi khác khi kết quả trước bị cắt; get_event_details cho phép xem tối đa 3 evidence IDs khác nhau.
- Tool trả lỗi tham số có thể gọi lại sau khi sửa tham số.
- Giữ toàn bộ evidence IDs, lịch sử audit và cơ chế truy vấn SQLite hiện hành.

QUAN TRỌNG
- --check không sửa gì; --apply sao lưu file cũ ra thư mục SOC-AI-tool-backup-* cạnh repo.
- Nếu --check báo khớp 0 đoạn code hoặc file tool_call_policy.py đã tồn tại thì dừng: source trên máy khác với phiên bản đã rà soát.
- Không khẳng định hiệu quả end-to-end cho tới khi bạn chạy test với container, Ollama và các alert của mình.
- Không chạy docker compose down -v hoặc xóa volume.

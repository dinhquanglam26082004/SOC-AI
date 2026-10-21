# Kiểm chứng bàn giao — 20/10/2026

> Ghi nhận lịch sử ngày 20/10/2026. Từ 21/10/2026, chức năng hỏi đáp và API chat
> đã được gỡ theo yêu cầu; kết quả kiểm tra chat bên dưới không áp dụng cho bản hiện tại.

## Đã thực hiện

- Đọc repository thật và chạy tests bằng Python 3.12 trong `.venv`.
- `python -m pytest tests -q --basetemp artifacts/pytest-delivery-final`: **25 passed**.
  Có một cảnh báo deprecation của Starlette TestClient/httpx; không có test failure.
  Windows sandbox làm TestClient treo ở lần đầu; bộ test được chạy lại ngoài sandbox
  với tệp tạm vẫn nằm trong workspace.
- Kiểm tra Python AST và `node --check` cho JavaScript dashboard: đạt.
- `docker compose --profile app config --quiet`: đạt.
- Docker Desktop Linux engine 29.4.1; build và chạy Manager **4.14.5** từ image chính thức.
- Healthcheck xác nhận analysisd/remoted/authd/integratord/db chạy và TCP1514/1515 nghe.
- Manager/forwarder đã recreate và giữ volume. Enrollment password được copy từ secret
  thành root:wazuh 0640 trong volume cấu hình; spool group setgid và DB mode0660.
- Log container đã phát hiện lỗi quyền ghi spool ở lần đầu; sửa quyền và recovery từ
  Manager alerts JSONL giữ lại. Sau sửa, callback tạo hàng đợi thành công.
- Mapper đọc được cảnh báo Manager tự sinh đang spool; không dùng fixture trong dashboard.
- `agent_control -l`: chỉ có Agent nội bộ **000 / soc-manager / Active-Local**;
  **chưa có Agent endpoint riêng**. Đây không phải bằng chứng demo FIM.
- RAG local truy xuất thực tế 3 tài liệu, không lỗi, dùng embedding cache offline;
  không rebuild ChromaDB để làm phép kiểm tra này.
- Ollama container 0.13.5 đã tải xong `qwen3:0.6b` (522 MB).
- Backup SQLite trước migration vào `artifacts/runtime-before-wazuh.sqlite3`.
  Migration thử trên bản sao giữ **52 bản ghi lịch sử**, 0 case; không xóa snapshot cũ.
- Image backend CPU đã build và chạy với entry point `api.app:app`; cả bốn container
  Manager, forwarder, backend, Ollama đều healthy ở lần kiểm tra cuối.
- Delivery qua mạng Compose sau khi backend hoạt động: spool pending=0, dead_letter=0,
  sent=5; SQLite có 4 alert Wazuh mới và đủ 52 lịch sử (tổng56). Có delivery lặp được
  dedup. Alert mới là thông báo nội bộ do Manager sinh, không phải log từ Agent riêng.
- `POST /api/chat` qua HTTP chạy RAG + Ollama thật: có câu trả lời 1.045 ký tự,
  3 citations, model qwen3:0.6b. Truy xuất trong container cũng lấy được 3 tài liệu.
  Embedding cache local được copy vào named volume, không rebuild ChromaDB.
- Hai agent Investigation/Playbook chạy model thật trên `tests/fixtures/wazuh_fim.json`:
  JSON hợp lệ, đủ evidence/inferences/unknowns/recommendations, 4 citations điều tra,
  4 hành động đề xuất. Fixture chỉ chạy trực tiếp hàm phân tích; không POST vào live DB.
  Kết quả này kiểm tra khả năng vận hành, chưa phải đánh giá độ chính xác điều tra.
- Một build lặp bị timeout tải PyTorch; build cuối hoàn tất bằng cache đã dựng thành công.
  Một startup Manager có wazuh-apid bị kill; chưa xác định nguyên nhân (cgroup oom_kill=0).
  Restart sau đó đạt readiness. Healthcheck đã phát hiện trạng thái chưa sẵn sàng này.

## Phạm vi bộ test

Mapper Windows Event4625, FIM Windows/Linux, optional fields, payload lỗi, không gán
Agent IP thành attacker IP; allowlist dưới ngưỡng AI; token thiếu/sai; startup thiếu token;
size limit; storage failure không ACK; queue backpressure; durable accept không gọi LLM;
duplicate đồng thời và sau restart; migration lịch sử/cases/responses; job recovery;
AI failure không tạo báo cáo giả; RAG và Ollama failure; citations chỉ trong context;
spool restart/network retry/401-DLQ/replay/capacity; API alerts/cases/response501;
endpoint nguồn cũ không còn đăng ký. Test timeseries hiện có vẫn chạy đạt.

HTTP server giả trong test và các câu trả lời mock chỉ dùng kiểm thử offline. Không
gọi chúng là bằng chứng thu log live hoặc đánh giá chất lượng mô hình.

## Số đo tài nguyên ban đầu

Manager khoảng 245–247 MiB ở trạng thái không có Agent; forwarder khoảng 19 MiB;
Ollama khoảng 86 MiB trước khi nạp model vào inference. Đây là số đo idle, không phải
đỉnh RAM hoặc ngân sách đầy đủ của máy Windows. Dùng docker stats/Task Manager khi chạy
FIM, ingest RAG và inference thực tế để đo lại. Compose đặt hard limits riêng.

Sau hỏi đáp/model: backend khoảng709 MiB, Ollama1.466 GiB, Manager212 MiB,
forwarder17 MiB tại một snapshot; Docker engine được cấp khoảng7.44 GiB.
Không gồm toàn bộ RAM Windows/Agent VM và không phải đo peak.

## Cần xác minh trên máy Agent

Chưa cài/thay đổi bất kỳ Agent từ xa nào. Cần người có quyền trên Agent chạy
[runbook](wazuh-live-demo.md): enrollment → baseline FIM → tạo/sửa/xóa file → đối chiếu
ID nguồn/Agent/path trong Manager và SOC-AI → quan sát trạng thái/kết quả AI.
Chưa xác minh audit4625 và PowerShell4104 trên endpoint thật.

Manager có thể ghi inventory-harvester/Indexer warnings trong lab không Indexer;
không cam kết inventory/vulnerability đầy đủ. Disk đầy/downtime dài có thể làm mất
callback chưa spool khi logs hết retention; giới hạn và cách recovery đã ghi trong README.

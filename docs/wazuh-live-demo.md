# Runbook Wazuh 4.14.5 — sự kiện thật từ máy Agent

Máy chính là Windows chạy Docker Desktop Linux containers. Ví dụ IP máy chính
`192.168.1.10`, Agent `192.168.1.20`; **thay hai giá trị này bằng IP thật**.
Agent phải là máy khác/VM có IP riêng; máy chính không tự được coi là endpoint giám sát.

## 1. Chuẩn bị máy chính

Chạy theo README để có Manager/forwarder/backend. Trên PowerShell Administrator,
chỉ mở hai cổng từ IP Agent hoặc subnet lab được phép:

```powershell
$agentAddress = '192.168.1.20'
New-NetFirewallRule -DisplayName 'SOC-Lab Wazuh data' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1514 -RemoteAddress $agentAddress -Profile Private
New-NetFirewallRule -DisplayName 'SOC-Lab Wazuh enrollment' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1515 -RemoteAddress $agentAddress -Profile Private
docker compose ps
docker compose exec wazuh-manager /var/ossec/bin/wazuh-control status
```

Docker Desktop port forwarding có thể có firewall rule sẵn: kiểm tra và thu hẹp các rule
Docker tương ứng, vì một rule allow rộng khác có thể vô hiệu hóa ý định giới hạn ở trên.
Không tự mở 55000/8100 ra LAN. Nếu native backend cần Docker subnet tới 8100, thêm rule
riêng chỉ cho subnet Docker thực tế; không dùng allow Any.

Manager dùng password enrollment từ `secrets/authd.pass`. Xem riêng file trên máy chính,
nhập giá trị vào Agent; không dán vào ảnh/log công khai. TCP 1515 chỉ enrollment;
1514 mới truyền sự kiện. Test-NetConnection thành công chỉ xác nhận TCP mở.

## 2. Windows Agent

Chỉ chạy trên máy Agent được phép. Dùng PowerShell Administrator:

```powershell
$managerAddress = '192.168.1.10'
Test-NetConnection $managerAddress -Port 1515
Test-NetConnection $managerAddress -Port 1514
Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi' -OutFile "$env:TEMP\wazuh-agent-4.14.5.msi"
Start-Process msiexec.exe -ArgumentList '/i', "$env:TEMP\wazuh-agent-4.14.5.msi", '/qn', "WAZUH_MANAGER=$managerAddress", 'WAZUH_AGENT_NAME=soc-lab-windows' -Wait
# Nhập password qua Read-Host; tránh đưa secret vào command history.
$enrollSecret = Read-Host 'Enrollment password từ máy chính'
Set-Content -LiteralPath 'C:\Program Files (x86)\ossec-agent\authd.pass' -Value $enrollSecret -Encoding ascii
Remove-Variable enrollSecret
```

Sửa `C:\Program Files (x86)\ossec-agent\ossec.conf`. Trong `<client>` hiện có,
đặt địa chỉ Manager thực tế và enrollment (không tạo client trùng):

```xml
<client>
  <server><address>192.168.1.10</address><port>1514</port><protocol>tcp</protocol></server>
  <enrollment>
    <enabled>yes</enabled><manager_address>192.168.1.10</manager_address>
    <port>1515</port><agent_name>soc-lab-windows</agent_name>
    <authorization_pass_path>authd.pass</authorization_pass_path>
  </enrollment>
</client>
```

Giới hạn quyền đọc authd.pass cho SYSTEM/Administrators theo chính sách máy lab.

```powershell
Start-Service WazuhSvc
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 60
```

Trên máy chính:

```powershell
docker compose exec wazuh-manager /var/ossec/bin/agent_control -l
```

Kỳ vọng Agent có tên đã chọn và ID riêng, trạng thái Active khi thực sự kết nối.
Manager key nằm volume `wazuh_etc`, không mất khi recreate. Không tái dùng tên/ID của
Agent khác; nếu tên trùng hãy xử lý registration cũ có chủ đích, không xóa mọi keys.

## 3. Demo A — Windows FIM (bắt buộc làm đầu tiên)

Tạo thư mục và file baseline trước khi bật theo dõi:

```powershell
New-Item -ItemType Directory -Path 'C:\SOC-Lab\watched' -Force
Set-Content -LiteralPath 'C:\SOC-Lab\watched\baseline.txt' -Value 'baseline'
```

Trong `<syscheck>` hiện có của Agent, bảo đảm disabled=no, scan_on_start=yes,
alert_new_files=yes và thêm directories. Không thay toàn bộ các đường dẫn vận hành:

```xml
<syscheck>
  <disabled>no</disabled>
  <scan_on_start>yes</scan_on_start>
  <alert_new_files>yes</alert_new_files>
  <directories check_all="yes" realtime="yes">C:\SOC-Lab\watched</directories>
  <!-- Giữ các cấu hình khác đang có -->
</syscheck>
```

```powershell
Restart-Service WazuhSvc
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 100 -Wait
```

Chờ thông báo hoàn tất FIM scan/baseline và real-time monitoring cho đường dẫn lab.
Không tạo thay đổi trong lúc baseline còn chạy. Dừng tail bằng Ctrl+C. Sau đó:

```powershell
Set-Content -LiteralPath 'C:\SOC-Lab\watched\demo-fim.txt' -Value 'SOC-LAB-FIM initial'
Start-Sleep -Seconds 5
Add-Content -LiteralPath 'C:\SOC-Lab\watched\demo-fim.txt' -Value 'SOC-LAB-FIM changed'
Start-Sleep -Seconds 5
Remove-Item -LiteralPath 'C:\SOC-Lab\watched\demo-fim.txt'
```

Trên máy chính, kiểm tra **cảnh báo Manager thực tế** (có thể chứa dữ liệu nhạy cảm;
chỉ lưu evidence lab cần thiết):

```powershell
docker compose exec wazuh-manager sh -c 'tail -n 100 /var/ossec/logs/alerts/alerts.json'
Invoke-RestMethod http://localhost:8100/api/alerts | ConvertTo-Json -Depth 10
Invoke-RestMethod http://localhost:8100/api/sources/status | ConvertTo-Json -Depth 8
```

Kỳ vọng `syscheck.path` khớp đường dẫn, `syscheck.event` added/modified/deleted, Agent
ID/name khớp và rule syscheck tương ứng (thường 554/550/553, kiểm tra ruleset thực tế).
SOC-AI hiển thị source=wazuh, hostname, rule level gốc, file operation và AI queued→running
→completed hoặc failed nếu dịch vụ AI chưa sẵn sàng. FIM dưới level7 vẫn đủ điều kiện nhờ
group syscheck allowlist. Thay đổi file là quan sát; chỉ có ý nghĩa bảo mật khi xét ngữ cảnh.

Lưu bốn bằng chứng riêng: lệnh/thời gian thay đổi trên Agent; JSON Manager có ID nguồn;
alert SOC-AI có cùng ID/Agent/path; trạng thái/báo cáo AI. Không dùng fixture để thay bước này.
Nếu AI failed, sửa Ollama/RAG rồi nhấn nút điều tra/thử lại (cooldown 10s, tối đa 5 lần).

Dọn lab: bỏ riêng `<directories>` của lab, restart Agent, rồi xóa file baseline và thư mục
lab nếu không còn dùng. Không xóa enrollment hay Agent keys chỉ để dọn demo.

## 4. Linux Agent thay cho Windows

Ví dụ Ubuntu/Debian Agent, lệnh trên Agent có sudo; không chạy trên máy chính:

```bash
curl -fLo /tmp/wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb
sudo env WAZUH_MANAGER=192.168.1.10 WAZUH_AGENT_NAME=soc-lab-linux dpkg -i /tmp/wazuh-agent.deb
sudo mkdir -p /opt/soc-lab/watched
printf 'baseline\n' | sudo tee /opt/soc-lab/watched/baseline.txt >/dev/null
```

Thêm client/enrollment như Windows nhưng `authorization_pass_path` là
`/var/ossec/etc/authd.pass`; tạo file bằng editor sudo, chmod600, root owner.
Trong syscheck thêm:

```xml
<directories check_all="yes" realtime="yes">/opt/soc-lab/watched</directories>
```

```bash
sudo systemctl enable --now wazuh-agent
sudo systemctl restart wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log
# Chờ scan baseline hoàn thành rồi Ctrl+C:
printf 'SOC-LAB-FIM initial\n' | sudo tee /opt/soc-lab/watched/demo-fim.txt >/dev/null
sleep 5
printf 'SOC-LAB-FIM changed\n' | sudo tee -a /opt/soc-lab/watched/demo-fim.txt >/dev/null
sleep 5
sudo rm /opt/soc-lab/watched/demo-fim.txt
```

Xác minh Manager/SOC-AI như Demo A. Bỏ config lab trước khi xóa baseline/thư mục.

## 5. Demo B — một vài đăng nhập sai, sau FIM

Windows Agent: dùng tài khoản lab riêng; không đụng tài khoản hằng ngày. Kiểm tra chính
sách lockout trước (`net accounts`), chỉ thử 1–2 lần dưới ngưỡng. Nếu ngưỡng không rõ/≤2,
không thực hiện trước khi quản trị viên xác nhận chính sách lab.

```powershell
$labPassword = Read-Host 'Mật khẩu mạnh cho tài khoản lab' -AsSecureString
New-LocalUser -Name 'soc-lab-login' -Password $labPassword -Description 'Temporary SOC lab account'
auditpol /backup /file:C:\SOC-Lab\audit-before.csv
# GUID Audit Logon (tránh tên subcategory thay đổi theo ngôn ngữ):
auditpol /set /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /failure:enable
runas /user:.\soc-lab-login cmd.exe
# Nhập sai MỘT lần tại prompt; không lặp bằng script.
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddMinutes(-5)} | Select-Object -First 3 TimeCreated,Id,Message
```

Agent cần localfile Security/eventchannel; cài đặt mặc định thường đã có. Kiểm tra và
thêm nếu thiếu, tránh block trùng:

```xml
<localfile><location>Security</location><log_format>eventchannel</log_format></localfile>
```

Restart Agent nếu sửa config. Kiểm tra JSON Manager: data.win.system.eventID=4625,
targetUserName là tài khoản lab và rule thực tế. Một lần sai không phải brute force.
Runbook này không thêm correlation rule lặp nên không tạo cảnh báo brute force giả.

Dọn: `Remove-LocalUser -Name 'soc-lab-login'`; restore audit policy bằng
`auditpol /restore /file:C:\SOC-Lab\audit-before.csv` chỉ khi không có thay đổi quản trị
khác kể từ backup. Không vô hiệu hóa audit vận hành ngoài phạm vi lab.

## 6. Demo C — PowerShell marker vô hại (tùy chọn)

Trên Windows Agent, bật Script Block Logging bằng GPO hoặc registry trong lab; ghi lại
giá trị trước để restore đúng. Nếu chưa có giá trị:

```powershell
$logKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $logKey -Force
New-ItemProperty -Path $logKey -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force
```

Thêm channel vào Agent (nếu thiếu), restart Agent:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4104]</query>
</localfile>
```

Marker chỉ tạo event, muốn có alert dùng rule thử nghiệm tùy chọn trong
`docker/wazuh/lab_rules.xml`; copy nó vào Manager etc/rules rồi restart Manager.
Rule match 4104 + marker, level3, group soc_lab; đây là quy tắc lab, không gọi mọi
PowerShell là độc hại. Muốn AI cho rule này, thêm 100110 vào WAZUH_AI_RULE_ALLOWLIST.

```powershell
docker compose cp docker/wazuh/lab_rules.xml wazuh-manager:/var/ossec/etc/rules/soc_lab_rules.xml
docker compose restart wazuh-manager
# TRÊN AGENT, mở Windows PowerShell session mới:
powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-HARMLESS-PS'"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date).AddMinutes(-5)} | Select-Object -First 3 TimeCreated,Message
```

Dọn rule lab riêng khỏi Manager, restore giá trị logging đã ghi lại; không tắt logging
đang được chính sách tổ chức quản lý. Không dùng malware, khai thác hay tắt Defender.

## 7. Troubleshooting / recovery

| Hiện tượng | Kiểm tra và xử lý |
| --- | --- |
| Chưa enrollment | TCP1515, password file, tên Agent trùng, authd logs; đừng chỉ dựa TCP |
| Đã enrollment nhưng không Active | TCP1514, IP Manager, client.keys, Agent ossec.log và agent_control |
| Active nhưng chưa alert | Sự kiện endpoint/channel có xuất hiện? Wazuh rule có tạo alert ≥3? Agent log không đồng nghĩa alert |
| FIM không báo | Directory có trước restart? Baseline hoàn tất? realtime active? Đường dẫn config chính xác? |
| Manager có alert, SOC-AI chưa có | Integration permission/logs, forward min/group, spool pending/dead, URL service và token |
| 401 | Đồng bộ WAZUH_WEBHOOK_TOKEN forwarder/backend; recreate rồi replay DLQ |
| Native không tới được backend | host.docker.internal, bind 0.0.0.0, firewall Docker subnet, backend thực sự đang chạy |
| AI skipped | Chính sách level/rule/group; alert vẫn hiện; nút điều tra thủ công có kiểm soát |
| AI failed | /api/system/status: Ollama reachable? model đã pull? KB có dữ liệu/embedding? RAM/OOM? |
| Source im lặng | Nhận log cuối không phải Agent offline; dùng agent_control hoặc trạng thái xác thực khác |
| Trùng HTTP deliveries | Bình thường khi retry, backend dedup theo Manager+ID; nếu đổi Manager name thì là namespace khác |
| Queue đầy | HTTP503 giữ spool; giải quyết AI/RAM hoặc tăng giới hạn sau khi đánh giá dung lượng |
| Container Manager Up nhưng unhealthy | Xem docker compose logs wazuh-manager; kiểm tra apid/analysisd/remoted/authd. Nếu startup thất bại, sửa lỗi rồi docker compose restart wazuh-manager; Up không có nghĩa ready |

Xem spool status và DLQ metadata (không in payload):

```powershell
docker compose exec wazuh-forwarder cat /spool/status.json
docker compose exec wazuh-forwarder python -c "import sqlite3; d=sqlite3.connect('/spool/queue.sqlite3'); print(d.execute('SELECT id,state,attempts,error FROM queue').fetchall())"
# Sau khi sửa lỗi cấu hình, replay đúng ID (thay 12):
docker compose exec wazuh-forwarder python -m wazuh_integration.forwarder --replay 12
```

Disk/spool đầy: integration có thể không spool và Wazuh không đảm bảo retry callback.
Giải phóng/tăng dung lượng trước, giữ Manager logs, import lại JSONL tương ứng. Ví dụ
file hiện tại (sẽ có duplicate an toàn); file rotated .gz phải giải nén ra file riêng
trước khi import, không sửa trực tiếp log Manager đang ghi:

```powershell
docker compose exec wazuh-forwarder python -m wazuh_integration.forwarder --import-jsonl /manager-logs/alerts/alerts.json
```

Nếu file đang viết có dòng cuối chưa hoàn chỉnh, importer dừng tại lỗi, không silently
skip; dùng bản sao ổn định sau khi dừng Manager hoặc file rotation đã hoàn tất. Import
lại từ đầu được vì backend dedup; đây là recovery thủ công, không phải tail checkpoint.
Sau khi đối chiếu đủ alerts, xóa riêng marker để clear health:

```powershell
docker compose exec wazuh-forwarder python -c "from pathlib import Path; Path('/spool/integration-error').unlink(missing_ok=True)"
```

Theo dõi dung lượng Manager logs và spool. Không giảm retention tới mức chưa kịp recovery.
DLQ chứa payload nhạy cảm, chỉ cấp quyền quản trị lab. Thời điểm sent cuối phản ánh delivery,
không phản ánh Agent online. Chưa có authenticated Manager status polling trong dashboard.

### Lỗi enrollment SSL EOF sau khi khởi động lại Manager

Nếu `agent-auth` báo `unexpected eof while reading`, xem log Manager trước khi
đổi mật khẩu hoặc cấu hình TLS. Container `Up` chưa đảm bảo `wazuh-authd` chạy.
Cấu hình hiện tại chỉ lưu `/var/ossec/var/multigroups`, không lưu toàn bộ
`/var/ossec/var` vì PID trong `var/run` có thể trùng PID mới và làm API tự dừng.
Script `0-local-prepare` dọn PID Wazuh tạm trước khi khởi động dịch vụ và chuẩn bị
thư mục nguồn rỗng cho bước khởi tạo multigroups. Volume cũ `wazuh_var` được giữ
để phục hồi nếu cần; không dùng `docker compose down -v` để xử lý lỗi này.

Sau khi Manager healthy, đọc lại enrollment password trên Agent trước mỗi lần
chạy `agent-auth`: `unset ENROLL_PASS` xóa giá trị của lần nhập trước. IP phải
trỏ tới máy chạy Manager và các cổng Docker được publish, không phải IP ví dụ
trong tài liệu.

## 8. Nguồn đối chiếu

- [Wazuh agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)
- [Windows Agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [FIM basic settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html)
- [Custom integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

Gói/rules/schema phải kiểm tra lại khi nâng khỏi 4.14.5. FIM và failed-logon trên Agent
thực tế vẫn cần người có quyền trên Agent thực hiện; container Manager healthy chưa đủ
để gọi là demo endpoint end-to-end thành công.

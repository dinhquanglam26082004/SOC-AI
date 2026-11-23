# Chính sách tiếp nhận log SOC

SOC tiếp nhận Zeek `dns`, `conn`, `http`, `ssh`, `ssl`, `notice`, `files`,
`dhcp`, `weird`. Các loại khác bị loại ở đầu vào SOC. `conn` tạm thời nhận
đầy đủ: chưa có danh sách IOC/cổng lạ hay tổng hợp theo giờ.

Wazuh được tiếp nhận `journald` khi chương trình hoặc nhóm rule liên quan đến
xác thực, SSH, sudo, quản lý tài khoản; `last -n 20`; `netstat listening ports` khi rule 533 báo
thay đổi; `wazuh-agent`, `wazuh-monitord`, `wazuh-remoted`, `syscheck`, `rootcheck`,
`/var/log/dpkg.log`, `logcollector`. Nguồn khác và nhóm `stats`, `syscollector`,
`sca` bị loại. Đây là lọc theo thuộc tính Wazuh, không bảo đảm
nhận đủ sự kiện nếu Agent không ghi hoặc Wazuh không phân loại những trường này.

Rule 11 thống kê Wazuh có thể mang location trỏ tới `conn.log` nhưng không phải
log kết nối Zeek; nó bị loại theo nhóm `stats`. Dữ liệu cũ không tự bị xóa.

Mẫu cấu hình Agent: `docker/wazuh/zeek-agent-localfile.xml` hoặc
`docker/wazuh/zeek-all-agent.conf`; mẫu tập trung bật thêm rootcheck cho
`ubuntu-agent`. Chỉ sử dụng một cách, bỏ wildcard và block
trùng ở Agent lẫn cấu hình tập trung. Cấu hình mẫu chưa tự áp dụng trên máy
Agent. Lọc tại SOC không xóa các file archive của Wazuh Manager và không thay
thế cấu hình vô hiệu nguồn tại Agent. Sau thay đổi code cần build lại app,
forwarder và manager để các thành phần áp dụng cùng chính sách.

# 🛡️ Network Anomaly Detector (SOC Home Shield)

**Network Anomaly Detector** là một hệ thống giám sát an ninh mạng dành cho gia đình hoặc văn phòng nhỏ (Home SOC). Dự án kết hợp kỹ thuật **ARP Spoofing** để điều hướng luồng dữ liệu, sử dụng **Scapy Sniffer** để phân tích sâu gói tin ở tầng mạng (DNS & TLS SNI) mà không cần can thiệp giải mã SSL/TLS, lưu trữ lịch sử vào cơ sở dữ liệu **SQLite**, quản lý tập trung thông qua **Flask Web Dashboard** trực quan và phát tín hiệu cảnh báo tức thời dạng Rich Embed qua **Discord Webhook**.

---

## ✨ Các tính năng nổi bật

1. **Tự động quét mạng (Network Discovery):** Sử dụng gói tin ARP để quét siêu tốc dải mạng (Subnet) nội bộ, tự động nhận diện và liệt kê tất cả các thiết bị đang trực tuyến (Online) ngoại trừ Router và chính máy giám sát.
2. **Điều hướng lưu lượng thông minh (ARP Spoofing):** Đóng vai trò thực thể trung gian (Man-In-The-Middle) để chuyển tiếp traffic của toàn bộ thiết bị mục tiêu qua máy giám sát một cách song song mà không gây gián đoạn mạng.
3. **Phân tích SNI & DNS Sniffing:**
   - Lắng nghe cổng UDP 53 để trích xuất truy vấn tên miền từ gói tin DNS.
   - Phân tích cú pháp thô (Byte/Raw Payload) trên cổng TCP 443 nhằm bóc tách trường **SNI (Server Name Indication)** của giao thức mã hóa TLS để lấy tên miền gốc chính xác.
4. **Hệ thống Blacklist linh hoạt:** Cấu hình danh sách các tên miền đáng ngờ hoặc cần giám sát kèm lý do cụ thể ngay trên giao diện Web. Hỗ trợ kiểm tra khớp đuôi tên miền (ví dụ: chặn `badsite.com` tự động nhận diện `sub.badsite.com`).
5. **Cơ chế chống spam (Cooldown Mode):** Giới hạn tần suất ghi log và gửi cảnh báo trùng lặp cho cùng một IP và tên miền trong vòng 30 giây để tối ưu hiệu năng và tránh làm tràn kênh thông báo.
6. **Cảnh báo qua Discord Webhook:** Khi thiết bị trong mạng truy cập tên miền trong danh sách đen, hệ thống tự động bắn một thông điệp dạng **Rich Embed** đầy đủ màu sắc, chứa IP thiết bị, loại giao thức (DNS/TLS), tên miền độc hại và lý do cảnh báo trực tiếp về kênh Discord của bạn.
7. **Web Dashboard Real-time:** Giao diện điều khiển xây dựng trên Flask và Tailwind CSS, tích hợp tự động làm mới nhật ký mạng (Live Monitoring) mỗi 2 giây bằng cơ chế Polling API gọn nhẹ.
8. **An toàn & Phục hồi:** Khi người dùng nhấn `Ctrl + C` để tắt hệ thống, mô-đun tự động kích hoạt tiến trình **ARP Restore**, khôi phục lại bảng ARP chuẩn cho toàn bộ thiết bị mạng, tránh tình trạng mất kết nối Internet của hệ thống sau khi tắt tool.

---

## 📂 Cấu trúc mã nguồn Dự án

```Main
├── app.py               # Flask Web Server cung cấp giao diện Dashboard, REST API quản trị logs & blacklist
├── arp_spoofer.py       # Mô-đun phụ trách đầu độc ARP, duy trì và khôi phục bảng mạng cho các thiết bị
├── tls_sniffer.py       # Trình bắt gói tin, trích xuất DNS/TLS SNI, kiểm tra blacklist và xử lý Alert/Discord
├── main.py              # Điểm chạy trung tâm (Entry Point), quản lý đa luồng (Multi-threading) và khởi tạo DB
└── templates/
    └── index.html       # Giao diện Web Dashboard thiết kế hiện đại bằng Tailwind CSS & FontAwesome
```

---

## 🛠️ Yêu cầu hệ thống & Chuẩn bị

### 1. Hệ điều hành
- Hệ thống yêu cầu chạy trên môi trường **Linux** (Ubuntu, Debian, Kali Linux...) vì thư viện Scapy yêu cầu quyền tương tác trực tiếp với Socket hệ thống ở tầng thấp.
- Yêu cầu quyền quản trị cao nhất (`sudo / root`).

### 2. Thư viện Python cần cài đặt
Cài đặt các gói phụ thuộc thiết yếu bằng lệnh:
```bash
pip install scapy flask
```
*(Giao diện giao diện sử dụng Tailwind CSS thông qua CDN và SQLite3 tích hợp sẵn trong Python nên không cần cài gì thêm).*

---

## ⚙️ Cấu hình hệ thống trước khi chạy

Trước khi khởi chạy hệ thống, bạn cần mở mã nguồn để chỉnh sửa một vài thông số phù hợp với hạ tầng mạng của mình:

### Bước 1: Khai báo cấu hình mạng nội bộ (`main.py`)
Mở file `main.py` và cập nhật lại các thông số mạng của bạn:
```python
INTERFACE = "wlp3s0"           # Tên card mạng của máy bạn (ví dụ: eth0, wlan0, wlp3s0...)
GATEWAY_IP = "192.168.1.1"      # Địa chỉ IP của Router/Modem nhà bạn
SUBNET_RANGE = "192.168.1.0/24" # Dải mạng LAN cần quét và giám sát
```

### Bước 2: Kích hoạt Forwarding gói tin trên máy Linux (BẮT BUỘC)
Để máy giám sát chuyển tiếp gói tin của nạn nhân ra Internet thành công mà không làm họ bị mất mạng khi chạy ARP Spoofing, bạn cần bật tính năng IP Forwarding của Linux:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### Bước 3: Cấu hình Discord Webhook (`tls_sniffer.py`)
Mở file `tls_sniffer.py` và thay thế liên kết Webhook kênh Discord của bạn vào biến:
```python
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_ACTUAL_WEBHOOK_LINK_HERE"
```

---

## 🚀 Hướng dẫn vận hành

Khi đã hoàn thành các bước cấu hình trên, tiến hành khởi chạy toàn bộ hệ thống bằng quyền root:

```bash
sudo python3 main.py
```

### Tiến trình tự động diễn ra:
1. Hệ thống khởi tạo cơ sở dữ liệu SQLite `anomaly_detector.db` (nếu chưa có).
2. Tự động kiểm tra quyền root, dò tìm IP cục bộ của máy chủ giám sát.
3. Gửi các gói tin quét ARP toàn mạng để tìm các thiết bị đang Online.
4. Khởi chạy 3 luồng hoạt động độc lập (Parallel Multi-threading):
   - **Luồng 1 (ARP Spoofing):** Bắt đầu gửi gói tin đầu độc định kỳ mỗi 3 giây.
   - **Luồng 2 (SNI Sniffer):** Lắng nghe luồng traffic thô thông qua bộ lọc `tcp port 443 or udp port 53`.
   - **Luồng 3 (Flask Web Server):** Mở giao diện Dashboard tại địa chỉ `http://localhost:5000`.

### Tắt hệ thống an toàn:
Khi muốn dừng giám sát, chỉ cần nhấn tổ hợp phím `Ctrl + C` tại cửa sổ Terminal. Tiến trình sẽ dừng các luồng bắt gói tin và dành ~3.5 giây để **khôi phục lại bảng ARP gốc** cho tất cả các thiết bị mục tiêu, đảm bảo mạng gia đình hoạt động bình thường và an toàn.

---

## 📊 Hướng dẫn sử dụng Giao diện Web Dashboard

Khi hệ thống đang chạy, truy cập trình duyệt theo địa chỉ: `http://localhost:5000`

- **Theo dõi thống kê:** Phía trên cùng hiển thị tổng số kết nối TLS đi qua hệ thống và số lượng cảnh báo phát hiện được.
- **Xem nhật ký trực tiếp:** Bảng dữ liệu sẽ liên tục cập nhật dòng chảy traffic, các kết nối bình thường sẽ có nhãn màu xanh `NORMAL`, kết nối nằm trong blacklist sẽ đổi màu đỏ rực kèm chữ `WARNING`.
- **Thêm/Xóa mục tiêu Blacklist:** Điền tên miền muốn chặn (ví dụ: `tiktok.com`) kèm lý do vào form bên phải và nhấn **Kích Hoạt Cảnh Báo**. Bạn cũng có thể hủy bỏ giám sát tên miền đó bất kỳ lúc nào bằng cách nhấn nút dấu `X` trong danh sách.

---

## 📝 Lưu ý an toàn bảo mật (Disclaimer)
Dự án này được phát triển cho mục đích giáo dục, học tập nghiên cứu cơ chế hoạt động của giao thức mạng, giám sát an toàn thông tin nội bộ trong gia đình hoặc quản lý con cái học tập từ xa. Việc sử dụng công cụ này để tấn công mạng, nghe lén thông tin mà không được sự cho phép của chủ sở hữu thiết bị trong các mạng công cộng là vi phạm pháp luật. Tác giả không chịu trách nhiệm cho bất kỳ hành vi lạm dụng nào gây thiệt hại cho cá nhân hoặc tổ chức.

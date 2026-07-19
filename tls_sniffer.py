# tls_sniffer.py
import scapy.all as scapy
import sqlite3
import re
import time
import json
import urllib.request
from datetime import datetime

DB_NAME = "anomaly_detector.db"

# 🛑 ĐIỀN ĐƯỜNG DẪN WEBHOOK DISCORD VÀO ĐÂY
DISCORD_WEBHOOK_URL = "YOUR DISCORD LINK"

recent_logs = {}
COOLDOWN_SECONDS = 30

def is_valid_domain(domain):
    if not domain or len(domain) > 253 or len(domain) < 3:
        return False
    pattern = re.compile(r"^[a-zA-Z0-9\-\.]+$")
    if not pattern.match(domain):
        return False
    if domain.startswith('.') or domain.endswith('.') or domain.startswith('-') or domain.endswith('-'):
        return False
    if '.' not in domain:
        return False
    return True

def send_discord_alert(client_ip, domain, reason, source_type):
    """Gửi cảnh báo dạng Embed vào kênh Discord """
    if not DISCORD_WEBHOOK_URL or "YOUR_DISCORD" in DISCORD_WEBHOOK_URL:
        return

    # Định nghĩa cấu trúc khung Embed của Discord
    payload = {
        "username": "🛡️ SOC Home Shield",
        "embeds": [
            {
                "title": "🚨 CẢNH BÁO: PHÁT HIỆN TRUY CẬP ĐÁNG NGỜ",
                "color": 15158332, # Mã màu đỏ hệ thập phân (0xE74C3C)
                "fields": [
                    {
                        "name": "🖥️ IP Thiết bị",
                        "value": f"`{client_ip}`",
                        "inline": True
                    },
                    {
                        "name": "📡 Giao thức phát hiện",
                        "value": f"`{source_type}`",
                        "inline": True
                    },
                    {
                        "name": "🌐 Tên miền (Domain)",
                        "value": f"**{domain}**",
                        "inline": False
                    },
                    {
                        "name": "⚠️ Lý do cảnh báo",
                        "value": f"*{reason}*",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "Hệ thống giám sát an ninh mạng gia đình"
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        ]
    }

    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/json'
            }
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            pass # Gửi thành công
    except Exception as e:
        print(f"[-] Lỗi gửi Discord: {e}")

def check_blacklist(domain):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, reason FROM blacklist")
    rows = cursor.fetchall()
    conn.close()
    for blocked_domain, reason in rows:
        if domain == blocked_domain or domain.endswith("." + blocked_domain):
            return reason
    return None

def log_to_db(client_ip, domain, is_blocked, reason):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO tls_logs (timestamp, client_ip, domain, is_blocked, reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (now, client_ip, domain, 1 if is_blocked else 0, reason))
    conn.commit()
    conn.close()

def extract_sni_raw(payload):
    """
    Hàm phân tích cú pháp dữ liệu thô (Byte/Raw Payload) của gói tin TCP 
    để trích xuất trường SNI (Server Name Indication) - tên miền mà client muốn kết nối.
    """
    try:
        if payload[0] == 0x16 and payload[5] == 0x01:
            session_id_len = payload[43]
            pos = 44 + session_id_len
            cipher_suite_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
            pos += 2 + cipher_suite_len
            comp_method_len = payload[pos]
            pos += 1 + comp_method_len
            extension_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
            pos += 2
            end_pos = pos + extension_len
            
            while pos < end_pos:
                ext_type = int.from_bytes(payload[pos:pos+2], byteorder='big')
                ext_len = int.from_bytes(payload[pos+2:pos+4], byteorder='big')
                
                if ext_type == 0:
                    name_len = int.from_bytes(payload[pos+7:pos+9], byteorder='big')
                    sni = payload[pos+9:pos+9+name_len].decode('utf-8', errors='ignore')
                    return sni
                pos += 4 + ext_len
    except Exception:
        pass
    return None

def handle_detected_domain(client_ip, domain, source_type):
    """
    Hàm xử lý tập trung khi phát hiện một tên miền:
    Kiểm tra trùng lặp (Cooldown), check blacklist, log DB và gửi Discord Alert.
    """
    now_ts = time.time()
    if client_ip not in recent_logs:
        recent_logs[client_ip] = {}
    last_logged_time = recent_logs[client_ip].get(domain, 0)
    if now_ts - last_logged_time < COOLDOWN_SECONDS:
        return

    recent_logs[client_ip][domain] = now_ts

    reason = check_blacklist(domain)
    if reason:
        print(f"\033[91m[🚨 WARNING via {source_type}]\033[0m {client_ip} -> {domain} ({reason})")
        log_to_db(client_ip, domain, is_blocked=True, reason=reason)

        # --- KÍCH HOẠT GỬI TIN NHẮN TỚI DISCORD ---
        send_discord_alert(client_ip, domain, reason, source_type)
    else:
        print(f"\033[92m[🌐 NORMAL via {source_type}]\033[0m {client_ip} -> {domain}")
        log_to_db(client_ip, domain, is_blocked=False, reason="")

def process_packet(packet, target_ips):
    """
    Hàm callback được Scapy gọi liên tục mỗi khi bắt được gói tin trên card mạng.
    Bộ lọc phân tích chỉ nhắm vào luồng traffic của các thiết bị mục tiêu (target_ips).
    """
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src

        if src_ip in target_ips:
            # 1. Quét DNS (Cổng UDP 53)
            if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
                try:
                    if packet.haslayer(scapy.DNSQR):
                        domain = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                        if is_valid_domain(domain):
                            handle_detected_domain(src_ip, domain, source_type="DNS")
                except Exception:
                    pass

            # 2. Quét TLS SNI (Cổng TCP 443)
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 443:
                payload = bytes(packet[scapy.TCP].payload)
                if payload:
                    domain = extract_sni_raw(payload)
                    if domain and is_valid_domain(domain):
                        handle_detected_domain(src_ip, domain, source_type="TLS")

def start_sniffer(interface, target_ips, stop_event):
    print(f"[+] SNI Sniffer: Bắt đầu lắng nghe luồng mạng của {len(target_ips)} thiết bị...")
    scapy.sniff(
        iface=interface,
        filter="tcp port 443 or udp port 53",
        store=False,
        prn=lambda pkt: process_packet(pkt, target_ips),
        stop_filter=lambda p: stop_event.is_set()
    )

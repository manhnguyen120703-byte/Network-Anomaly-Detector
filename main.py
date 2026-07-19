# main.py
import os
import sys
import time
import sqlite3
import threading
import socket
import scapy.all as scapy

# Import modules
import arp_spoofer
import tls_sniffer
import app as web_app

DB_NAME = "anomaly_detector.db"
INTERFACE = "wlp3s0"
GATEWAY_IP = "192.168.1.1"      # Router IP
SUBNET_RANGE = "192.168.1.0/24" # Subnet

stop_event = threading.Event()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            domain TEXT PRIMARY KEY,
            reason TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tls_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            domain TEXT,
            is_blocked INTEGER,
            reason TEXT
        )
    ''')
    conn.close()

def get_my_ip():
    """Tự động lấy IP hiện tại của máy chạy tool"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def scan_network(subnet, gateway_ip, my_ip):
    """Quét ARP siêu tốc để tìm toàn bộ thiết bị đang Online"""
    print(f"[*] Hệ thống: Đang tiến hành quét dải mạng {subnet}...")
    active_ips = []
    try:
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        for element in answered_list:
            ip = element[1].psrc
            # Loại bỏ IP Router và IP của chính máy đang chạy tool
            if ip != gateway_ip and ip != my_ip:
                active_ips.append(ip)
    except Exception as e:
        print(f"[-] Lỗi quét mạng: {e}")
    return active_ips

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\033[91m[-] THẤT BẠI: Bạn phải dùng quyền root để chạy toàn hệ thống!\033[0m")
        sys.exit(1)
        
    init_db()
    
    my_ip = get_my_ip()
    print(f"[+] Máy giám sát (Local Host IP): {my_ip}")
    
    # Quét tìm thiết bị đang hoạt động
    target_ips = scan_network(SUBNET_RANGE, GATEWAY_IP, my_ip)
    
    print("\n" + "═"*70)
    print("🛡️  KÍCH HOẠT HỆ THỐNG GIÁM SÁT MẠNG - PHIÊN BẢN SOC GIA ĐÌNH  🛡️")
    print(f"📡 Số lượng thiết bị phát hiện đang online: {len(target_ips)} thiết bị.")
    if target_ips:
        print(f"📋 Danh sách IP giám sát: {', '.join(target_ips)}")
    print("═"*70 + "\n")

    if not target_ips:
        print("\033[91m[-] Không tìm thấy thiết bị nào khác đang online. Vui lòng kiểm tra lại kết nối mạng!\033[0m")
        sys.exit(1)

    try:
        # 1. Run module ARP Spoofing cho danh sách IP quét được
        arp_thread = threading.Thread(
            target=arp_spoofer.start_arp_spoof, 
            args=(target_ips, GATEWAY_IP, stop_event),
            name="ARPSpoofThread"
        )
        arp_thread.daemon = True
        arp_thread.start()
        
        # 2. Run module TLS Sniffer giám sát danh sách IP
        sniff_thread = threading.Thread(
            target=tls_sniffer.start_sniffer,
            args=(INTERFACE, target_ips, stop_event),
            name="SnifferThread"
        )
        sniff_thread.daemon = True
        sniff_thread.start()
        
        # 3. Run modules Flask Web Dashboard
        web_thread = threading.Thread(
            target=web_app.start_web,
            name="WebThread"
        )
        web_thread.daemon = True
        web_thread.start()
        
        print("\033[93m[!] Nhấn [Ctrl + C] để tắt toàn bộ hệ thống và khôi phục mạng.\033[0m")
        print("═"*70 + "\n")

        while not stop_event.is_set():
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\033[93m[-] Nhận lệnh tắt hệ thống. Đang dừng các luồng hoạt động...\033[0m")
        stop_event.set()
        time.sleep(3.5)
        print("\033[92m[+] Hệ thống đã tắt và khôi phục mạng của cả nhà an toàn!\033[0m")
        sys.exit(0)

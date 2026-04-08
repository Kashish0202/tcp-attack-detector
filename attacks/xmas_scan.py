from scapy.all import IP, TCP, sr1
import sys

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else '192.168.132.101'
PORTS = [21, 22, 23, 25, 80, 443, 8080]

print(f"[*] XMAS Scan -> {VICTIM_IP}")
for port in PORTS:
    # FIN + PSH + URG = 'FPU'
    pkt = IP(dst=VICTIM_IP) / TCP(dport=port, flags='FPU')
    resp = sr1(pkt, timeout=1, verbose=0)
    status = 'OPEN' if resp is None else 'CLOSED'
    print(f"  Port {port}: {status}")
print("[+] Done")
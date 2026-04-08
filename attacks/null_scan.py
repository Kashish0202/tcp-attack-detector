from scapy.all import IP, TCP, sr1
import sys

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else '192.168.132.101'
PORTS = [22, 80, 443, 3306]

print(f"[*] NULL Scan -> {VICTIM_IP}")
for port in PORTS:
    pkt = IP(dst=VICTIM_IP) / TCP(dport=port, flags=0)  # No flags
    resp = sr1(pkt, timeout=1, verbose=0)
    status = 'OPEN' if resp is None else 'CLOSED'
    print(f"  Port {port}: {status}")
print("[+] Done")

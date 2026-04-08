from scapy.all import IP, TCP, sr1
import sys

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else '192.168.132.101'
PORTS = [21, 22, 23, 25, 80, 443, 8080, 3306]

print(f"[*] FIN Scan -> {VICTIM_IP}")
for port in PORTS:
    pkt = IP(dst=VICTIM_IP) / TCP(dport=port, flags='F')
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp is None:
        print(f"  Port {port}: OPEN (no response)")
    else:
        print(f"  Port {port}: CLOSED (RST received)")
print("[+] Done")

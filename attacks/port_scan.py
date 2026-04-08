from scapy.all import IP, TCP, sr1, RandShort
import sys

VICTIM_IP = sys.argv[1] if len(sys.argv) > 1 else '192.168.132.101'
PORT_RANGE = range(1, 101)  # Scan ports 1-100

print(f"[*] SYN Port Scan -> {VICTIM_IP}")
open_ports = []
for port in PORT_RANGE:
    pkt = IP(dst=VICTIM_IP) / TCP(dport=port, sport=int(RandShort()), flags='S')
    resp = sr1(pkt, timeout=0.5, verbose=0)
    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 'SA':  # SYN-ACK = open
            open_ports.append(port)
            # Send RST to avoid full connection
            rst = IP(dst=VICTIM_IP) / TCP(dport=port, flags='R')
            send(rst, verbose=0)
print(f"[+] Open ports: {open_ports}")

from scapy.all import TCP, IP
import time

# Tracks connection state per (src_ip, dst_port)
from collections import defaultdict
syn_tracker   = defaultdict(list)   # src_ip -> [timestamps]
port_tracker  = defaultdict(set)    # src_ip -> set of ports hit
session_table = set()              # active sessions (src,dst,dport)

def extract_features(packet):
    """Extract a dict of features from a TCP packet."""
    ip  = packet[IP]
    tcp = packet[TCP]
    now = time.time()

    flags = tcp.flags   # e.g. 'S', 'SA', 'F', 'R', 'FPU', ''
    src   = ip.src
    dst   = ip.dst
    dport = tcp.dport
    seq   = tcp.seq

    # Track SYNs per source IP
    if 'S' in str(flags) and 'A' not in str(flags):
        syn_tracker[src].append(now)
        # Keep only last 1 second
        syn_tracker[src] = [t for t in syn_tracker[src] if now - t < 1.0]
        port_tracker[src].add(dport)
        session_table.add((src, dst, dport))

    return {
        "src_ip":       src,
        "dst_ip":       dst,
        "dport":        dport,
        "flags":        str(flags),
        "seq":          seq,
        "syn_rate":     len(syn_tracker[src]),
        "ports_hit":    len(port_tracker[src]),
        "has_session":  (src, dst, dport) in session_table,
        "timestamp":    now,
    }

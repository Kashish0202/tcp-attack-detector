from scapy.all import sniff, TCP, IP
from detector.features import extract_features
from detector.rules import check_rules
from detector.alert import log_alert
import time

def packet_callback(packet):
    """Called for every TCP packet captured."""
    if packet.haslayer(TCP) and packet.haslayer(IP):
        features = extract_features(packet)
        alert = check_rules(features)
        if alert:
            log_alert(alert)

def start_sniffing(interface=None):
    """Start capturing packets. interface=None means auto-detect."""
    print("[*] Starting TCP sniffer... Press Ctrl+C to stop")
    sniff(
        filter="tcp",
        prn=packet_callback,
        store=0,
        iface=interface
    )
if __name__ == "__main__":
    start_sniffing()

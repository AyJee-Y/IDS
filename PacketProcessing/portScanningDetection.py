from collections import defaultdict
import time
from scapy.all import IP, TCP, UDP

connections = defaultdict(lambda: defaultdict(list))

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 60

def analyze_packet(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        currentTime = time.time()

        connections[src_ip][dst_ip].append((dst_port, currentTime))
        connections[src_ip][dst_ip] = [
            (port, timestamp) for port, timestamp in connections[src_ip][dst_ip]
            if currentTime - timestamp <= PORT_SCAN_TIME_WINDOW
        ]

        unique_ports = set(port for port, _ in connections[src_ip][dst_ip])
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            print(f"PORT SCAN - FROM {dst_ip}")

def detectPortScan(packet):
    analyze_packet(packet)
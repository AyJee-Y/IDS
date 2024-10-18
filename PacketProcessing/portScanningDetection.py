from collections import defaultdict
import time
from scapy.all import IP, TCP, UDP
import threading

connections = defaultdict(lambda: defaultdict(list))

PORT_SCAN_THRESHOLD = 200
PORT_SCAN_TIME_WINDOW = 300

connectionsLock = threading.Lock()

CLEANUP_INTERVAL = 600

def analyze_packet(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        currentTime = time.time()

        with connectionsLock:
            connections[src_ip][dst_ip].append((dst_port, currentTime))
            connections[src_ip][dst_ip] = [
                (port, timestamp) for port, timestamp in connections[src_ip][dst_ip]
                if currentTime - timestamp <= PORT_SCAN_TIME_WINDOW
            ]

            unique_ports = set(port for port, _ in connections[src_ip][dst_ip])
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                print(f"PORT SCAN - FROM {dst_ip}")

def cleanUpOldPackets(stop_event):
    while not stop_event.is_set():
        time.sleep(CLEANUP_INTERVAL)
        performCleanup()

def performCleanup():
    current_time = time.time()
    with connectionsLock:
        for src_ip in list(connections.keys()):
            for dst_ip in list(connections[src_ip].keys()):
                connections[src_ip][dst_ip] = [
                    (port, timestamp) for port, timestamp in connections[src_ip][dst_ip]
                    if current_time - timestamp <= (CLEANUP_INTERVAL * 2)
                ]
                if not connections[src_ip][dst_ip]:
                    del connections[src_ip][dst_ip]
            if not connections[src_ip]:
                del connections[src_ip]

def detectPortScan(packet):
    analyze_packet(packet)
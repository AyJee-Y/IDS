import pandas as pd
import os
import copy
from threading import Lock
from scapy.all import TCP, UDP, IP, Raw

class suspiciousPacketLog:
    def __init__(self, logLocation):
        self.logLocation = logLocation

        if (os.path.exists(self.logLocation)):
            self.logDataFrame = pd.read_csv(suspiciousPacketLog)
        else:
            columns = ["TIME", "SRC", "SRC PORT", "DST", "DST PORT", "PROTOCOL", "DATA", "SUSPICION"]
            self.logDataFrame = pd.DataFrame(columns)
        
        self.lock = Lock()

    def logPacket(self, packet, suspicion):
        self.lock.acquire()

        timestamp = packet.time
        src = packet[IP].src
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
        dst = packet[IP].dst
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        data = packet[Raw].load.decode()
        protocol = "TCP" if TCP in packet else "UDP"

        newLog = {
            "TIME": timestamp,
            "SRC": src,
            "SRC_PORT": src_port,
            "DST": dst,
            "DST_PORT": dst_port,
            "PROTOCOL": protocol,
            "DATA": data,
            "SUSPICION": suspicion
        }
        df = df.append(newLog)
        df.to_csv(suspiciousPacketLog, index=True)

        self.lock.release()

    def receiveDataFrameCopy(self):
        self.lock.acquire()

        result = copy.deepcopy(self.logDataFrame)

        self.lock.release()

        return result
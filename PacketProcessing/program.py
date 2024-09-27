from scapy.all import sniff
from concurrent.futures import ThreadPoolExecutor

from payloadSignature import SignaturesBasedDetection_Payloads

analyzationFunctions = [SignaturesBasedDetection_Payloads]
executor = ThreadPoolExecutor(max_workers = len(analyzationFunctions))

def packet_handler(packet):
    for func in analyzationFunctions:
        executor.submit(func, packet)

def startPacketSniffing():
    sniff(prn = packet_handler, store = 0)

if __name__ == '__main__':
    startPacketSniffing()
from scapy.all import sniff
from concurrent.futures import ThreadPoolExecutor

analyzationFunctions = []
executor = ThreadPoolExecutor(max_workers = len(analyzationFunctions))

def packet_handler(packet):
    for func in analyzationFunctions:
        executor.submit(func, packet)

def startPacketSniffing():
    sniff(prn = packet_handler, store = 0)
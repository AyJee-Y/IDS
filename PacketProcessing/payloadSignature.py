import re
from scapy.all import sniff, TCP, UDP, IP, Raw

payloadSignatures = {
    "SQL Injection" : "(?i)(\%27|\'|--|\%23|#|(\b(select|union|insert|update|delete|drop|where|having|or|and)\b))",
    "XSS" : "(?i)(<script.*?>|javascript:|on\w+\s*=\s*['\"]?[^'\">]*['\"]?)",
    "Command Injection" : "(?i)(\b(exec|cmd|system|shell|cmd\.exe|/bin/sh|/bin/bash)\b)",
    "Directory Traversal" : "(\.\./|\.\.\\|%2e%2e|%2f|%5c)",
    "Remote File Inclusion" : "(?i)(\b(include|require|file_get_contents)\b.*?((http|ftp|https)://|www\.))",
    "Malicious File Upload" : "(?i)\.(php|pl|cgi|py|jsp|asp|exe|sh|bat)$",
}

def SignaturesBasedDetection_Payloads(packet):
    if TCP in packet:
        if IP in packet and Raw in packet:
            try:
                data = packet[Raw].load.decode()
                for i in payloadSignatures.keys():
                    if (re.search(payloadSignatures[i], data)):
                        print(f"{i} attack detected")
                        print(f"SRC_IP: {packet[IP].src}, SRC_PORT: {packet[TCP].sport}")
                        print(f"Packet data: {data}")
                        print("--------------------------------------------------------------")
            except:
                return
    if UDP in packet:
        if IP in packet and Raw in packet:
            try:
                data = packet[Raw].load.decode()
                for i in payloadSignatures.keys():
                    if (re.search(payloadSignatures[i], data)):
                        print(f"{i} attack detected")
                        print(f"SRC_IP: {packet[IP].src}, SRC_PORT: {packet[UDP].sport}")
                        print(f"Packet data: {data}")
                        print("--------------------------------------------------------------")
            except:
                return
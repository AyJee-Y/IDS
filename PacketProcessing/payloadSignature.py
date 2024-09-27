import re
from scapy.all import sniff, TCP, UDP

payloadSignatures = {
    "SQL Injection" : "(?i)(\%27|\'|--|\%23|#|(\b(select|union|insert|update|delete|drop|where|having|or|and)\b))",
    "XSS" : "(?i)(<script.*?>|javascript:|on\w+\s*=\s*['\"]?[^'\">]*['\"]?)",
    "Command Injection" : "(?i)(\b(exec|cmd|system|shell|cmd\.exe|/bin/sh|/bin/bash)\b)",
    "Directory Traversal" : "(\.\./|\.\.\\|%2e%2e|%2f|%5c)",
    "Remote File Inclusion" : "(?i)(\b(include|require|file_get_contents)\b.*?((http|ftp|https)://|www\.))",
    "Malicious File Upload" : "(?i)\.(php|pl|cgi|py|jsp|asp|exe|sh|bat)$",
    "Malware" : "([A-Za-z0-9+/]{4}){2,}([A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]?[=]{0,2})?",
    "Suspicious URL" : "(?i)(%[0-9a-f]{2}|[&?]{1}(?:[^=]+=[^&]*)+|[?&]{1}.*[=|&]{1}.+)"
}

def SignaturesBasedDetection_Payloads(packet):
    if TCP in packet:
        tcp_payload = packet[TCP].payload
        for i in payloadSignatures.keys():
            if (re.search(payloadSignatures[i], tcp_payload)):
                print(f"{i} attack detected")
                print(packet.show())
                print()
    elif UDP in packet:
        udp_payload = packet[UDP].payload
        for i in payloadSignatures.keys():
            if (re.search(payloadSignatures[i], udp_payload)):
                print(f"{i} attack detected")
                print(packet.show())
                print()
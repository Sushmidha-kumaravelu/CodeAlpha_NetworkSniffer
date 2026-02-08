from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n==============================")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        if TCP in packet:
            print("Protocol Type  : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol Type  : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

        if packet.haslayer('Raw'):
            print(f"Payload        : {bytes(packet['Raw'])[:50]}")

print("Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)

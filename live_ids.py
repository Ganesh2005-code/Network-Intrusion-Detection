from scapy.all import sniff, IP, TCP, UDP
import time


# ==========================================
# Live Packet Handler
# ==========================================

packet_number = 0


def process_packet(packet):

    global packet_number

    if IP not in packet:
        return

    packet_number += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = packet[IP].proto

    packet_length = len(packet)

    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        protocol_name = "TCP"

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        protocol_name = "UDP"

    else:
        protocol_name = str(protocol)

    print("\n" + "=" * 60)

    print(f"Packet #{packet_number}")

    print(f"Source IP       : {source_ip}")

    print(f"Destination IP  : {destination_ip}")

    print(f"Protocol        : {protocol_name}")

    print(f"Source Port     : {source_port}")

    print(f"Destination Port: {destination_port}")

    print(f"Packet Size     : {packet_length} bytes")

    print("=" * 60)


# ==========================================
# Start Live Capture
# ==========================================

print("\n==========================================")
print("   NETWORK INTRUSION DETECTION SYSTEM")
print("==========================================")

print("Starting live packet capture...")

print("Press CTRL+C to stop.\n")


sniff(
    prn=process_packet,
    store=False
)
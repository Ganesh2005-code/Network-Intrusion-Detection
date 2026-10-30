from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


# ==========================================
# Packet Counter
# ==========================================

packet_count = 0


# ==========================================
# Process Captured Packet
# ==========================================

def process_packet(packet):

    global packet_count

    packet_count += 1

    print("\n" + "=" * 60)

    print(f"Packet #{packet_count}")

    print(
        "Time:",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    # ======================================
    # Check IP Layer
    # ======================================

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)

        # ==================================
        # TCP Packet
        # ==================================

        if TCP in packet:

            print("Protocol: TCP")

            print(
                "Source Port:",
                packet[TCP].sport
            )

            print(
                "Destination Port:",
                packet[TCP].dport
            )

            print(
                "TCP Flags:",
                packet[TCP].flags
            )

        # ==================================
        # UDP Packet
        # ==================================

        elif UDP in packet:

            print("Protocol: UDP")

            print(
                "Source Port:",
                packet[UDP].sport
            )

            print(
                "Destination Port:",
                packet[UDP].dport
            )

        # ==================================
        # Other IP Protocol
        # ==================================

        else:

            print("Protocol: Other")

    else:

        print("Non-IP Packet")

    # ======================================
    # Packet Size
    # ======================================

    print(
        "Packet Size:",
        len(packet),
        "bytes"
    )


# ==========================================
# Start Packet Capture
# ==========================================

print("=" * 60)

print("LIVE NETWORK PACKET CAPTURE")

print("=" * 60)

print("Starting packet capture...")

print("Press CTRL + C to stop.")

print()


try:

    sniff(
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:

    print("\n")
    print("=" * 60)
    print("Packet capture stopped.")
    print("Total packets captured:", packet_count)
    print("=" * 60)
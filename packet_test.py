from scapy.all import sniff

print("Starting packet capture...")
print("Capture 10 packets...")

packets = sniff(count=10)

print("\nCaptured packets:", len(packets))

for i, packet in enumerate(packets, start=1):
    print(f"\nPacket #{i}")
    print(packet.summary())
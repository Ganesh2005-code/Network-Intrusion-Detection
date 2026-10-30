from scapy.all import sniff

from feature_extractor import process_packet


print("=" * 60)
print("LIVE FEATURE EXTRACTION TEST")
print("=" * 60)

print("Capturing 10 packets...")
print()


def handle_packet(packet):

    result = process_packet(packet)

    if result:

        print(result)


sniff(
    count=10,
    prn=handle_packet,
    store=False
)


print()
print("=" * 60)
print("Feature extraction test completed.")
print("=" * 60)
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        protocol_name = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }.get(proto, 'Other')

        print(f"\n[+] Packet Captured:")
        print(f"    Protocol      : {protocol_name}")
        print(f"    Source IP     : {src_ip}")
        print(f"    Destination IP: {dst_ip}")

        # TCP or UDP ports
        if TCP in packet:
            print(f"    Source Port   : {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    Source Port   : {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")

        # Payload (if available)
        if Raw in packet:
            raw_data = packet[Raw].load
            try:
                print(f"    Payload       : {raw_data.decode(errors='ignore')}")
            except:
                print(f"    Payload       : (Binary Data)")

def main():
    print("=== Network Packet Analyzer ===")
    print("Sniffing... Press Ctrl+C to stop.\n")

    # Sniff only IP packets (you can change filter if needed)
    sniff(filter="ip", prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()

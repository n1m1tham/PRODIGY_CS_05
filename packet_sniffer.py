from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the protocol and capture relevant information
        if protocol == 6:  # TCP
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol_name = "Other"
            src_port = None
            dst_port = None

        # Print packet information
        print(f"[{protocol_name}] {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        
        # Display payload data if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = packet[Raw].load if packet.haslayer(Raw) else None
            if payload:
                print(f"Payload: {payload}\n")
    else:
        print("Non-IP Packet detected")

# Start sniffing
print("Starting packet sniffing... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Function to process captured packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Display basic IP information
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
        # Check for TCP or UDP layer
        if proto == 6:  # TCP
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                print(f"Protocol: TCP")
                print(f"Source Port: {tcp_layer.sport}")
                print(f"Destination Port: {tcp_layer.dport}")
                print(f"Payload: {bytes(tcp_layer.payload)}")
        elif proto == 17:  # UDP
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                print(f"Protocol: UDP")
                print(f"Source Port: {udp_layer.sport}")
                print(f"Destination Port: {udp_layer.dport}")
                print(f"Payload: {bytes(udp_layer.payload)}")
        else:
            print(f"Protocol: {proto}")
        print("\n")

# Start sniffing
print("Starting packet capture...")
sniff(prn=packet_callback, store=0)

import threading
import keyboard
from scapy.all import sniff, wrpcap, get_if_list, IP, TCP, UDP, ICMP

# List to store captured packets
captured_packets = []
stop_sniffing = False

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        print(f"\n[IP Packet] Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check for TCP
        if TCP in packet:
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            payload = bytes(tcp_layer.payload)
            print(f"[TCP Segment] Source IP: {src_ip}:{src_port} -> Destination IP: {dst_ip}:{dst_port} | Payload: {payload}")

        # Check for UDP
        elif UDP in packet:
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            payload = bytes(udp_layer.payload)
            print(f"[UDP Datagram] Source IP: {src_ip}:{src_port} -> Destination IP: {dst_ip}:{dst_port} | Payload: {payload}")

        # Check for ICMP
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            payload = bytes(icmp_layer.payload)
            print(f"[ICMP Packet] Type: {icmp_type}, Code: {icmp_code} | Payload: {payload}")

        # Add the packet to the list
        captured_packets.append(packet)

def stop_sniffer():
    global stop_sniffing
    stop_sniffing = True

def packet_sniffer(iface):
    sniff(iface=iface, prn=analyze_packet, stop_filter=lambda x: stop_sniffing)

# List all network interfaces
interfaces = get_if_list()
print("Available interfaces:")
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")

# Ask user to select an interface
while True:
    try:
        iface_index = int(input("Select the interface index to sniff on: "))
        if iface_index < 0 or iface_index >= len(interfaces):
            raise IndexError
        iface = interfaces[iface_index]
        break
    except (ValueError, IndexError):
        print("Invalid index. Please try again.")

print(f"Sniffing on interface: {iface}")

# Start the packet sniffer in a separate thread
sniffer_thread = threading.Thread(target=packet_sniffer, args=(iface,))
sniffer_thread.start()

# Wait for the user to press the Esc key to stop sniffing
print("Press Esc to stop sniffing...")
keyboard.wait('esc')
stop_sniffer()

# Wait for the sniffer thread to finish
sniffer_thread.join()

# Save captured packets to a file
output_file = 'captured_packets.pcap'
wrpcap(output_file, captured_packets)
print(f"\nCaptured packets saved to {output_file}")

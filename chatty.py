import pyshark
from collections import defaultdict
import operator

# Function to analyze the pcap and find the top talkers including ports and protocols
def analyze_network_traffic(pcap_file_path, output_file_path):
    # Create a dictionary to hold pair-wise traffic counts
    traffic_counter = defaultdict(int)

    # Read the pcap file
    cap = pyshark.FileCapture(pcap_file_path)

    for packet in cap:
        try:
            # Check if the packet contains IP layer information
            if 'IP' in packet:
                protocol = 'Unknown'
                src_port, dst_port = 'N/A', 'N/A'

                # Check for TCP and UDP layers
                if 'TCP' in packet:
                    protocol = 'TCP'
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                elif 'UDP' in packet:
                    protocol = 'UDP'
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport

                # Create a tuple of the source, destination, ports, and protocol
                src_dst_pair = (packet.ip.src, packet.ip.dst, src_port, dst_port, protocol)
                
                # Increment the traffic count for this src-dest pair
                traffic_counter[src_dst_pair] += int(packet.length)
        except AttributeError:
            # Skip packets that don't have the required information
            continue

    # Sort the traffic counts from highest to lowest
    sorted_traffic = sorted(traffic_counter.items(), key=operator.itemgetter(1), reverse=True)

    # Write the sorted results to the output file
    with open(output_file_path, 'w') as output_file:
        for pair, count in sorted_traffic:
            output_file.write(f"{pair[0]}:{pair[2]} -> {pair[1]}:{pair[3]} ({pair[4]}): {count} bytes\n")

# Prompt the user for the path to the pcap file
pcap_file_path = input("Enter the path to your pcap file: ")

# Specify the output file path
output_file_path = "chatty.txt"

# Analyze the pcap file for top talkers including ports and protocols
analyze_network_traffic(pcap_file_path, output_file_path)

print(f"Network traffic analysis complete. Results are saved in {output_file_path}.")

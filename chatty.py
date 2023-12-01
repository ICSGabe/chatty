import pyshark
from collections import defaultdict
import operator

# Function to analyze the pcap and find the top talkers
def analyze_network_traffic(pcap_file_path, output_file_path):
    # Create a dictionary to hold pair-wise traffic counts
    traffic_counter = defaultdict(int)

    # Read the pcap file
    cap = pyshark.FileCapture(pcap_file_path)

    for packet in cap:
        try:
            # Check if the packet contains IP layer information
            if 'IP' in packet:
                # Create a tuple of the source and destination
                src_dst_pair = (packet.ip.src, packet.ip.dst)
                # Increment the traffic count for this src-dest pair
                traffic_counter[src_dst_pair] += int(packet.length)
        except AttributeError:
            # Skip packets that don't have IP layer information
            continue

    # Sort the traffic counts from highest to lowest
    sorted_traffic = sorted(traffic_counter.items(), key=operator.itemgetter(1), reverse=True)

    # Write the sorted results to the output file
    with open(output_file_path, 'w') as output_file:
        for pair, count in sorted_traffic:
            output_file.write(f"{pair[0]} -> {pair[1]}: {count} bytes\n")

# Prompt the user for the path to the pcap file
pcap_file_path = input("Enter the path to your pcap file: ")

# Specify the output file path
output_file_path = "chatty.txt"

# Analyze the pcap file for top talkers
analyze_network_traffic(pcap_file_path, output_file_path)

print(f"Network traffic analysis complete. Results are saved in {output_file_path}.")

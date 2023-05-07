import os
import subprocess
import sys
import shutil
import re
from collections import Counter

# Define the function to check if the script is being run as root
def check_root():
    if not os.geteuid() == 0:
        print("This script must be run as root.")
        sys.exit()

# Define the function to check if tshark is installed and install it if necessary
def check_tshark():
    if not shutil.which("tshark"):
        print("tshark is not installed. Installing...")
        # Detect the operating system and use the appropriate install command
        if platform.system() == "Linux":
            os.system("sudo apt-get update")
            os.system("sudo apt-get install -y tshark")
        elif platform.system() == "Darwin":
            os.system("brew update")
            os.system("brew install tshark")
        else:
            print("Sorry, this script only supports Linux and macOS.")
            exit()

# Define the function to scan for top source IP addresses
def scan_top_source_ips(pcap_file):
    # Run the tshark command to extract source IP addresses
    source_ips = subprocess.check_output(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.src"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Count the occurrences of each source IP address
    source_ip_counts = {}
    for source_ip in source_ips:
        if source_ip not in source_ip_counts:
            source_ip_counts[source_ip] = 1
        else:
            source_ip_counts[source_ip] += 1

    # Sort the source IP addresses by count
    sorted_source_ips = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Display the top 10 source IP addresses
    print()
    print("Top 10 Source IP Addresses:")
    print()
    print("Rank\tCount\tSource IP")
    for i, item in enumerate(sorted_source_ips[:10]):
        print(f"{i+1}\t{item[1]}\t{item[0]}")

    # Ask if the user wants to display the rest of the source IP addresses
    if len(sorted_source_ips) > 10:
        print()
        choice = input("Would you like to display the rest of the Source IP addresses? (y/n) ")
        if choice.lower() == "y":
            print()
            print("Source IP addresses:")
            print()
            print("Count\tSource IP address")
            for source_ip in sorted_source_ips[10:]:
                print(f"{source_ip[1]}\t{source_ip[0]}")

# Define the function to scan for top source ports
def scan_top_source_ports(pcap_file):
    # Run the tshark command to extract source ports
    source_ports = subprocess.check_output(["tshark", "-r", pcap_file, "-T", "fields", "-e", "tcp.srcport"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Count the occurrences of each source port
    source_port_counts = {}
    for source_port in source_ports:
        if source_port not in source_port_counts:
            source_port_counts[source_port] = 1
        else:
            source_port_counts[source_port] += 1

    # Sort the source ports by count
    sorted_source_ports = sorted(source_port_counts.items(), key=lambda x: x[1], reverse=True)

    # Display the top 10 source ports
    print()
    print("Top 10 Source Ports:")
    print()
    print("Rank\tCount\tSource Port")
    for i, item in enumerate(sorted_source_ports[:10]):
        print(f"{i+1}\t{item[1]}\t{item[0]}")

    # Ask if the user wants to display the rest of the source ports
    if len(sorted_source_ports) > 10:
        print()
        choice = input("Would you like to display the rest of the Source Ports? (y/n) ")
        if choice.lower() == "y":
            print()
            print("Source Ports:")
            print()
            print("Count\tSource Port")
            for source_port in sorted_source_ports[10:]:
                print(f"{source_port[1]}\t{source_port[0]}")

# Define the function to scan for top destination IPs
def scan_top_dest_ips(pcap_file):
    # Run the tshark command to extract destination IP addresses
    dest_ips = subprocess.check_output(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.dst"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Count the occurrences of each destination IP address
    dest_ip_counts = {}
    for dest_ip in dest_ips:
        if dest_ip not in dest_ip_counts:
            dest_ip_counts[dest_ip] = 1
        else:
            dest_ip_counts[dest_ip] += 1

    # Sort the destination IP addresses by count
    sorted_dest_ips = sorted(dest_ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Display the top 10 destination IP addresses
    print()
    print("Top 10 Destination IP Addresses:")
    print()
    print("Rank\tCount\tDestination IP")
    for i, item in enumerate(sorted_dest_ips[:10]):
        print(f"{i+1}\t{item[1]}\t{item[0]}")

    # Ask if the user wants to display the rest of the destination IP addresses
    if len(sorted_dest_ips) > 10:
        print()
        choice = input("Would you like to display the rest of the Destination IP addresses? (y/n) ")
        if choice.lower() == "y":
            print()
            print("Destination IP addresses:")
            print()
            print("Count\tDestination IP address")
            for dest_ip in sorted_dest_ips[10:]:
                print(f"{dest_ip[1]}\t{dest_ip[0]}")
                
# Define the function to scan for top destination Ports
def scan_top_dest_ports(pcap_file):
    # Run the tshark command to extract destination ports
    destination_ports = subprocess.check_output(["tshark", "-r", pcap_file, "-T", "fields", "-e", "tcp.dstport"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Count the occurrences of each destination port
    destination_port_counts = {}
    for destination_port in destination_ports:
        if destination_port not in destination_port_counts:
            destination_port_counts[destination_port] = 1
        else:
            destination_port_counts[destination_port] += 1

    # Sort the destination ports by count
    sorted_destination_ports = sorted(destination_port_counts.items(), key=lambda x: x[1], reverse=True)

    # Display the top 10 destination ports
    print()
    print("Top 10 Destination Ports:")
    print()
    print("Rank\tCount\tDestination Port")
    for i, item in enumerate(sorted_destination_ports[:10]):
        print(f"{i+1}\t{item[1]}\t{item[0]}")

    # Ask if the user wants to display the rest of the destination ports
    if len(sorted_destination_ports) > 10:
        print()
        choice = input("Would you like to display the rest of the Destination Ports? (y/n) ")
        if choice.lower() == "y":
            print()
            print("Destination Ports:")
            print()
            print("Count\tDestination Port")
            for destination_port in sorted_destination_ports[10:]:
                print(f"{destination_port[1]}\t{destination_port[0]}")

# Define the function to scan for user agents
def scan_user_agents(pcap_file):
    # Run the tshark command to extract User-Agent field
    user_agents = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "http.user_agent", "-T", "fields", "-e", "http.user_agent"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Count the occurrences of each User-Agent string
    user_agent_counts = {}
    for user_agent in user_agents:
        if user_agent not in user_agent_counts:
            user_agent_counts[user_agent] = 1
        else:
            user_agent_counts[user_agent] += 1

    # Sort the User-Agent strings by count
    sorted_user_agents = sorted(user_agent_counts.items(), key=lambda x: x[1], reverse=True)

    # Display the top 10 user agents
    print()
    print("Top 10 User Agents:")
    print()
    print("Rank\tCount\tUser Agent")
    for i, item in enumerate(Counter(user_agents).most_common(10)):
        print(f"{i+1}\t{item[1]}\t{item[0]}")

    # Offer to display the rest of the User-Agent strings
    if len(sorted_user_agents) > 10:
        print()
        choice = input("Would you like to display the rest of the User-Agent strings? (y/n) ")
        if choice.lower() == "y":
            print()
            print("User-Agent strings:")
            print()
            print("Count\tUser-Agent string")
            for user_agent in sorted_user_agents[10:]:
                print(f"{user_agent[1]}\t{user_agent[0]}")

# Define the function to scan for DNS queries
def scan_dns_queries(pcap_file):
    # Run the tshark command to extract DNS query names
    dns_query_names = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "dns.flags.response == 0 and dns.qry.type == 1", "-T", "fields", "-e", "dns.qry.name"], stderr=subprocess.DEVNULL).decode().splitlines()

    sorted_dns_queries = sorted(Counter(dns_query_names).items(), key=lambda x: x[1], reverse=True)

    # Define a function to get the protocol for a DNS query name
    def get_protocol(query_name):
        if query_name.endswith(".local"):
            return "LLMNR"
        elif query_name.endswith(".arpa"):
            return "Reverse DNS"
        elif re.match(r"\d+\.\d+\.\d+\.\d+", query_name):
            return "PTR"
        else:
            return "DNS"

    # Display the top 10 DNS query names
    print()
    print("Top 10 DNS query names:")
    print()
    print("Rank\tCount\tQuery Name".ljust(50) + "Protocol")
    for i, item in enumerate(sorted_dns_queries[:10]):
        protocol = get_protocol(item[0])
        query_name = item[0].ljust(50)
        print(f"{i+1}\t{item[1]}\t{query_name}\t{protocol}")

    # Ask if the user wants to display the rest of the DNS query names
    print()
    choice = input("\nDo you want to display the rest of the DNS query names? (y/n) ")
    if choice.lower() == "y":
        print()
        print("Rank\tCount\tQuery Name".ljust(50) + "Protocol")
        for i, item in enumerate(sorted_dns_queries[10:]):
            protocol = get_protocol(item[0])
            query_name = item[0].ljust(50)
            print(f"{i+11}\t{item[1]}\t{query_name}\t{protocol}")

    # Ask if the user wants to do another hunt
    choice = input("\nDo you want to do another hunt? (y/n) ")
    if choice.lower() == "y":
        menu(pcap_file)
    else:
        print("Goodbye!")
        exit()

# Define the function to scan for stealth port scans
def scan_stealth_port_scans(pcap_file):
    # Run the tshark command to extract SYN, SYN+ACK, RST and RST+ACK packets
    syn_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "tcp.flags==0x002", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport"], stderr=subprocess.DEVNULL).decode().splitlines()
    synack_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "tcp.flags==0x012", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport"], stderr=subprocess.DEVNULL).decode().splitlines()
    rst_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "tcp.flags==0x004", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport"], stderr=subprocess.DEVNULL).decode().splitlines()
    rstack_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "tcp.flags==0x014", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Combine the packets into a single list and remove duplicates
    stealth_packets = list(set(syn_packets + synack_packets + rst_packets + rstack_packets))

    # Display the IP addresses and ports that were scanned
    print()
    print("Stealth port scan IP addresses and ports:")
    print()
    print("Source IP\tDestination IP\tSource Port\tDestination Port")
    for packet in stealth_packets:
        packet_fields = packet.split("\t")
        print(f"{packet_fields[0]}\t{packet_fields[1]}\t{packet_fields[2]}\t{packet_fields[3]}")

# Define the function to scan for ping sweeps
def scan_ping_sweeps(pcap_file):
    # Run the tshark command to extract ICMP type 8 packets and TCP and UDP packets with destination port 7
    icmp_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "icmp.type==8", "-T", "fields", "-e", "ip.src", "-e", "ip.dst"], stderr=subprocess.DEVNULL).decode().splitlines()
    tcp_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "tcp.dstport==7", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "eth.src", "-e", "eth.dst"], stderr=subprocess.DEVNULL).decode().splitlines()
    udp_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "udp.dstport==7", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "eth.src", "-e", "eth.dst"], stderr=subprocess.DEVNULL).decode().splitlines()

        # Combine the packets into a single list and remove duplicates
    ping_packets = list(set(icmp_packets + tcp_packets + udp_packets))

    # Display the IP addresses that were scanned
    print()
    print("Ping sweep IP addresses:")
    print()
    for packet in ping_packets:
        packet_fields = packet.split("\t")
        print(packet_fields[0])
        print(packet_fields[1])

# Define the function to scan for ARP sweeps
def scan_arp_sweeps(pcap_file):
    # Run the tshark command to extract ARP requests and responses
    arp_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "arp.opcode==1 or arp.opcode==2", "-T", "fields", "-e", "arp.src.hw_mac", "-e", "arp.src.proto_ipv4", "-e", "arp.dst.hw_mac", "-e", "arp.dst.proto_ipv4"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Combine the packets into a single list and remove duplicates
    arp_requests = []
    arp_responses = []
    for packet in arp_packets:
        packet_fields = packet.split("\t")
        if packet_fields[0] not in arp_requests and packet_fields[1] != "0.0.0.0":
            arp_requests.append(packet_fields[0])
        if packet_fields[2] not in arp_responses and packet_fields[3] != "0.0.0.0":
            arp_responses.append(packet_fields[2])

    # Display the MAC addresses and IP addresses that were scanned
    print()
    print("ARP sweep MAC addresses and IP addresses:")
    print()
    print("MAC address\t\t\tIP address")
    for mac_address in arp_requests + arp_responses:
        print(f"{mac_address[:2]}:{mac_address[2:4]}:{mac_address[4:6]}:{mac_address[6:8]}:{mac_address[8:10]}:{mac_address[10:]}")

# Define the function to scan for Xmas scans
def scan_xmas_scans(pcap_file):
    # Run the tshark command to extract Xmas scan packets
    xmas_packets = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", "tcp.flags==0x029", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport"], stderr=subprocess.DEVNULL).decode().splitlines()

    # Display the IP addresses and ports that were scanned
    print()
    print("Xmas scan IP addresses and ports:")
    print()
    print("Source IP\tDestination IP\tSource Port\tDestination Port")
    for packet in xmas_packets:
        packet_fields = packet.split("\t")
        print(f"{packet_fields[0]}\t{packet_fields[1]}\t{packet_fields[2]}\t{packet_fields[3]}")

# Define the http packet counter function
def http_packet_counter(pcap_file):
    # Run the tshark command to extract HTTP packet counts
    http_packet_counts = subprocess.check_output(["tshark", "-q", "-r", pcap_file, "-z", "http,tree"], stderr=subprocess.DEVNULL).decode()
    # Print the HTTP packet counts
    print("HTTP packet counts:\n")
    print(http_packet_counts)

# Define the menu options
def menu(pcap_file):
    while True:
        # Clear the screen
        os.system("clear")

        # Print ASCII art
        print("#     #                            #####                              ")
        print("##   ##   ##    ####  #  ####     #     # #    #   ##   #####  #    # ")
        print("# # # #  #  #  #    # # #    #    #       #    #  #  #  #    # #   #  ")
        print("#  #  # #    # #      # #          #####  ###### #    # #    # ####   ")
        print("#     # ###### #  ### # #               # #    # ###### #####  #  #   ")
        print("#     # #    # #    # # #    #    #     # #    # #    # #   #  #   #  ")
        print("#     # #    #  ####  #  ####      #####  #    # #    # #    # #    # ")
        print("\n\n")
        print("By: Brian Dorr")

        # Display the menu options
        print("\nSelect a scan option:")
        print()
        print("1. Top source IPs")
        print("2. Top source ports")
        print("3. Top destination IP addresses")
        print("4. Top destination ports")
        print("5. DNS query Scan")
        print("6. User-Agent Scan")
        print("7. HTTP/Packet Counter")
        print("8. Stealth port scan")
        print("9. Ping sweep scan")
        print("10. ARP sweep scan")
        print("11. Xmas scan")
        print("12. Quit")

        # Get the user's choice
        choice = input("\nEnter your choice: ")

        if choice == "1":
           scan_top_source_ips(pcap_file)
        elif choice == "2":
           scan_top_source_ports(pcap_file)
        elif choice == "3":
           scan_top_dest_ips(pcap_file)
        elif choice == "4":
           scan_top_dest_ports(pcap_file)
        elif choice == "5":
           scan_dns_queries(pcap_file)
        elif choice == "6":
           scan_user_agents(pcap_file)
        elif choice == "7":
           http_packet_counter(pcap_file)
        elif choice == "8":
           scan_stealth_port_scans(pcap_file)
        elif choice == "9":
           scan_ping_sweeps(pcap_file)
        elif choice == "10":
           scan_arp_sweeps(pcap_file)
        elif choice == "11":
           scan_xmas_scans(pcap_file)
        elif choice == "12":
           print("Exiting program.")
           break
        else:
           print("Invalid choice. Please enter a number from 1-12.")


        # Offer to do another scan
        choice = input("\nWould you like to do another scan? (y/n) ")
        if choice.lower() != "y":
            print("Exiting program.")
            break

        # Ask if user wants to clear the screen
        choice = input("\nClear screen? (y/n) ")
        if choice.lower() == "y":
            os.system("clear")

if __name__ == "__main__":
    # Get the name of the pcap file to analyze
    if len(sys.argv) == 2:
        pcap_file = sys.argv[1]
    else:
        print("Please provide the name of a pcap file to analyze.")
        sys.exit()

    # Check if tshark is installed
    check_tshark()

    # Check if the script is being run as root
    check_root()

    # Run the menu
    menu(pcap_file)




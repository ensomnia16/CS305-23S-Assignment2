from scapy.all import *

conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
ackss = []

def packet_info(pcap_file, save_file):
    stream = []
    # Open the pcap file
    packets = rdpcap(pcap_file)

    # Loop through all packets in the pcap file
    with open(save_file, 'w') as f:
        for packet in packets:
            # Check if the packet is an IP packet
            if 'IP' in packet and [packet['IP'].src, packet['TCP'].sport, packet['IP'].dst,
                                   packet['TCP'].dport] not in stream:
                # Print the source and destination IP addresses and ports
                stream.append([packet['IP'].src, packet['TCP'].sport, packet['IP'].dst, packet['TCP'].dport])
                f.write("{}:{} -> {}:{}\n".format(packet['IP'].src, packet['TCP'].sport, packet['IP'].dst,
                                                   packet['TCP'].dport))


def tcp_stream_analyzer_(pcap, connection):
        # Split the string at the "->" symbol
    ip1_port1, ip2_port2 = connection.split(" -> ")

    # Split the IP address and port number for the first IP address
    ip1, port1 = ip1_port1.split(":")

    # Split the IP address and port number for the second IP address
    ip2, port2 = ip2_port2.split(":")

    # Create a tuple with the four elements
    result = (pcap, '12331.txt', ip1, ip2, int(port1), int(port2))
    tcp_stream_analyzer(*result)
    print(ackss)

# iterate over each packet in the pcap file
def tcp_stream_analyzer(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    # read the pcap file
    packets = rdpcap(file)
    print(packets)
    # packets = packets.sort(key=sorter)

    # initialize variables for tracking the TCP stream

    ini_seq_client = 0
    ini_seq_server = 0
    seq_num = None
    ack_num = None
    window_size = None
    packet_num = 0
    server_ip = None
    client_ip = None
    if_not_write = True

    with open(savefile, 'w') as f:
        for packet in packets:
            # extract the source and destination IP addresses and port numbers
            layer = ''
            if packet.haslayer('IP'):
                layer = 'IP'
            elif packet.haslayer('IPv6'):
                layer = 'IPv6'

            src_ip = packet[layer].src
            dst_ip = packet[layer].dst
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport

            # check if this packet belongs to the same TCP stream as the previous packet
            if (src_ip, dst_ip, src_port, dst_port) not in (
                    (client_ip_prev, server_ip_prev, client_port_prev, server_port_prev),
                    (server_ip_prev, client_ip_prev, server_port_prev, client_port_prev)):
                seq_num = None
                ack_num = None
                window_size = None
                continue
            else:
                packet_num += 1

            # initialize the sequence numbers for the client and server
            if ini_seq_server == 0 or ini_seq_client == 0:
                if packet_num == 1:
                    client_ip = packet[layer].src
                    server_ip = packet[layer].dst
                    ini_seq_client = packet['TCP'].seq
                elif packet_num == 2:
                    ini_seq_server = packet['TCP'].seq

            if if_not_write:
                f.write(f"Server : {server_ip}:{dst_port} <-> Client : {client_ip}:{src_port} \n")
                if_not_write = False

            # extract the sequence and acknowledgement numbers and window size
            if packet.haslayer('TCP'):
                if packet[layer].src == client_ip:
                    seq_num = packet['TCP'].seq - ini_seq_client
                elif packet[layer].src == server_ip:
                    seq_num = packet['TCP'].seq - ini_seq_server
                if packet[layer].src == client_ip:
                    ack_num = packet['TCP'].ack - ini_seq_server
                elif packet[layer].src == server_ip:
                    ack_num = packet['TCP'].ack - ini_seq_client
                

                flag = packet['TCP'].sprintf("%flags%")

                f.write(
                    f"{'Client' if packet[layer].src == client_ip else 'Server'} -> "
                    f"{'Client' if packet[layer].dst == client_ip else 'Server'} Num: {packet_num}, SEQ: {seq_num}, "
                    f"ACK: {ack_num} {flag}\n")
                ackss.append(ack_num)


def http_stream_analyzer(pcapfile, savefile, client_ip_prev, server_ip_prev, client_port_prev):
    # analyze the TCP stream and extract the HTTP requests and responses
    # read the pcap file
    packets = rdpcap(pcapfile)

    with open(savefile, 'w') as f:
        for i in packets:
            layer = ''
            if i.haslayer('IP'):
                layer = 'IP'
            elif i.haslayer('IPv6'):
                layer = 'IPv6'

            src_ip = i[layer].src
            dst_ip = i[layer].dst
            src_port = i['TCP'].sport
            dst_port = i['TCP'].dport

            if (not i.haslayer('TCP')) or \
                    (src_ip, dst_ip, src_port, dst_port) not in ((client_ip_prev, server_ip_prev, client_port_prev, 80),
                                                                 (
                                                                         server_ip_prev, client_ip_prev, 80,
                                                                         client_port_prev)):
                continue

            http_packet = i['TCP'].payload
            try:
                http_method = (http_packet.fields['load']).split(b'\r\n')[0].decode()
                if ' ' not in http_method:
                    http_method = None
            except UnicodeDecodeError:
                http_method = "..NO HEADER.."
            except KeyError:
                continue

            if http_method:
                f.write(f'{http_method}\n')
            else:
                continue
            # Print the HTTP method, status code, URL, and headers

# import matplotlib.pyplot as plt

# # Example list of ACKs

# # Create x-axis values (just the index of each ACK)
# x_values = list(range(len(ackss)))

# # Plot the line chart
# plt.plot(x_values, ackss)

# # Add x and y labels and a title
# plt.xlabel('Packet Number')
# plt.ylabel('ACK Number')
# plt.title('ACK Numbers vs Packet Numbers')

# # Show the plot
# plt.show()

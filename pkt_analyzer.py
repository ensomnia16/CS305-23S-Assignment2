from scapy.all import *

conf.verb = 0

'''
This is the skeleton code for the packet analyzer. You will need to complete the functions below. Note that 
you cannot modify the function signatures. You can add additional functions if you wish.
'''

def packet_info(pcap_file, save_file):
    '''

    :param pcap_file: path to pcap file
    :param save_file: path to save file of results
    :return: not specified
    '''
    packets = rdpcap(pcap_file)

    with open(save_file, 'w') as f:
        for packet in packets:
            # Check if the packet is an IP packet
            pass


# iterate over each packet in the pcap file
def tcp_stream_analyzer(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    """

    :param file: path to pcap file
    :param savefile: path to save file of analysis results
    :param client_ip_prev: ip address of client of TCP stream waiting for analysis
    :param server_ip_prev: ip address of server of TCP stream waiting for analysis
    :param client_port_prev: port of client of TCP stream waiting for analysis
    :param server_port_prev: port of server of TCP stream waiting for analysis
    :return: not specified
    """
    packets = rdpcap(file)
    with open(savefile, 'w') as f:
        for packet in packets:

            if not packet.haslayer('IP'):
                continue # skip non-IP packets, delete this block if you want to implement IPv6 support

            pass


def http_stream_analyzer(pcapfile, savefile, client_ip_prev, server_ip_prev, client_port_prev):
    """

    :param pcapfile: path to pcap file
    :param savefile: path to save file of analysis results
    :param client_ip_prev: ip address of client of HTTP stream waiting for analysis
    :param server_ip_prev: server ip address of HTTP stream waiting for analysis
    :param client_port_prev: port of client of HTTP stream waiting for analysis
    :return: not specified
    """
    packets = rdpcap(pcapfile)

    with open(savefile, 'w') as f:
        for i in packets:
            pass

if __name__ == '__main__':
    pass
    '''
    You can call functions here to test your code.
    '''
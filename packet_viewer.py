##################################################################################################
'''
// @Project      Network-Analyzer
// @Author       Saccharide
'''
##################################################################################################


import socket
import struct
import textwrap


def main():
    # Last parameter makes sure conversion of big/small endian correctly
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Main infinite loop

    while True:
        raw_data, addr = s.recvfrom(65536)
        
        # Unpacks the raw data
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print("Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))


# Unpack ethernet frame, return the destination mac addr, source mac addr, and type (IPV4, IPV6, ARP Request/Response)
def ethernet_frame(data):
    
    destination_mac, source_mac, proto = struct.unpack('! 6s 6s H',data[:14])

    return get_mac_addr(destination_mac), get_mac_addr(source_mac), socket.htons(proto), data[14:]

# Returns human readable MAC address (AA:BB:CC:DD)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return mac_addr  = ':'.join(bytes_str).upper()



main()

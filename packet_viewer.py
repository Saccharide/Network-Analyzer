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
    return ':'.join(bytes_str).upper()



# Unpack IPv4 packet
def ipv4_packet(data):
    version_with_header_length = data[0]

    # Get pure version number by right shifts 4 bits
    version = version_with_header_length >> 4

    # Get pure header length by left shifts 4 bits
    header_length = (version_with_header_length & 15) * 4

    time_to_live, proto, scr, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return version, header_length, time_to_live, proto, ipv4(src), ipv4(dest), data[header_length:]


# Returns human readabel IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))
main()

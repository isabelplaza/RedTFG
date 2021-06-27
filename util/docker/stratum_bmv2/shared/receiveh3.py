#!/usr/bin/env python
import sys, os, socket, random, struct, time
import binascii, uuid, json
from datetime import datetime
import calendar
import argparse
import struct

from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.layers.inet6 import IPv6
from scapy.fields import *

from binascii import hexlify

SRC = 0
DST = 1
DSCP = 2

BOS = 0
LABEL1 = 1

ICMP_PROTO = 1
TCP_PROTO = 6
UDP_PROTO = 17
INT_PROTO = 0xFE

parser = argparse.ArgumentParser(description='Process some parameters')

parser.add_argument('-e', '--ethernet', type=str, help='Ethernet src/dst addresses')
parser.add_argument('-m', '--mpls', type=str, help='Enable MPLS header and add parameters')
parser.add_argument('-i', '--ip', type=str, help='Add IPv4 parameters')
parser.add_argument('-t', '--tcp', type=int, action='store', help='Enable TCP header and add parameters')
parser.add_argument('-u', '--udp', type=int, action='store', help='Enable UDP header and add parameters')
parser.add_argument('-p', '--packets', type=int, action='store', help='Number of packets to send')
parser.add_argument('-b', '--bytes', type=int, action='store', help='Bytes for the payload')
parser.add_argument('-r', '--randbytes', const=True, action='store_const',  help='Add random bytes to the payload')
parser.add_argument('-f', '--filename', type=str, help='Path for the filename')
parser.add_argument('-x', '--filter', type=str, help='Filter criteria')
parser.add_argument('-c', '--interface', type=str, help='Name of the interface to send the packet to')
#parser.add_argument('-n', '--int', type=str, help='INT header')

args = parser.parse_args()

class MPLS(Packet):
    name = "MPLS"
    fields_desc = [
        BitField("label", 1000, 20),
        BitField("exp", 0, 3),
        BitField("bos", 1, 1),
        ByteField("ttl", 0)
    ]


class INT_HEADER(Packet):
    name = "INT_HEADER"
    fields_desc = [
        BitField("ver", 1, 8), #name, default, size
        BitField("max_hop_cnt", 1, 32),
        BitField("total_hop_cnt", 2, 32),
        BitField("instruction_mask", 1, 8)
    ]

class INT_METADATA(Packet):
    name = "INT_METADATA"
    fields_desc = [
        BitField("sw_id", 0, 32),
        BitField("egress_timestamp", 0, 48)
    ]



bind_layers(Ether, IP, type=0x0800)
bind_layers(IP, INT_HEADER, protocol=INT_PROTO)
bind_layers(INT_HEADER, INT_METADATA)

#para leer las interfaces
def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if args.interface in i:
            iface=i
            break;
    if not iface:
        print("Cannot find  interface")
        exit(1)
    return iface

def handle_pkt(packet, flows, counters):

    info = { }

    info["rec_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    pkt = bytes(packet)
    print("## PACKET RECEIVED ##")

    eth_h = None
    mpls_h = None
    ip_h = None
    l4_h = None
    packetPayload = None

    ETHERNET_HEADER_LENGTH = 14
    MPLS_HEADER_LENGTH = 4
    IP_HEADER_LENGTH = 20
    ICMP_HEADER_LENGTH = 8
    UDP_HEADER_LENGTH = 8
    TCP_HEADER_LENGTH = 20
    INT_HEADER_LENGTH = 10 # 10 byte = 80 bits
    INT_METADATA_LENGTH = 10 # 10 bytes = 80 bits


    ETHERNET_OFFSET = 0 + ETHERNET_HEADER_LENGTH
    INT_HEADER_OFFSET = ETHERNET_OFFSET + IP_HEADER_LENGTH
    INT_METADATA_OFFSET = INT_HEADER_OFFSET + INT_HEADER_LENGTH

    eth_h = Ether(pkt[0:ETHERNET_OFFSET])
    eth_h.show()

    int_h = INT_HEADER(pkt[INT_HEADER_OFFSET:(INT_HEADER_OFFSET+INT_HEADER_LENGTH)])
    int_h.show()

    f = open('int_data_h3h2.txt', 'a')
    f.write("\n\n\n////////////////////////////////////////////////////////////////////////")
    f.write("\nThis is the INT data collected from the traffic flow between h3 and h2.\n")

    ft = open('timestamps_h3h2.txt', 'a')

    for x in range(0, int_h.total_hop_cnt):

        int_m = INT_METADATA(pkt[INT_METADATA_OFFSET:(INT_METADATA_OFFSET+INT_METADATA_LENGTH)])
        int_m.show()

        f.write("\n\nSwitch ID %d: " % (x+1))
        f.write(str(int_m.sw_id))

        f.write("\nEgress timestamp %d: " % (x+1))
        f.write(str(int_m.egress_timestamp))
        f.write("\n")
        f.write("////////////////////////////////////////////////////////////////////////")

        ft.write(str(int_m.egress_timestamp))
        ft.write("\n")

        INT_METADATA_OFFSET = INT_METADATA_OFFSET + INT_METADATA_LENGTH


    f.close()
    ft.close()
    sys.stdout.flush()


def main():
    flows = {}
    counters = {}

    print("sniffing on %s" % args.interface)
    sys.stdout.flush()
    sniff(
        lfilter = lambda d: d.src == '00:00:00:00:00:1c', #or 00:00:00:00:00:1c, # MAC del host origen
        iface = args.interface,
        prn = lambda x: handle_pkt(x, flows, counters))

if __name__ == '__main__':
    main()
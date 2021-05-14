#!/usr/bin/env python
import sys, os, socket, random, struct, time
import binascii, uuid, json
from datetime import datetime
import calendar
import argparse

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


class INT(Packet):
    name = "INT"
    fields_desc = [
        BitField("egress_timestamp", 5, 64)
    ]


bind_layers(Ether, IP, type=0x0800)
bind_layers(IP, INT, protocol=0xFE)

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
    INT_HEADER_LENGTH = 8 # 8 bytes = 64 bits


    ETHERNET_OFFSET = 0 + ETHERNET_HEADER_LENGTH
    INT_OFFSET = ETHERNET_OFFSET + IP_HEADER_LENGTH

    eth_h = Ether(pkt[0:ETHERNET_OFFSET])
    eth_h.show()

    int_h = INT(pkt[INT_OFFSET:(INT_OFFSET+INT_HEADER_LENGTH)])
    int_h.show()

    sys.stdout.flush()

def main():
    flows = {}
    counters = {}

    print("sniffing on %s" % args.interface)
    sys.stdout.flush()
    sniff(
        lfilter = lambda d: d.src == '00:00:00:00:00:1a', # MAC del host origen (h1)
        iface = args.interface,
        prn = lambda x: handle_pkt(x, flows, counters))

if __name__ == '__main__':
    main()
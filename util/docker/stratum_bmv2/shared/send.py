#!/usr/bin/env python
import sys, os , socket, random, struct, time
import argparse

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.fields import *

SRC = 0
DST = 1
DSCP = 2

BOS = 0
LABEL1 = 1

SWITCH_ID = 0
TIMESTAMP = 1

parser = argparse.ArgumentParser(description='Process some integers.')

parser.add_argument('-e', '--ethernet', type=str, help='Ethernet src/dst addresses')
parser.add_argument('-m', '--mpls', type=str, help='Enable MPLS header and add parameters')
parser.add_argument('-i', '--ip', type=str, help='Add IPv4 parameters')
parser.add_argument('-t', '--tcp', type=int, action='store', help='Enable TCP header and add parameters')
parser.add_argument('-u', '--udp', type=int, action='store', help='Enable UDP header and add parameters')
parser.add_argument('-p', '--packets', type=int, action='store', help='Number of packets to send')
parser.add_argument('-b', '--bytes', type=int, action='store', help='Bytes for the payload')
parser.add_argument('-r', '--randbytes', const=True, action='store_const',  help='Add random bytes to the payload')
parser.add_argument('-f', '--filename', type=str, help='Path for the filename')
parser.add_argument('-c', '--interface', type=str, help='Name of the interface to send the packet to')
parser.add_argument('-n', '--int', type=str, help='Add INT header')


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
#bind_layers(IP, INT, protocol=0xFE)

def main():

    if args.ethernet:
        ethernetParams = [p for p in args.ethernet.split(',')]

    if args.ip:
        ipParams = [p for p in args.ip.split(',')]



    #outF = open(fileName, "a")

    print("Sending packets on interface %s" % (args.interface))

    pkt = Ether(src=ethernetParams[SRC], dst=ethernetParams[DST])

    pkt = pkt / IP(src=ipParams[SRC], dst=ipParams[DST], tos=int(ipParams[DSCP], 0) << 2)


    #if args.int:
    #    pkt = pkt / INT_HEADER(ver=2, max_hop_cnt=3, total_hop_cnt=1, instruction_mask=3)
    #    pkt = pkt / INT_METADATA(sw_id=5, egress_timestamp=12345)

    if args.udp:
        pkt = pkt / UDP(sport=0, dport=args.udp)
    if args.tcp:
        pkt = pkt / TCP(sport=0, dport=args.tcp)

    if args.bytes:
        if args.randbytes:
            pkt = pkt / Raw(load=bytearray(os.urandom(args.bytes)))
        else:
            pkt = pkt / Raw(load=bytearray([0] * args.bytes) )

    for i in range(args.packets):    
        #pkt.show()
        #t = time.time_ns()
        if args.udp:
            pkt[UDP].sport = i+1

        if args.tcp:
            pkt[TCP].sport = i+1
        
        sendp(pkt, iface=args.interface, verbose=False)
        print("Sent packet: " + str(i+1))
        time.sleep(0.3)


if __name__ == '__main__':
    main()

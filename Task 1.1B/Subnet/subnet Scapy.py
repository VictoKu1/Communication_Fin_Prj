#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()


pkt = sniff(iface=['br-82771e18ec80', 'enp0s3'], filter = 'net 128.230.0.0/16' , prn=print_pkt)


#!/usr/bin/python

import sys
import optparse
from scapy.all import (Ether,
                       ARP,
                       sendp)


# intf = "lo"
# src_mac = "24:8a:07:4c:f5:00"
# src_ip = "192.168.1.28"


bcast_mac = "ff:ff:ff:ff:ff:ff"


def main():
    usage = "usage: %prog [options] arg1 arg2"

    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-i", "--interface", type="string", dest="interface", help="Interface list to send packets, seperated by ','",metavar="intfName")
    parser.add_option('-m', "--src_mac", type="string", dest="src_mac", help="src mac address", metavar="srcMac")
    parser.add_option("-p", "--src_ip", type="string", dest="src_ip", help="src ip address", metavar="srcIp")
    (options, args) = parser.parse_args()

    if options.interface is None:
        print >> sys.stderr, "Need to specify the interface to send GARP"
        parser.print_help()
        sys.exit(1)

    if options.src_mac is None:
        print >> sys.stderr, "Need to specify the source mac in GARP packet"
        parser.print_help()
        sys.exit(1)

    if options.src_ip is None:
        print >> sys.stderr, "Need to specify the source ip in GARP packet"
        parser.print_help()
        sys.exit(1)

    intf = options.interface.split(',')[0]
    print >> sys.stderr, intf
    src_mac = options.src_mac
    print >> sys.stderr, "src MAC: %s" % (src_mac)
    src_ip = options.src_ip
    print >> sys.stderr, "src IP: %s" % (src_ip)

    pkt = Ether(dst=bcast_mac, src=src_mac)/ARP(hwtype=1, ptype=0x0800, hwlen=6, plen=4, op=1, hwsrc=src_mac, psrc=src_ip, hwdst=bcast_mac, pdst=src_ip)

    sendp(pkt,iface=intf, loop=1)


if __name__ == "__main__":
    main()

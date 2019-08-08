#!/usr/bin/python

import binascii
import sys
import optparse
from socket import (socket,
                    AF_PACKET,
                    SOCK_RAW)


bcast_mac  = "\xff\xff\xff\xff\xff\xff"

ether_type = "\x08\x06"
hw_type    = "\x00\x01"
prot_type  = "\x08\x00"
hw_len     = "\x06"
prot_len   = "\x04"
op_code    = "\x00\x01"


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

    src_mac_hexstr = options.src_mac.replace(':', '')
    print >> sys.stderr, "src MAC: %s" % (src_mac_hexstr)
    src_mac = binascii.unhexlify(src_mac_hexstr)

    src_ip = ''
    for ip_subsec in options.src_ip.split('.'):
        print >> sys.stderr, "src IP: %s" % (ip_subsec)
        src_ip += binascii.unhexlify(format(int(ip_subsec), '02x'))

    try:
        sckt = socket(AF_PACKET, SOCK_RAW)
    except:
        print("unable to create socket. Check your permissions")
        sys.exit(1)

    sckt.bind((intf, 0))

    pkt = bcast_mac + src_mac + ether_type + hw_type + prot_type + hw_len + prot_len + op_code + src_mac + src_ip + bcast_mac + src_ip
    while 1:
        sckt.send(pkt)


if __name__ == "__main__":
    main()

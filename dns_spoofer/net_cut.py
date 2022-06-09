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
    print(packet)
    # packet.accept()  # Forwards the packet to the router/target :)
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

print("\n[+] ON...\n")

queue.bind(0, process_packet)  # Callback function refers each packet in the queue to the specified function :)
# This binds our object 'queue' to the queue with num. '0' created above using iptables through subprocess

queue.run()  # This activates the queue; runs it! :D

subprocess.call("iptables --flush", shell=True)  # restores iptables back to normal :)

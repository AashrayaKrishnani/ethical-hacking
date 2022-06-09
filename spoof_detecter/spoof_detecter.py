#!/usr/env/bin/ python3

import scapy.all as scapy
from colorama import Fore, Back, Style


def check_root_or_not():
    try:
        scapy.srp(scapy.Ether(), verbose=False, timeout=0.5)
    except PermissionError:
        print("\n[-] Kindly re-run with root privileges.\n")
        exit(0)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_mac(ip):
    if not check_ip(ip):
        print("\n[-] Invalid IP - " + ip)
        exit(0)

    try:  # Catching error due to Invalid IP.
        arp_request = scapy.ARP(pdst=ip)  # pdst is variable that stores value of ip address to be broadcast.
    except scapy.socket.gaierror:
        arp_request = None
        print("[-] Invalid IP - " + ip)
        exit(0)

    broadcast = scapy.Ether()

    #    scapy.ls(scapy.Ether())
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'  # dst = Destination MAC, It figures our MAC as src on its own ;p

    arp_request_broadcast = broadcast / arp_request  # '/' Here is used to combine two packets as scapy ALLOWS it XD

    while True:
        try:
            try:
                answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=2)[0]
                if answered_list is not None:
                    mac = answered_list[0][1].hwsrc  # Returns MAC of first element '0' in answered list.
                    # Remember each element in the answered_list is a couple that contains a SENT request,
                    # and a RECEIVED Response. We use '[1]' to access the response packet received by us,
                    # of first element i.e., '[0]' Then we take the 'hwsrc' i.e., MAC of where that response packet
                    # came from. :D
                    break
                else:
                    print("\n[-] No client found on the network at ip - " + ip)
                    exit(0)
            except KeyboardInterrupt:
                print("\n[-] Abruptly Exiting on KeyboardInterrupt...")
                exit(0)
        except IndexError:
            pass
            # mac = None
            # print("\n [-] Failed to Find MAC Address for IP --> " + ip)
            # exit(0)

    # Useful Comments.
    {

        #     scapy.ls(scapy.ARP())
        #     scapy.ls() is used to list arguments that can be passed in the Class which is passed in it as argument.
        #     scapy.ls(scapy.ARP())  tells what arguments are accepted by scapy.ARP()
        # scapy.ARP() is a class that allows us to send ARP requests ;)

        # print("[+] arp_request.summary() \n" + arp_request.summary())
        # print("[+] Calling arp_request.show()")
        # arp_request.show()  # show() method lists details of the type of packet it is called from ;D

        # scapy.Ether() is a class that allows us to create an Ethernet frame where we actually broadcast the ARP Req.
        # It sends The ARP Req to all MAC ADDRESSES so that they can receive it and send their response! :D

        # Above MAC (ff:ff:ff:ff:ff:ff) is actually a NULL MAC which means it'll be broadcast to all devices. :D

        # print("[+] broadcast.summary() \n" + broadcast.summary())
        # print("[+] Calling broadcast.show()")
        # broadcast.show()  # show() method lists details of the type of packet it is called from ;D

        # Combining arp_request (ARP packet) and broadcast (MAC Address Packet) into one :D

        # print("[+} arp_request_broadcast.summary() \n" + arp_request_broadcast.summary())
        #
        # print("[+] Calling arp_request_broadcast.show()")
        # arp_request_broadcast.show()  # show() method lists details of the type of packet it is called from ;D

        #  Onto Sending and Receiving Packets ;D
        # (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1)
        # scapy.srp() returns two lists - answered_list and unanswered_list

        # Modifying stuff to only receive answered list cos we don't need unanswered list.

        # verbose=False removes unnecessary Console Output.
        # [0] here specifies that we need only FIRST Element and not the second returning element of the function

        # print("[+] answered_list.summary()")
        # print(answered_list.summary())

        # print("[+] unanswered_list.summary()")
        # print(unanswered_list.summary())

    }

    return mac  # Returning MAC address of the IP passed as argument. :)


def process_sniffed_packet(packet):

    if packet.haslayer(scapy.ARP):
        if packet[scapy.ARP].op == 2:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac is not response_mac:
                print(Back.RED + Fore.WHITE + "[+] System is being ARP poisoned by IP "
                      + Back.WHITE + Fore.RED + str(packet[scapy.ARP].psrc) + Style.RESET_ALL)

            print(packet.show())  # To print All Options in all layers of said Packet :D


check_root_or_not()

sniff("wlan0")

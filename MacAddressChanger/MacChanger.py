#!/usr/bin/env python3

import subprocess
import re
import optparse

# A function for all the PARSING CODE! :-


def get_args():
    parser = optparse.OptionParser()
    # Adding argument options
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change it's MAC Address")
    parser.add_option("-m", "--mac", dest="newMac", help="New Mac Address to be changed to.")
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Enter Any valid Char To Display Details of interface after completion.")
    parser.add_option("-s", "--silent", dest="silent", help="Enter Any valid Char To Execute WITHOUT ANY messages.")

    # parser.parse_args() is used to parse the entered values.

    # It returns a set of two distinct lists - The first contains the options chosen by the user.
    # The second list contains corresponding arguments that we had entered.
    return parser.parse_args()


# A function to change MAC :-


def change_mac(interface=None, new_mac=None, verbose=None, silent=None, data=None):
    if interface is None:
        if data.interface is None:
            interface = input("\nEnter Interface Name : ")
        else:
            interface = data.interface

    if new_mac is None:
        if data.newMac is None:
            new_mac = input("Enter New Mac Address for " + interface + " : ")
        else:
            new_mac = data.newMac

    # The input() function is a Python 3 function.
    # To use its Python2 version, replace with raw_input()
    # Like : -

    # interface = raw_input("Enter Interface Name : ")
    # newMac = raw_input("Enter New Mac Address : ")

    if data is not None:
        verbose = data.verbose
        silent = data.silent

    if not check_interface(interface):
        print("\n[-] Invalid/Incompatible Interface name Entered. \nKindly Try Again. \n")
        exit(0)

    if not check_mac(new_mac):
        print("\n[-] Invalid/Incompatible MAC Address Entered. \nKindly Try Again. \n")
        exit(0)

    if silent is None:
        print("\n[+] Changing MAC Address for " + str(interface) + " to " + str(new_mac))

    # Bad Practice Since User can Input Commands in variables and Hijack the program.
    #
    # subprocess.call("ifconfig " + interface + " down", shell=True)
    # subprocess.call("ifconfig " + interface + " hw ether " + newMac, shell=True)
    # subprocess.call("ifconfig " + interface + " up", shell=True)
    # subprocess.call("ifconfig " + interface, shell=True)

    # Below is the Correct Way to do it.
    # This is a good practice as it tells Python that the variables are words and part of the same command.
    # It will give an error while messing with it, but won't allow anyone to Hijack the code! :)

    # The Square Brackets in Python are used to specify a List of variables! :)

    subprocess.call(["ifconfig", str(interface), "down"])
    subprocess.call(["ifconfig", str(interface), "hw", "ether", str(new_mac)])
    subprocess.call(["ifconfig", str(interface), "up"])
    confirm_change_mac(interface=interface, new_mac=new_mac, verbose=verbose, silent=silent)


# A function to check if MAC actually changed or not :-


def confirm_change_mac(interface, new_mac, verbose, silent):
    mac_address_search_result = get_current_mac(interface)
    new_mac_filtered = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", new_mac)

    if mac_address_search_result:
        if mac_address_search_result[0] == new_mac_filtered[0]:
            if verbose is not None:
                if silent is None:
                    print()
                    subprocess.call(["ifconfig", str(interface)])
                    print()
            if silent is None:
                print("[+] Done.\n")
        return

    print("[+] Unsuccessful in changing MAC, Apologies.")


def check_interface(interface):
    mac_search_result = get_current_mac(interface)

    if mac_search_result is not None:
        return True
    else:
        return False


def check_mac(new_mac):
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", new_mac)

    if mac_address_search_result:
        return True

    return False


def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface], stderr=subprocess.STDOUT)
        # 'stderr=STDOUT' Here prevents displaying error msg to the console :D
    except subprocess.CalledProcessError:
        output = None

    if output:
        output = output.decode('UTF-8')

    try:
        mac_search_result = re.search(pattern=r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", string=output)
    except TypeError:
        mac_search_result = None

    return mac_search_result


# Calling Functions to do the job for us ;p

(options, arguments) = get_args()

change_mac(data=options)

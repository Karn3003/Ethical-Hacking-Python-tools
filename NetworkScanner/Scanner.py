#!/usr/bin/env python3
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="TARGET IP/ IP RANGE")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an TARGET IP/ IP RANGE, use --help for more information.")
    return str(options.target)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # returns answered and unanswered response
    # answered_list.summary()
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return  clients_list

def print_result(results_list):
    print("------------------------------------------")
    print("IP\t\t\tMAC ADDRESS")
    print("------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
    print("------------------------------------------")

target = get_arguments()
scan_result = scan(target)
print_result(scan_result)
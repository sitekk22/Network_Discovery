import scapy.all as scapy
import argparse as arg
import socket

def get_arguments():
    parser = arg.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Throw me IP/Netmask")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, 1,verbose = False, timeout = 2)[0]
    client_list = []
    
    for ip in answered_list:
        client_dict = {"ip":ip[1].psrc, "mac":ip[1].hwsrc}
        client_list.append(client_dict)
    
    return client_list


def print_results(scan_list):
    print("IP\t\t\tMAC\n" + "-"*45)
    for client in scan_list:
        print(client["ip"] + "\t\t" + client["mac"])
    print("-"*45)
options = get_arguments()
result_list = scan(options.target)
print_results(result_list)

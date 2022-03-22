import ipaddress
import select
import socket
import time
from datetime import datetime
from datetime import date
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
import scapy.all as scapy
from scapy.layers.l2 import Ether
import os
from file import Constants
from queue import Queue


MAX_MSG_LENGTH = 1024
UDP_IP = "192.168.31.24"
UDP_PORT = 2023
DISCOVER_MESSAGE = "discover"
OFFER_MESSAGE = "offer"
REQUEST_MESSAGE = "request"
ACKNOWLEDGE_MESSSAGE = "acknowledge"
MAX_COUNT = 40
LAST_NUM = 26
IP_ADRESS = "172.16.20.211"
SUBNET_MASK = "255.255.255.0"
Index = 1
SIZE_QUEUE = 0

# server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
# server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# server_socket.bind((UDP_IP, UDP_PORT))
# #server_socket.listen()


class IP_allocator:

    def __init__(self, subnet_mask, ip_addr):
        self.subnet_mask = subnet_mask
        self.ip_addr = ip_addr
        self.ip_bank = Queue()
        self.offer_dict = {}
        self.allocated_dict = {}
        #identify static part in ip
        self.subnet_mask_parts =self.subnet_mask.split(Constants.IP_SAPARATOR)
        self.ip_addr_parts = self.ip_addr.split(Constants.IP_SAPARATOR)

        # ip_tupples_parts = []
        # for i in range(0, len(self.subnet_mask_parts))]:
        #    ip_tupples_parts.append((self.subnet_mask_parts[i], self.ip_addr_parts[i]))
        ip_tupples_parts = [(self.subnet_mask_parts[i], self.ip_addr_parts[i]) for i in range(0, len(self.subnet_mask_parts))]
        subnet_counter = 0
        for part in ip_tupples_parts:
            if part[Constants.MASK_PART] == Constants.STATIC_MASK_PART:
                subnet_counter += 8
            else:
                subnet_counter += 8
                num = int(part[Constants.MASK_PART])
                while num != 0:
                    digit = num % 2
                    num = num / 2
                    if digit == 1:
                        break
                    subnet_counter -= 1

        net4 = ipaddress.ip_network(self.ip_addr + '/' + str(subnet_counter))
        ip = "192.168.1.3"
        self.size_queue = 0
        for x in net4.hosts():
            print(x)
            self.ip_bank = x
            self.size_queue += 1

        # #loop om dynamic part to generate ips
        # for i in range(4):
        #     if len(static_ip_parts) > i:
        #         part = static_ip_parts[i]
        #         ip_tupples_parts[Constants.MASK_PART]
        #         pass
        #         #handle copy part and complete missing
        #     else:
        #         #generateDynamic part
    def offer_dictionary(self, mac):
        ip_requested = self.ip_bank.pop()
        timeout = str(8267) + "s"
        self.offer_dict.update({mac: (ip_requested, timeout)})
        return ip_requested

    def acknowledge_dictionary(self, ip, mac):
        timeout = str(8267) + "s"
        self.allocated_dict.update({mac: (ip, timeout)})
        return self.allocated_dict


# def filter(packet):
#     if UDP in packet:
#         if packet[UDP].dport == Constants.dest_port:
#             return True
#     return False


def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


# def handle_packets(packet):
#     print("hello")
#     mac = packet[Ether].src
#     ip_obj=IP_allocator(SUBNET_MASK,IP_ADRESS)
#     type_message = packet[DHCP].options[0][1] #1-discover, 3-request
#     #build offer
#     #if type message = 1 , we will send an offer message
#     if type_message == 1:
#         ip_requested = ip_obj.offer_dictionary(mac)
#         ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
#         ip = IP(dst=ip_requested, src="172.16.20.211")#dest_addr
#         udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
#         bootp = BOOTP(op=2, yiaddr=ip_requested, siaddr="172.16.20.211", chaddr=mac)
#         dhcp = DHCP(options=[("message-type", "offer"), ("server_id", ip_requested), ("broadcast_address", "255.255.255.255"),
#                              ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"), ("lease_time", str(8267) + " s")]) #router - gateway :"172.16.255.254"
#         of_pack = ethernet / ip / udp / bootp / dhcp
#         sendp(of_pack)
#     elif type_message == 3:
#         #bulid acknolwedge
#         cur_ip = packet[DHCP].options[2][1]
#         alocated_dict = ip_obj.allocated_dict(cur_ip)
#         ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
#         #save_ip=get_requested_ip(IpQueue)
#         ip = IP(dst=cur_ip, src="172.16.20.211")  # dest_addr
#         udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
#         bootp = BOOTP(op=2, yiaddr=cur_ip, siaddr="172.16.20.211", chaddr=mac)
#         dhcp = DHCP(
#             options=[("message-type", "offer"), ("server_id", cur_ip), ("broadcast_address", "255.255.255.255"),
#                      ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
#                      ("lease_time", str(8267) + " s")])  # router - gateway :"172.16.255.254"
#         of_pack1 = ethernet / ip / udp / bootp / dhcp
#         # send ack
#         sendp(of_pack1)
#
#     Index += 1


class DHCPHandler:
    def __init__(self):
        #tables and database, and etc
        self.ip_obj = IP_allocator(SUBNET_MASK, IP_ADRESS)


    def filter(self, packet):
        if UDP in packet:
            print(packet[UDP].dport)
            if packet[UDP].dport == Constants.dest_port:
                return True
        return False


    def handle(self, packet):
        mac = packet[Ether].src
        packet.show()
        print(packet)
        print(packet[Raw])
        # להבין איך לקרוא את ה-DHCP
        type_message = packet[DHCP].options[0][1]  # 1-discover, 3-request
        if self.is_discover(packet):
            self.handle_discover(packet, mac)

        elif self.is_request(packet):
            self.handle_request(packet, mac)


    def handle_discover(self, packet,mac):
        # build offer
        ip_requested = self.ip_obj.offer_dictionary(mac)
        ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
        ip = IP(dst=ip_requested, src="172.16.20.211")  # dest_addr
        udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
        bootp = BOOTP(op=2, yiaddr=ip_requested, siaddr="172.16.20.211", chaddr=mac)
        dhcp = DHCP(
            options=[("message-type", "offer"), ("server_id", ip_requested), ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", str(8267) + " s")])  # router - gateway :"172.16.255.254"
        of_pack = ethernet / ip / udp / bootp / dhcp
        sendp(of_pack)


    def handle_request(self, packet, mac):
        # bulid acknolwedge
        cur_ip = packet[DHCP].options[2][1]
        alocated_dict = self.ip_obj.allocated_dict(cur_ip)
        ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
        # save_ip=get_requested_ip(IpQueue)
        ip = IP(dst=cur_ip, src="172.16.20.211")  # dest_addr
        udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
        bootp = BOOTP(op=2, yiaddr=cur_ip, siaddr="172.16.20.211", chaddr=mac)
        dhcp = DHCP(
            options=[("message-type", "acknowledge"), ("server_id", cur_ip), ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16"
                                ".255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", str(8267) + " s")])  # router - gateway :"172.16.255.254"
        of_pack1 = ethernet / ip / udp / bootp / dhcp
        # send ack
        sendp(of_pack1)


    def is_discover(self, packet) -> bool:
        type_message = packet[DHCP].options[0][1]  # 1-discover, 3-request
        if type_message == 1:
            return True
        else:
            return False


    def is_request(self, packet) -> bool:
        type_message = packet[DHCP].options[0][1]  # 1-discover, 3-request
        if type_message == 3:
            return True
        else:
            return False



def main():

    handler = DHCPHandler()
    while True:

        print("enter to loop")
        try:

            print("enter to try")
            # sock.sendto(bytes("hello", "utf-8"), ip_co)
            pa = sniff(lfilter=handler.filter, prn=handler.handle)#expecting to recieve discover msg

        except:
            print("error")
            continue




if __name__ == "__main__":
    main()

    # DHCPTypes = {
    #     1: "discover",
    #     2: "offer",
    #     3: "request",
    #     4: "decline",
    #     5: "ack",
    #     6: "nak",
    #     7: "release",
    #     8: "inform",
    #     9: "force_renew",
    #     10: "lease_query",
    #     11: "lease_unassigned",
    #     12: "lease_unknown",
    #     13: "lease_active",
    # }
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
#import constant
from client import mac_to_bytes, client_mac
import os
from file import Constants
from queue import Queue



MAX_MSG_LENGTH = 1024
UDP_IP = "192.168.31.24"
UDP_PORT = 2023
#server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# UDP
DISCOVER_MESSAGE = "discover"
OFFER_MESSAGE = "offer"
REQUEST_MESSAGE = "request"
ACKNOWLEDGE_MESSSAGE = "acknowledge"
#allip = ["172.16.20.212"] #"255.255.255.0" at school
allip = ["192.168.31.25"] #"255.255.255.0" at home
list_users = [] #id, MAC address, ip
MAX_COUNT = 40
LAST_NUM = 26
#IP_FIRST_PART = "172.16.20." at school
IP_FIRST_PART = "192.168.31." #at home
Index = 0
IpQueue = Queue()
IpQueue.put("192.168.31.25")
#to do queue of ips
#to do a dictionarry of Mac address: Ip address

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server_socket.bind((UDP_IP, UDP_PORT))
#server_socket.listen()
#class constants

# class Constants:
#     a = 4
#     def __init__(self):
#         self.x = 5

def create_ips(LAST_NUM):
    # this for create the ip
    for i in range(MAX_COUNT):
        CREATE_IP = IP_FIRST_PART + str(LAST_NUM)  # 192.168.31.26
        print(type(CREATE_IP))
        LAST_NUM += 1
        allip.append(CREATE_IP)
        str_index=str(i+1)
        print(type(str_index))
        print("ID: %s" % str_index + " IP address: %s" % str(CREATE_IP))

def filter(packet):
    if UDP in packet:
        if packet[UDP].dport == Constants.dest_port:
            return True
    return False

def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def handle_packets(packet, Index):
    mac = packet[Ether].src
    type_message = packet[DHCP].options[0][1] #1-discover, 3-request
    #build offer
    #if type message = 1 , we will send an offer message
    if type_message == 1:
        ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
        ip = IP(dst=allip[Index], src="172.16.20.211")#dest_addr
        udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
        bootp = BOOTP(op=2, yiaddr=allip[Index], siaddr="172.16.20.211", chaddr=mac)
        dhcp = DHCP(options=[("message-type", "offer"), ("server_id", allip[Index]), ("broadcast_address", "255.255.255.255"),
                             ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"), ("lease_time", str(8267) + " s")]) #router - gateway :"172.16.255.254"
        of_pack = ethernet / ip / udp / bootp / dhcp
        # sendp(offer)
        sendp(of_pack)
    elif type_message == 3:
        #bulid acknolwedge
        ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
        ip = IP(dst=allip[Index], src="172.16.20.211")  # dest_addr
        udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
        bootp = BOOTP(op=2, yiaddr=allip[Index], siaddr="172.16.20.211", chaddr=mac)
        dhcp = DHCP(
            options=[("message-type", "offer"), ("server_id", allip[Index]), ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", str(8267) + " s")])  # router - gateway :"172.16.255.254"
        of_pack1 = ethernet / ip / udp / bootp / dhcp
        # send ack
        sendp(of_pack1)

    Index += 1




while True:
    create_ips(LAST_NUM)
    print("enter to loop")
    try:
        print("enter to try")
        # sock.sendto(bytes("hello", "utf-8"), ip_co)
        pa = sniff(lfilter=filter, prn=lambda: handle_packets(pa, Index))#expecting to recieve discover msg
        print("hi")
        for packet in pa:
            if DHCP in pa and pa[DHCP].options[0][1] == 1: #message type=1, that means discover message
                    print("edv")
                    OFFER_MESSAGE = OFFER_MESSAGE + " " + allip[Index]
                    Index += 1
                    result = scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(dst="255.255.255.255", src="172.16.20.211") / scapy.UDP(sport=2023, dport=2025) / scapy.Raw( OFFER_MESSAGE), verbose=0, timeout=3)
                    print("offer msg" + OFFER_MESSAGE)
                    pa = (
                            Ether(dst="ff:ff:ff:ff:ff:ff") /
                            IP(src="0.0.0.0", dst="255.255.255.255") /
                            UDP(sport=Constants.src_port, dport=Constants.dest_port) /
                            BOOTP(
                                chaddr=mac_to_bytes(client_mac),
                                xid=random.randint(1, 2 ** 32 - 1),
                            ) /
                            DHCP(options=[("message-type", "discover"), "end"])
                    )

                    pa = sniff(lfilter=filter, iface="Software Loopback Interface 1")# expecting to recieve discover msg
                    for packet in pa:
                        msg = pa[raw]
                        message=msg = msg.split(" ")  # ["request",ip adr]
                        ip_adr = message[1]
                        if message.startswith() == REQUEST_MESSAGE:
                           # user = "id " + addr + " " + ip_adr
                            list_users.append(user)  # a new user added to the list
                            user = ip_adr
                            result2 = scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(dst="255.255.255.255",src="172.16.20.211") / scapy.UDP(sport=2023, dport=2024) / scapy.Raw(ACKNOWLEDGE_MESSSAGE), verbose=0, timeout=3)
                        else:
                            print("error")
    except:
        print("error")
        continue


def main():
    print("hi")


if name == "main":
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
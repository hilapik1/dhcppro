import socket
from time import sleep
from scapy.all import *
from scapy.layers.inet import UDP
import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
import random
import os
from file import Constants

os.system("python file.py")
#import constant

UDP_IP = "172.16.20.211"
UDP_PORT = 2024
DISCOVER_MESSAGE = "discover"
OFFER_MESSAGE = "offer"
REQUEST_MESSAGE = "request"
ACKNOWLEDGE_MESSSAGE = "acknowledge"
SETTINGS={}

print("UDP target IP: %s" % UDP_IP)
print("UDP target port: %s" % UDP_PORT)
print("message: %s" % DISCOVER_MESSAGE)


# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# sock.bind(("0.0.0.0", 2025))


def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


def filter(packet):
    if UDP in packet:
        if packet[UDP].dport == 2024:
            return True
    return False
#srp1
class DHCP_generator:

    def __init__(self, src_port, dest_port, client_mac):
        self.src_port = src_port
        self.dest_port = dest_port
        self.mac = client_mac

    def discover_generate(self):
        #src_port=2025, dst_port=2023
        self.dhcp_discover = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=self.src_port, dport=self.dest_port) /
                BOOTP(
                    chaddr=mac_to_bytes(self.mac),
                    xid=776 #random.randint(1, 2 ** 32 - 1),
                ) /
                DHCP(options=[("message-type", "discover"), "end"])
        )
        self.dhcp_discover.show()
        return self.dhcp_discover

    def request_generate(self):
        #src_port=2025, dst_port=2023
        self.dhcp_request = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=Constants.src_port, dport=Constants.dest_port) /
                BOOTP(chaddr=mac_to_bytes(client_mac)) /
                DHCP(options=[("message-type", "request"), ("server_id", SETTINGS["serverIP"]),
                              ("requested_addr", SETTINGS["clientIP"]), "end"]))
        return self.dhcp_request

while True:

        client_mac = "18:60:24:8F:64:90"#"01:02:03:04:05:06"
        generator = DHCP_generator(Constants.src_port, Constants.dest_port, client_mac)# src_port=2025, dest_port=2023
        dhcp_discover = generator.discover_generate()
        # SETTINGS = {"serverIP": dhcp_discover[BOOTP].siaddr, "clientIP": dhcp_discover[BOOTP].yiaddr, "XID": dhcp_discover[BOOTP].xid}
        result = srp1(dhcp_discover, verbose=False)#, iface="Software Loopback Interface 1"  # expecting to recieve an offer msg
        result.show()
        print("hi")
        SETTINGS = {"serverIP": dhcp_discover[BOOTP].siaddr, "clientIP": result[BOOTP].yiaddr,
                    "XID": dhcp_discover[BOOTP].xid}
        for packet in result:
            #if DHCP in result and result[DHCP].options[0][1] == 2:
            if DHCP in result and result[BOOTP][DHCP].options == 2:  # message type=2, that means offer message
                    dhcp_request = generator.request_generate()
                    print("sent request")
                    result1 = srp1(dhcp_request, lfilter=filter)# expecting to recieve an acknowledge msg
                    for packet in result1:
                            if result1[BOOTP][DHCP].options == 5:
                                    print("it works")
                            else:
                                    print("error")



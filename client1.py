import socket
from time import sleep
from scapy.all import *
from scapy.layers.inet import UDP
import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
import random
import os
from file import Constants
from threading import Thread

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


class DHCPHandler:

    #def _init_(self, client_mac):
    def _init_(self):
        pass
        #self.generate = DHCP_generator(Constants.src_port, Constants.dest_port, client_mac)

    def filter(self, pack):
        if not (DHCP in pack):
            return False

        if not(BOOTP in pack):
            return False

        if not(pack[BOOTP].xid in dict1.keys()):
            return False

        pa_in_dict = dict1[pack[BOOTP].xid]
        if pack[BOOTP][DHCP].options[0][1] == Constants.OFFER:
            if pa_in_dict[BOOTP][DHCP].options[0][1] == Constants.DISCOVER:
                return True
        elif pack[BOOTP][DHCP].options == Constants.ACK:
            if pa_in_dict[BOOTP][DHCP].options == Constants.REQUEST:
                return True

        return False

    def handle(self, pack):
        #צריכה לעשות מחלקה נפרדת בקובץ נפרד של כל הטיפול בבקשות השונות (כמו שעשיתי בסרבר)
        message_type = pack[BOOTP][DHCP].options[0][1]
        if message_type == Constants.OFFER:
            #handle_offer(pa)
            #self.generate.request_generate(pack[BOOTP].siaddr, pack[BOOTP].yiaddr, pack[BOOTP].chaddr)
            pa_in_dict = dict1[pack[BOOTP].xid]
            request = request_generate(pack[BOOTP].siaddr, pack[BOOTP].yiaddr, pa_in_dict[BOOTP].chaddr)
            sendp(request)

        elif message_type == Constants.ACK:
            #handle_ack()
            print("ACK WAS RECIEVED")


'''
class DHCP_generator:

    def _init_(self, src_port, dest_port, client_mac):
        self.src_port = src_port
        self.dest_port = dest_port
        self.mac = client_mac
'''
def discover_generate(mac):
    #src_port=2025, dst_port=2023
    dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=Constants.src_port, dport=Constants.dest_port) /
            BOOTP(
                chaddr=mac_to_bytes(mac),
                xid=777 #random.randint(1, 2 ** 32 - 1),
            ) /
            DHCP(options=[("message-type", "discover"), "end"])
    )
    dhcp_discover.show()
    return dhcp_discover

def request_generate(server_ip, client_ip, client_mac):
    #src_port=2025, dst_port=2023
    dhcp_request = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=Constants.src_port, dport=Constants.dest_port) /
            BOOTP(chaddr=client_mac)/#mac_to_bytes(client_mac)) /
            DHCP(options=[("message-type", "request"), ("server_id", server_ip),
                          ("requested_addr", client_ip), "end"]))
    return dhcp_request


def sniffer(filter, handler):
    pa = sniff(lfilter=filter, prn=handler)


handler = DHCPHandler()
t = Thread(target=sniffer, args=(handler.filter, handler.handle))
t.start()
time.sleep(0.5)
while True:

        client_mac = "18:60:24:8F:64:90"#"01:02:03:04:05:06"
        #generator = DHCP_generator(Constants.src_port, Constants.dest_port, client_mac)# src_port=2025, dest_port=2023
        #dhcp_discover = generator.discover_generate()
        dhcp_discover = discover_generate(client_mac)
        id = dhcp_discover[BOOTP].xid
        dict1 = {}
        dict1[id] = dhcp_discover
        dhcp_discover.show()
        sendp(dhcp_discover)
        t.join()
        #pa = sniff(lfilter=handler.filter, prn=handler.handle)
        #SETTINGS = {"serverIP": dhcp_discover[BOOTP].siaddr, "clientIP": pa[BOOTP].yiaddr,
        #            "XID": dhcp_discover[BOOTP].xid}
        #result = srp1(dhcp_discover, verbose=False)#, iface="Software Loopback Interface 1"  # expecting to recieve an offer msg
        #result.show()


        #for packet in pa:
            #if DHCP in result and result[DHCP].options[0][1] == 2:
        #    if DHCP in pa and pa[BOOTP][DHCP].options == 2:  # message type=2, that means offer message
        #            dhcp_request = generator.request_generate()
        #            print("sent request")
        #            result1 = srp1(dhcp_request, lfilter=filter)# expecting to recieve an acknowledge msg
        #            for packet in result1:
        #                    if result1[BOOTP][DHCP].options == 5:
        #                            print("it works")
        #                   else:
        #                            print("error")
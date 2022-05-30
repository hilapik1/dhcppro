import socket
import time
from datetime import date
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
import scapy.all as scapy
from scapy.layers.l2 import Ether
import os
from file import Constants
from datetime import datetime, timedelta
import logging
from DBHandler import DBHandler
from DHCPHandler import DHCPHandler
from Analyse import Analyse
from grafic import Creation

MAX_MSG_LENGTH = 1024
UDP_IP = "192.168.31.24"
UDP_PORT = 2023
DISCOVER_MESSAGE = "discover"
OFFER_MESSAGE = "offer"
REQUEST_MESSAGE = "request"
ACKNOWLEDGE_MESSSAGE = "acknowledge"
MAX_COUNT = 40
LAST_NUM = 26
IP_ADRESS = "192.168.10.10"
SUBNET_MASK = "255.255.255.0"
Index = 1
SIZE_QUEUE = 0


# server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
# server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# server_socket.bind((UDP_IP, UDP_PORT))
# #server_socket.listen()



def main():
    logging.basicConfig(format='%(created)f [%(levelname)s] - %(threadName)s - %(message)s')
    logging.getLogger().setLevel(logging.INFO)
    db_handler = DBHandler('localhost', "root", 'cyber', 'dhcppro')
    db_handler.clean_ack_table()
    analyser = Analyse(db_handler)
    handler = DHCPHandler(analyser)

    while True:

        logging.debug("enter to loop")
        #try:

        logging.debug("enter to try")
        # sock.sendto(bytes("hello", "utf-8"), ip_co)
        pa = sniff(lfilter=handler.filter, prn=handler.handle)#expecting to recieve discover msg

        #except Exception as ex:
            #print(ex)
            #print("error")
            #continue


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
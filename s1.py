from scapy.all import *
import logging
from DBHandler import DBHandler
from DHCPHandler import DHCPHandler
from Analyse import Analyse



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



def main():
    logging.basicConfig(format='%(created)f [%(levelname)s] - %(threadName)s - %(message)s')
    logging.getLogger().setLevel(logging.INFO)
    db_handler = DBHandler()
    db_handler.clean_ack_table()
    db_handler.clean_discover_table()
    analyser = Analyse(db_handler)
    handler = DHCPHandler(analyser)

    while True:

        pa = sniff(lfilter=handler.filter, prn=handler.handle)#expecting to recieve discover msg



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
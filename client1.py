import logging
import socket
from time import sleep
from scapy.all import *
from scapy.layers.inet import UDP
import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
import random
from file import Constants
from threading import Thread


def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


class DHCPHandler:

    def __init__(self, lease_time_worker, client_info):
        self.lease_time_worker = lease_time_worker
        self.client_info = client_info

        #self.generate = DHCP_generator(Constants.src_port, Constants.dest_port, client_mac)

    def filter(self, pack):
        if not (DHCP in pack):
            return False

        if not(BOOTP in pack):
            return False

        if not(pack[BOOTP].xid in self.client_info.dict.keys()):
            return False

        pa_in_dict = self.client_info.dict[pack[BOOTP].xid]
        if pack[BOOTP][DHCP].options[0][1] == Constants.OFFER:
            if pa_in_dict[BOOTP][DHCP].options[0][1] == Constants.DISCOVER:
                return True
        elif pack[BOOTP][DHCP].options[0][1] == Constants.ACK:
            if pa_in_dict[BOOTP][DHCP].options[0][1] == Constants.REQUEST:
                return True

        return False


    def handle(self, pack):
        #צריכה לעשות מחלקה נפרדת בקובץ נפרד של כל הטיפול בבקשות השונות (כמו שעשיתי בסרבר)
        message_type = pack[BOOTP][DHCP].options[0][1]
        if message_type == Constants.OFFER:
            #handle_offer(pa)
            #self.generate.request_generate(pack[BOOTP].siaddr, pack[BOOTP].yiaddr, pack[BOOTP].chaddr)
            pa_in_dict = self.client_info.dict[pack[BOOTP].xid]
            request = request_generate(pack[BOOTP].siaddr, pack[BOOTP].yiaddr, pa_in_dict[BOOTP].chaddr, pack[BOOTP].xid)
            self.client_info.dict[pack[BOOTP].xid] = request
            sendp(request)

        elif message_type == Constants.ACK:
            lease_time = pack[BOOTP][DHCP].options[5][1]
            self.lease_time_worker.init_last_time(lease_time)
            self.client_info.dict.pop(pack[BOOTP].xid)
            #handle_ack()
            logging.debug("ACK WAS RECIEVED")



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
            DHCP(options=[("message-type", Constants.DISCOVER), "end"])
    )
    #dhcp_discover.show()
    return dhcp_discover

def request_generate(server_ip, client_ip, client_mac, t_xid):
    #src_port=2025, dst_port=2023
    dhcp_request = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=Constants.src_port, dport=Constants.dest_port) /
            BOOTP(xid=t_xid, chaddr=client_mac)/#mac_to_bytes(client_mac)) /
            DHCP(options=[("message-type", Constants.REQUEST), ("server_id", server_ip),
                          ("requested_addr", client_ip), "end"]))
    return dhcp_request

def sniffer(filter, handler):
    pa = sniff(lfilter=filter, prn=handler)

class ClientLeaseTimeHandler:
    INIT = 0
    SAFE_TIME = 1
    RENEW_TIME = 2
    EXPIRED_TIME = 3
    def __init__(self, client_info):
        self.lease_time = 0
        self.last_ack_time = -1
        self.factor = 0.8
        self.state = ClientLeaseTimeHandler.INIT
        self.renew_discover_sent = False
        self.client_info = client_info

    def worker(self):
        while True:
            logging.info(f"state = {self.state}")
            if self.state != ClientLeaseTimeHandler.INIT:
                    #check lease time:
                curtime = datetime.now()
                if (curtime - self.last_ack_time).total_seconds() > self.lease_time:
                    self.state = ClientLeaseTimeHandler.EXPIRED_TIME
                    # ClientLeaseTimeHandler.EXPIRED_TIME
                    dhcp_discover = discover_generate(self.client_info.client_mac)
                    id = dhcp_discover[BOOTP].xid
                    self.client_info.dict[id] = dhcp_discover
                    #dhcp_discover.show()
                    sendp(dhcp_discover)

                    self.renew_discover_sent = True

                elif (curtime - self.last_ack_time).total_seconds() > self.lease_time * self.factor:
                    # ClientLeaseTimeHandler.RENEW_TIME
                    self.state = ClientLeaseTimeHandler.RENEW_TIME
                    if self.renew_discover_sent == False:

                        dhcp_discover = discover_generate(self.client_info.client_mac)
                        id = dhcp_discover[BOOTP].xid
                        self.client_info.dict[id] = dhcp_discover
                        #dhcp_discover.show()
                        sendp(dhcp_discover)

                        self.renew_discover_sent = True


                else:
                    pass # ClientLeaseTimeHandler.SAFE_TIME

                # if almost expired:
                    # resend discover..
            time.sleep(1)

    def init_last_time(self, lease_time):
        self.lease_time = lease_time
        self.last_ack_time = datetime.now()
        self.state = ClientLeaseTimeHandler.SAFE_TIME
        self.renew_discover_sent = False

    def ip_lease_status(self):
        return self.state

class ClientInfo:
    def __init__(self):
        self.client_mac = "40:B0:34:1D:AB:65"
        self.dict = {}

def main():
    logging.basicConfig(format='%(created)f [%(levelname)s] - %(threadName)s - %(message)s')
    logging.getLogger().setLevel(logging.INFO)
    client_info = ClientInfo()

    lease_time_worker = ClientLeaseTimeHandler(client_info)
    handler = DHCPHandler(lease_time_worker, client_info)
    t = Thread(target=sniffer, args=(handler.filter, handler.handle))
    t.start()
    t2 = Thread(target=lease_time_worker.worker)
    t2.start()
    time.sleep(0.5)


    client_mac = "40:B0:34:1D:AB:65"#"01:02:03:04:05:06"
    #generator = DHCP_generator(Constants.src_port, Constants.dest_port, client_mac)# src_port=2025, dest_port=2023
    #dhcp_discover = generator.discover_generate()
    dhcp_discover = discover_generate(client_info.client_mac)
    id = dhcp_discover[BOOTP].xid
    client_info.dict[id] = dhcp_discover
    dhcp_discover.show()
    sendp(dhcp_discover)

    t.join()

if __name__=="__main__":
    main()
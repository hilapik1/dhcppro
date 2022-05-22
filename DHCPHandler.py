from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import scapy.all as scapy
from file import Constants
from s1 import IP_allocator
from s1 import LeaseTimeHandler
IP_ADRESS = "192.168.10.10"
SUBNET_MASK = "255.255.255.0"

class DHCPHandler:
    def __init__(self, analyser):
        #tables and database, and etc
        self.ip_allocator = IP_allocator(SUBNET_MASK, IP_ADRESS)
        self.leasetime_handler = LeaseTimeHandler()
        self.lease_thread = Thread(target=self.leasetime_handler.worker, args=(self.ip_allocator,))
        self.lease_thread.start()
        self.analyser=analyser

    def filter(self, packet):
        if UDP in packet:
            logging.debug(packet[UDP].dport)
            if packet[UDP].dport == Constants.dest_port:
                if DHCP in packet:
                    return True
        return False

    def handle(self, packet):
        #packet.show()
        if Ether in packet:
            mac = packet[BOOTP].chaddr
        logging.debug(packet)
        logging.debug(packet[BOOTP])
        type_message = packet[BOOTP][DHCP].options#[0][1]  # 1-discover, 3-request
        if self.is_discover(packet):
            logging.info(f"{Constants.OP2CMD[Constants.DISCOVER]} from mac {mac}")
            self.handle_discover(packet, mac)

        elif self.is_request(packet):
            logging.info(f"{Constants.OP2CMD[Constants.REQUEST]} from mac {mac}")
            self.handle_request(packet, mac)

    def handle_discover(self, packet,mac):
        # build offer
        #--------------------------
        self.analyser.analyse_discover(packet)#when we got discover we call to analyse
        if mac in self.leasetime_handler.getOfferDict().keys():
            ip_requested = self.leasetime_handler.getOfferDict()[mac][0]  # how to renew timeout
        else:
            ip_requested = self.ip_allocator.offer_dictionary(mac, self.leasetime_handler.getAllocatedDict(), self.leasetime_handler.getOfferDict())
        #--------------------------
        #ip_requested = self.ip_obj.offer_dictionary(mac)
        logging.info(f"---handle_discover - ip = {ip_requested}")
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src="18:60:24:8F:64:90", type=0x800)
        ip = IP(dst="255.255.255.255", src="172.16.20.211")  # dest_addr
        udp = UDP(sport=Constants.dest_port, dport=Constants.src_port)
        bootp = BOOTP(xid=packet[BOOTP].xid, flags=0x8000, op=2, yiaddr=ip_requested, siaddr="172.16.20.211", chaddr="ff:ff:ff:ff:ff:ff")
        dhcp = DHCP(
            options=[("message-type", Constants.OFFER), ("server_id", ip_requested), ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", 8267)])  # router - gateway :"172.16.255.254"
        of_pack = ethernet / ip / udp / bootp / dhcp
        sendp(of_pack)
        logging.debug("packet was sent")

    def handle_request(self, packet, mac):
        logging.debug("---handle_request")
        # build acknowledge
        self.analyser.analyse_request(packet)#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ NEW
        #cur_ip = packet[DHCP].options[2][1] ?
        if mac in self.leasetime_handler.getOfferDict().keys():
            #to check about the mac_bytes to mac in string- how to do it
            logging.debug(f"****** request from {self.prettify(mac)} ******")
            cur_ip = self.leasetime_handler.getOfferDict()[mac][0]
            self.leasetime_handler.getOfferDict().pop(mac)
            self.ip_allocator.acknowledge_dictionary(cur_ip, mac, self.leasetime_handler.getAllocatedDict())
        else:
            logging.warning(f"TODO: error - need to send NAK message to {self.prettify(mac)}")
            return

        ethernet = Ether(dst=self.prettify(mac), src="18:60:24:8F:64:90", type=0x800)
        # save_ip=get_requested_ip(IpQueue)
        ip = IP(dst=cur_ip, src="192.168.10.10")  # destination address
        udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
        bootp = BOOTP(xid=packet[BOOTP].xid, op=2, yiaddr=cur_ip, siaddr="192.168.10.10", chaddr=self.prettify(mac))
        dhcp = DHCP(
            options=[("message-type", Constants.ACK), ("server_id", cur_ip), ("broadcast_address", "255.255.255.255"),
                     ("router", "192.168"
                                ".255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", Constants.LEASE_TIME)])  # router - gateway :"172.16.255.254"
        of_pack1 = ethernet / ip / udp / bootp / dhcp
        #of_pack1.show()
        # send ack
        sendp(of_pack1)

    @staticmethod
    def prettify(mac_bytes):
        #convert mac bytes to string
        #return ":".join('%02x' % ord(b) for b in mac_bytes)
        logging.debug("&&&&"+mac_bytes.hex(":")[0:Constants.MAC_ADDRESS_LENGTH]+"&&&&&")
        #mac_bytes[0:6].hex(":") ANOTHER OPTION
        #print(mac_bytes)
        #print(mac_bytes.hex(":"))
        #print(type(mac_bytes.hex(":")[0:17]))
        return mac_bytes.hex(":")[0:Constants.MAC_ADDRESS_LENGTH]


    @staticmethod
    def is_discover(packet) -> bool:
        type_message = packet[DHCP].options[0][1]  # 1-discover, 3-request
        if type_message == Constants.DISCOVER:
            return True
        else:
            return False

    @staticmethod
    def is_request(packet) -> bool:
        type_message = packet[BOOTP][DHCP].options[0][1] # 1-discover, 3-request
        if type_message == Constants.REQUEST:
            return True
        else:
            return False


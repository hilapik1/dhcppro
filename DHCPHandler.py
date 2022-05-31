from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import ipaddress
import scapy.all as scapy
from file import Constants
from Analyse import Analyse
from queue import Queue
from Analyse import Analyse

IP_ADDRESS = "192.168.10.10"
SUBNET_MASK = "255.255.255.0"



class LeaseTimeHandler:
    def __init__(self, analyser):
        self.__offer_dict__ = {}
        self.__allocated_dict__ = {}
        self.__analyser__ = analyser

    def getOfferDict(self):
        return self.__offer_dict__

    def getAllocatedDict(self):
        return self.__allocated_dict__

    def addOffer(self, mac, ip):
        pass

    def addAllocated(self, mac, ip):
        pass

    def removeFromOffer(self, mac):
        pass

    def removeFromAllocated(self, mac):
        pass

    def getOfferedMacKeys(self):
        pass

    def getAllocatedMacKeys(self):
        pass

    def bytes_to_str(self,mac_addr: bytes)->str:
        mac_s = mac_addr[:6].hex()
        mac_addr = mac_s[:2]
        for i in range(2,len(mac_s),2):
            mac_addr += ":"
            mac_addr += mac_s[i:i+2]

        return mac_addr

    def worker(self, ip_allocator):
        while True:
            logging.debug("worker iterration")
            time.sleep(1)
            curtime = datetime.now()
            logging.info(f"worker: checking ips in offer lease")
            remove_list = []
            for mac in self.__offer_dict__.keys():
                self.__check_lease_time(curtime, mac, self.__offer_dict__, remove_list, ip_allocator)

            logging.info(f"worker: clean offer dict")
            for mac in remove_list:
                self.__offer_dict__.pop(mac)

            remove_list = []
            logging.info(f"worker: checking ips in allocated lease")
            for mac in self.__allocated_dict__.keys():
                self.__check_lease_time(curtime, mac, self.__allocated_dict__, remove_list, ip_allocator)

            for mac in remove_list:
                #####################################
                #delete from acktable
                self.__analyser__.delete_from_ack_table(self.bytes_to_str(mac))  ############################
                self.__allocated_dict__.pop(mac)

    def __check_lease_time(self, curtime, mac, dict, remove_list, ip_allocator):
        ip, lease_time, original_time = dict[mac]
        diff = curtime - original_time
        result = diff.total_seconds()
        logging.debug(f"worker: calculated diff = {result}")
        if result < lease_time:
            logging.debug(f"worker: still more time")
            # its ok
            pass
        else:
            # ip need to return to ip bank
            logging.info(f"worker: timeout occured, move ip {ip} back to bank")
            ip_allocator.add_2_bank(ip)
            remove_list.append(mac)



class IP_allocator:

    def __init__(self, subnet_mask, ip_addr):
        self.subnet_mask = subnet_mask
        self.ip_addr = ip_addr
        self.ip_bank = Queue()
        # identify static part in ip
        self.subnet_mask_parts = self.subnet_mask.split(Constants.IP_SAPARATOR)
        self.ip_addr_parts = self.ip_addr.split(Constants.IP_SAPARATOR)

        # ip_
        # upples_parts = []
        # for i in range(0, len(self.subnet_mask_parts))]:
        #    ip_tupples_parts.append((self.subnet_mask_parts[i], self.ip_addr_parts[i]))
        ip_tupples_parts = [(self.subnet_mask_parts[i], self.ip_addr_parts[i]) for i in range(0, len(self.subnet_mask_parts))]
        subnet_counter = 0
        for part in ip_tupples_parts:
            if part[Constants.MASK_PART] == Constants.STATIC_MASK_PART:
                subnet_counter += 8

            else:
                num = int(part[Constants.MASK_PART])
                if num != 0:
                    subnet_counter += 8
                    while num != 0:
                        digit = num % 2
                        num = num / 2
                        if digit == 1:
                            break
                        subnet_counter -= 1

        sub_ip_parts = []
        for part in ip_tupples_parts:
            mask_part = int(part[Constants.MASK_PART])
            ip_part = int(part[Constants.IP_PART])
            res_part = mask_part & ip_part
            sub_ip_parts.append(str(res_part))


        net4 = ipaddress.ip_network(".".join(sub_ip_parts) + '/' + str(subnet_counter))

        self.size_queue = 0
        for x in net4.hosts():
            logging.info(f"inventory ip {x}")
            self.ip_bank.put(x)
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

    def offer_dictionary(self, mac, allocated_dict, offer_dict):
        if mac in allocated_dict.keys():
             logging.debug("-------------------- found mac --- reoffering ------------------------")
             ip_requested = allocated_dict[mac][0]
             allocated_dict.pop(mac)
        else:
             logging.debug("@@@@@@@@@@@@@@@@@@@@@ new mac @@@ offering @@@@@@@@@@@@@@@@@@@@@@@@@")
             ip_requested = self.ip_bank.get()
             logging.info(f"!!!!!!!!!!!!! the number of ip addresses that was left: {self.ip_bank.qsize()} !!!!!!!!!!!!!!!!!!!")

        timeout = Constants.LEASE_TIME
        now = datetime.now()
        offer_dict.update({mac: (ip_requested, timeout, now)})
        return ip_requested

    def acknowledge_dictionary(self, ip, mac, allocated_dict):
        #check why it remove me from allocated dict
        timeout = Constants.LEASE_TIME*20
        ####################################################################################### cheat remove*20
        now = datetime.now()
        allocated_dict.update({mac: (ip, timeout, now)})
        return allocated_dict

    def update_ackknowledge_lease_time(self, mac, allocated_dict):
        now = datetime.now()
        allocated_dict[mac] = (allocated_dict[mac][0], Constants.LEASE_TIME, now)
        return allocated_dict

    def add_2_bank(self, ip):
        self.ip_bank.put(ip)
        logging.info(f"!!!!!!!!!!!!! the number of ip addresses that was left: {self.ip_bank.qsize()} !!!!!!!!!!!!!!!!!!!")


class DHCPHandler:
    def __init__(self, analyser):
        #tables and database, and etc
        self.ip_allocator = IP_allocator(SUBNET_MASK, IP_ADDRESS)
        self.leasetime_handler = LeaseTimeHandler(analyser)
        self.lease_thread = Thread(target=self.leasetime_handler.worker, args=(self.ip_allocator,))
        self.lease_thread.start()
        self.analyser=analyser
        self.lease_time=0

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
        what_to_do = self.analyser.analyse_discover(packet)#when we got discover we call to analyse
        if what_to_do == Analyse.DO_NOTHING:
            if mac in self.leasetime_handler.getOfferDict().keys():
                self.ip_allocator.add_2_bank(self.leasetime_handler.getOfferDict()[mac])
                self.leasetime_handler.getOfferDict().pop(mac)
                return

        if mac in self.leasetime_handler.getOfferDict().keys():
            ip_requested = self.leasetime_handler.getOfferDict()[mac][0]  # how to renew timeout
        else:
            ip_requested = self.ip_allocator.offer_dictionary(mac, self.leasetime_handler.getAllocatedDict(), self.leasetime_handler.getOfferDict())
        #--------------------------
        #self.lease_time=8267
        #ip_requested = self.ip_obj.offer_dictionary(mac)
        logging.info(f"---handle_discover - ip = {ip_requested}")
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src="18:60:24:8F:64:90", type=0x800)
        ip = IP(dst="255.255.255.255", src="192.168.10.10")  # dest_addr
        udp = UDP(sport=Constants.dest_port, dport=Constants.src_port)
        bootp = BOOTP(xid=packet[BOOTP].xid, flags=0x8000, op=2, yiaddr=ip_requested, siaddr="192.168.10.10", chaddr="ff:ff:ff:ff:ff:ff")
        dhcp = DHCP(
            options=[("message-type", Constants.OFFER), ("server_id", ip_requested), ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", Constants.LEASE_TIME)])  # router - gateway :"172.16.255.254"
        of_pack = ethernet / ip / udp / bootp / dhcp
        sendp(of_pack)
        logging.debug("packet was sent")

    def handle_request(self, packet, mac):
        logging.debug("---handle_request")
        # build acknowledge
        what_to_do = self.analyser.analyse_request(packet)#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ NEW
        if what_to_do == Analyse.DO_NOTHING:
            return
        #cur_ip = packet[DHCP].options[2][1] ?
        if mac in self.leasetime_handler.getOfferDict().keys():
            #to check about the mac_bytes to mac in string- how to do it
            logging.debug(f"****** request from {self.prettify(mac)} ******")
            cur_ip = self.leasetime_handler.getOfferDict()[mac][0]
            self.leasetime_handler.getOfferDict().pop(mac)
            self.ip_allocator.acknowledge_dictionary(cur_ip, mac, self.leasetime_handler.getAllocatedDict())

        # just renew lease time
        elif mac in self.leasetime_handler.getAllocatedDict().keys():
            cur_ip = self.leasetime_handler.getAllocatedDict()[mac][0]
            self.ip_allocator.update_ackknowledge_lease_time(mac, self.leasetime_handler.getAllocatedDict())

        else:
            logging.warning(f"TODO: error - need to send NAK message to {self.prettify(mac)}")
            return

        print(cur_ip)
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

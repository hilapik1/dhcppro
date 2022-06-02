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
    def _init_(self, analyser):
        '''

        :param analyser: object who connects to the db and analyzes the data
        return: doesn't return anything, just creates two dictionaries and initializes the analyse object.
        '''
        self._offer_dict_ = {}
        self._allocated_dict_ = {}
        self._analyser_ = analyser

    def getOfferDict(self):
        return self._offer_dict_

    def getAllocatedDict(self):
        return self._allocated_dict_

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
        '''

        :param mac_address:
        :return: mac address in type string.
        '''
        mac_s = mac_addr[:6].hex()
        mac_addr = mac_s[:2]
        for i in range(2,len(mac_s),2):
            mac_addr += ":"
            mac_addr += mac_s[i:i+2]

        return mac_addr

    def worker(self, ip_allocator):
        '''

        :param ip_allocator:
        :return: doesn't return anything, just checking if the timeout occurred and then we will delete him from the dict and return the ip to bank,
                                          else, nothing will happen.
        '''
        while True:
            logging.debug("worker iterration")
            time.sleep(1)
            curtime = datetime.now()
            logging.info(f"worker: checking ips in offer lease")
            remove_list = []
            for mac_str in self._offer_dict_.keys():
                self._check_lease_time(curtime, mac_str, self.offer_dict_, remove_list, ip_allocator)

            logging.info(f"worker: clean offer dict")
            for mac_str in remove_list:
                self._offer_dict_.pop(mac_str)

            remove_list = []
            logging.info(f"worker: checking ips in allocated lease")
            for mac_str in self._allocated_dict_.keys():
                self._check_lease_time(curtime, mac_str, self.allocated_dict_, remove_list, ip_allocator)

            for mac_str in remove_list:
                #####################################
                #delete from acktable
                #self._analyser_.delete_from_ack_table(self.bytes_to_str(mac))  ############################
                self._analyser_.delete_from_ack_table(mac_str)
                self._allocated_dict_.pop(mac_str)

    def __check_lease_time(self, curtime, mac_str, dict, remove_list, ip_allocator):
        '''

        :param curtime: the current time
        :param mac_str: mac in type string
        :param dict: offer dictionary / allocated dictionary
        :param remove_list: if a timeout occurred we will want to remove this query from the dict, and we will update the remove list.
        :param ip_allocator: object who allocates the IP addresses.
        :return: doesn't return anything, just checking the lease time and do whatever that is required according to the lease time.
        '''
        ip, lease_time, original_time = dict[mac_str]
        diff = curtime - original_time
        result = diff.total_seconds()
        logging.debug(f"worker: calculated diff = {result}")
        if result < lease_time:
            logging.debug(f"worker: still more time")
            # its ok
            pass
        else:
            # ip need to return to ip bank
            logging.info(f"worker: timeout occurred, move ip {ip} back to bank")
            ip_allocator.add_2_bank(ip)
            remove_list.append(mac_str)



class IP_allocator:

    def _init_(self, subnet_mask, ip_addr):
        '''

        :param subnet_mask:
        :param ip_addr:
        return: doesn't return anything, just creates ip addresses and put it in a queue - ip bank
        '''
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

    def offer_dictionary(self, mac_str, allocated_dict, offer_dict):
        '''
        :param mac_str:
        :param allocated_dict: {mac_str: (ip, timeout, now)}
        :param offer_dict: {mac_str: (ip_requested, timeout, now)}
        :return: new ip, if a new mac sent to the server discover for the first time -> the server will send him offer
                         else, if the mac already exist in allocated dict, the server will send him reoffer and return the ip
                                that the client was gotten in the last time.
        '''
        if mac_str in allocated_dict.keys():
             logging.debug("-------------------- found mac --- reoffering ------------------------")
             ip_requested = allocated_dict[mac_str][0]
             allocated_dict.pop(mac_str)
        else:
             logging.debug("@@@@@@@@@@@@@@@@@@@@@ new mac @@@ offering @@@@@@@@@@@@@@@@@@@@@@@@@")
             ip_requested = self.ip_bank.get()
             logging.info(f"!!!!!!!!!!!!! the number of ip addresses that was left: {self.ip_bank.qsize()} !!!!!!!!!!!!!!!!!!!")

        timeout = Constants.LEASE_TIME
        now = datetime.now()
        offer_dict.update({mac_str: (ip_requested, timeout, now)})
        return ip_requested


    def acknowledge_dictionary(self, ip, mac_str, allocated_dict):
        '''

        :param ip:
        :param mac_str:
        :param allocated_dict: {mac_str: (ip, timeout, now)}
        :return: allocated dictionary after updating it.
        '''
        timeout = Constants.LEASE_TIME*20
        ####################################################################################### cheat remove*20
        now = datetime.now()
        allocated_dict.update({mac_str: (ip, timeout, now)})
        return allocated_dict

    def update_ackknowledge_lease_time(self, mac_str, allocated_dict):
        '''
        :param mac_str:
        :param allocated_dict: {mac_str: (ip, timeout, now)}
        :return: allocated dictionary after renewing the lease time of the mac we got as parameter.
        '''
        now = datetime.now()
        allocated_dict[mac_str] = (allocated_dict[mac_str][0], Constants.LEASE_TIME, now)
        return allocated_dict

    def add_2_bank(self, ip):
        '''

        :param ip:
        :return: doesn't return anything, just return the ip to the bank (queue).
        '''
        self.ip_bank.put(ip)
        logging.info(f"!!!!!!!!!!!!! the number of ip addresses that was left: {self.ip_bank.qsize()} !!!!!!!!!!!!!!!!!!!")



class DHCPHandler:
    def _init_(self, analyser):
        '''

        :param analyser: object who connects to the db and analyzes the data
        return: doesn't return anything, just initializes the variables and starts the lease thread.
        '''

        self.ip_allocator = IP_allocator(SUBNET_MASK, IP_ADDRESS)
        self.leasetime_handler = LeaseTimeHandler(analyser)
        self.lease_thread = Thread(target=self.leasetime_handler.worker, args=(self.ip_allocator,))
        self.lease_thread.start()
        self.analyser=analyser
        self.lease_time=0

    def filter(self, packet):
        '''

        :param packet:
        :return: True if it's a DHCP packet, else: returns False
        '''
        if UDP in packet:
            logging.debug(packet[UDP].dport)
            if packet[UDP].dport == Constants.dest_port:
                if DHCP in packet:
                    return True
        return False

    def bytes_to_str(self, mac_addr: bytes) -> str:
        '''
         :param mac_addr:
         :return: mac address in type string.
        '''
        mac_s = mac_addr[:6].hex()
        mac_addr = mac_s[:2]
        for i in range(2, len(mac_s), 2):
            mac_addr += ":"
            mac_addr += mac_s[i:i + 2]

        return mac_addr

    def handle(self, packet):
        '''

        :param packet:
        :return: doesn't return anything, just checking the type of packet we got, and then call to relevant functions.
        '''
        #packet.show()
        if Ether in packet:
            mac = packet[BOOTP].chaddr
            mac_str=self.bytes_to_str(mac)
        logging.debug(packet)
        logging.debug(packet[BOOTP])
        type_message = packet[BOOTP][DHCP].options#[0][1]  # 1-discover, 3-request
        if self.is_discover(packet):
            logging.info(f"{Constants.OP2CMD[Constants.DISCOVER]} from mac {mac_str}")
            self.handle_discover(packet,mac, mac_str)

        elif self.is_request(packet):
            logging.info(f"{Constants.OP2CMD[Constants.REQUEST]} from mac {mac_str}")
            self.handle_request(packet, mac, mac_str)


    def handle_discover(self, packet,mac, mac_str: str):
        '''

        :param packet:
        :param mac: in bytes
        :param mac_str: type-> string
        :return: doesn't return anything, just send an offer packet.
        '''
        # build offer
        #--------------------------
        what_to_do = self.analyser.analyse_discover(packet)#when we got discover we call to analyse
        if what_to_do == Analyse.DO_NOTHING:
            if mac_str in self.leasetime_handler.getOfferDict().keys():
                self.ip_allocator.add_2_bank(self.leasetime_handler.getOfferDict()[mac_str][0]) #return the ip to bank
                self.leasetime_handler.getOfferDict().pop(mac_str)
                return

        if mac_str in self.leasetime_handler.getOfferDict().keys():
            ip_requested = self.leasetime_handler.getOfferDict()[mac_str][0]
        else:
            ip_requested = self.ip_allocator.offer_dictionary(mac_str, self.leasetime_handler.getAllocatedDict(), self.leasetime_handler.getOfferDict())
        #--------------------------
        #self.lease_time=8267
        #ip_requested = self.ip_obj.offer_dictionary(mac)
        logging.info(f"---handle_discover - ip = {ip_requested}")
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src="18:60:24:8F:64:90", type=0x800)
        ip = IP(dst="255.255.255.255", src="192.168.10.10")  # dest_addr
        udp = UDP(sport=Constants.dest_port, dport=Constants.src_port)
        bootp = BOOTP(xid=packet[BOOTP].xid, flags=0x8000, op=2, yiaddr=ip_requested, siaddr="192.168.10.10", chaddr=mac)
        dhcp = DHCP(
            options=[("message-type", Constants.OFFER), ("server_id", ip_requested), ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", Constants.LEASE_TIME)])  # router - gateway :"172.16.255.254"
        of_pack = ethernet / ip / udp / bootp / dhcp
        sendp(of_pack)
        logging.debug("packet was sent")

    def handle_request(self, packet, mac, mac_str: str):
        '''

        :param packet:
        :param mac: in bytes
        :param mac_str: type-> string
        :return: doesn't return anything, just send a request packet.
        '''
        logging.debug("---handle_request")
        logging.debug(mac_str)
        # build acknowledge
        what_to_do = self.analyser.analyse_request(packet)#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ NEW
        if what_to_do == Analyse.DO_NOTHING:
            return
        #cur_ip = packet[DHCP].options[2][1] ?
        if mac_str in self.leasetime_handler.getOfferDict().keys():
            #to check about the mac_bytes to mac in string- how to do it
            logging.debug(f"** request from {mac_str} **")
            cur_ip = self.leasetime_handler.getOfferDict()[mac_str][0]
            self.leasetime_handler.getOfferDict().pop(mac_str)
            self.ip_allocator.acknowledge_dictionary(cur_ip, mac_str, self.leasetime_handler.getAllocatedDict())

        # just renew lease time
        elif mac_str in self.leasetime_handler.getAllocatedDict().keys():
            cur_ip = self.leasetime_handler.getAllocatedDict()[mac_str][0]
            self.ip_allocator.update_ackknowledge_lease_time(mac_str, self.leasetime_handler.getAllocatedDict())

        else:
            logging.warning(f"TODO: error - need to send NAK message to {mac_str}")
            return

        print(cur_ip)
        ethernet = Ether(dst=mac_str, src="18:60:24:8F:64:90", type=0x800)
        # save_ip=get_requested_ip(IpQueue)
        ip = IP(dst=cur_ip, src="192.168.10.10")  # destination address
        udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
        bootp = BOOTP(xid=packet[BOOTP].xid, op=2, yiaddr=cur_ip, siaddr="192.168.10.10", chaddr=mac)
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
        '''

        :param packet:
        :return: True if the packet from type message "discover", else return False
        '''
        type_message = packet[DHCP].options[0][1]  # 1-discover, 3-request
        if type_message == Constants.DISCOVER:
            return True
        else:
            return False

    @staticmethod
    def is_request(packet) -> bool:
        '''
        :param packet:
        :return: True if the packet from type message "request", else return False
        '''
        type_message = packet[BOOTP][DHCP].options[0][1] # 1-discover, 3-request
        if type_message == Constants.REQUEST:
            return True
        else:
            return False
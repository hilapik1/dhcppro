from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import ipaddress
from file import Constants
from queue import Queue
from Analyse import Analyse

IP_ADDRESS = sys.argv[3]#"192.168.10.10" #sys.argv[3]   to do argv in server
SUBNET_MASK = sys.argv[2]#"255.255.255.0" #sys.argv[2]
#sys.argv = ["1", "18:60:24:8F:64:90", "3" ,"4"]
MAC_ADDRESS=sys.argv[1]


class LeaseTimeHandler:
    def __init__(self, analyser):
        '''

        :param analyser: object who connects to the db and analyzes the data
        return: doesn't return anything, just creates two dictionaries and initializes the analyse object.
        '''
        self.__offer_dict__ = {}
        self.__allocated_dict__ = {}
        self.__analyser__ = analyser

    def getOfferDict(self):
        return self.__offer_dict__

    def getAllocatedDict(self):
        return self.__allocated_dict__


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

    def str_to_bytes(self, mac_addr: str)->bytes:
        '''
        Convers a MAC address string to byte.
        :return: MAC address in bytes
        '''
        s= mac_addr.replace(":","")
        int_s=int(s,16)
        bytes_s=int_s.to_bytes(6,"big")
        return bytes_s

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
            for mac_str in self.__offer_dict__.keys():
                self.__check_lease_time(curtime, mac_str, self.__offer_dict__, remove_list, ip_allocator)

            logging.info(f"worker: clean offer dict")
            for mac_str in remove_list:
                self.__offer_dict__.pop(mac_str)
                #need to send NAK

            remove_list = []
            logging.info(f"worker: checking ips in allocated lease")
            for mac_str in self.__allocated_dict__.keys():
                self.__check_lease_time(curtime, mac_str, self.__allocated_dict__, remove_list, ip_allocator)

            for mac_str in remove_list:
                self.__analyser__.delete_from_ack_table(mac_str)
                self.__allocated_dict__.pop(mac_str)
                # need to send NAK , when expired




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

    def __init__(self, subnet_mask, ip_addr):
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
            # reduce reserverd ip's:
            if x.exploded.split(".")[3] == '1' or \
                x.exploded.split(".")[3] == '255' or \
                x.exploded.split(".")[3] == '254' or \
                x.exploded == IP_ADDRESS:
                continue
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

    def offer_dictionary(self, mac_str, allocated_dict, offer_dict, ip_requested_hint):
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
            ip_requested = ""
            if not ip_requested_hint == "": # hint ip requested
                tempq = Queue()
                queue_size = self.ip_bank.qsize()
                for i in range(queue_size):
                    ip = self.ip_bank.get()
                    if ip.exploded == ip_requested_hint:
                        ip_requested = ip
                        break
                    else:
                        tempq.put(ip)

                queue_size = self.ip_bank.qsize()
                for i in range(queue_size):
                    ip = self.ip_bank.get()
                    tempq.put(ip)
                self.ip_bank = tempq

            if ip_requested == "": # if not found hint or no hint
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
        timeout = Constants.LEASE_TIME
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
    def __init__(self, analyser):
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
            if packet[UDP].dport == Constants.server_port:
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
        if Ether in packet:
            mac = packet[BOOTP].chaddr
            mac_str=self.bytes_to_str(mac)
        logging.debug(packet)
        logging.debug(packet[BOOTP])
        if self.is_discover(packet):
            logging.info(f"{Constants.OP2CMD[Constants.DISCOVER]} from mac {mac_str}")
            self.handle_discover(packet,mac, mac_str)

        elif self.is_request(packet):
            logging.info(f"{Constants.OP2CMD[Constants.REQUEST]} from mac {mac_str}")
            self.handle_request(packet, mac, mac_str)

    #     elif self.is_decline(packet):
    #         logging.info(f"{Constants.OP2CMD[Constants.DECLINE]} from mac {mac_str}")
    #         self.handle_decline(packet,mac,mac_str)
    #
    # def handle_decline(self,packet,mac,mac_str):
    #     self.ip_allocator.offer_dictionary(mac_str,self.leasetime_handler.getAllocatedDict(),

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
            client_requested_ip_hint = self.get_requested_address_option(packet)

            ip_requested = self.ip_allocator.offer_dictionary(mac_str, self.leasetime_handler.getAllocatedDict(), self.leasetime_handler.getOfferDict(), client_requested_ip_hint)

        logging.info(f"---handle_discover - ip = {ip_requested}")
        #send offer
        of_pack=self.generate_offer(packet,ip_requested, mac)
        sendp(of_pack)
        logging.debug("packet was sent")

    def generate_offer(self, packet, ip_requested, mac):
        '''

        :param ip_requested:
        :param mac:
        :return: an offer packet
        '''
        # ("server_id", ip_requested)
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=MAC_ADDRESS, type=0x800)
        ip = IP(dst="255.255.255.255", src="192.168.10.10")  # dest_addr
        udp = UDP(sport=Constants.server_port, dport=Constants.client_port)

        logging.info(f"packet[BOOTP].xid = {packet[BOOTP].xid} of type = {type(packet[BOOTP].xid)}")
        logging.info(f"ip_requested = {ip_requested} of type = {type(ip_requested)}")
        logging.info(f"mac = {mac} of type = {type(mac)}")

        bootp = BOOTP(xid=packet[BOOTP].xid, flags=0x8000, op=2, yiaddr=ip_requested, siaddr="192.168.10.10",
                      chaddr=mac)
        dhcp = DHCP(
            options=[("message-type", Constants.OFFER), ("server_id", IP_ADDRESS),
                     ("broadcast_address", "255.255.255.255"),
                     ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", Constants.LEASE_TIME)])  # router - gateway :"172.16.255.254"
        of_pack = ethernet / ip / udp / bootp / dhcp
        return of_pack

    def handle_request(self, packet, mac, mac_str: str):
        '''

        :param packet:
        :param mac: in bytes
        :param mac_str: type-> string
        :return: doesn't return anything, just send a Ack packet.
        '''
        logging.info("---handle_request")
        logging.debug(mac_str)
        # build acknowledge
        what_to_do = self.analyser.analyse_request(packet)
        #time.sleep(30)
        if what_to_do == Analyse.DO_NOTHING:
            return

        if mac_str in self.leasetime_handler.getOfferDict().keys():
            logging.debug(f"** request from {mac_str} **")
            cur_ip = self.leasetime_handler.getOfferDict()[mac_str][0]
            self.leasetime_handler.getOfferDict().pop(mac_str)
            self.ip_allocator.acknowledge_dictionary(cur_ip, mac_str, self.leasetime_handler.getAllocatedDict())

        # just renew lease time
        elif mac_str in self.leasetime_handler.getAllocatedDict().keys():
            logging.info(f"len(self.leasetime_handler.getAllocatedDict() = {len(self.leasetime_handler.getAllocatedDict())}")
            if len(self.leasetime_handler.getAllocatedDict()) > 0:
                logging.info(f"self.leasetime_handler.getAllocatedDict().keys() = {self.leasetime_handler.getAllocatedDict().keys()}")

                logging.info(f"mac_str = {mac_str}")
                logging.info(f"self.leasetime_handler.getAllocatedDict()[mac_str] = {self.leasetime_handler.getAllocatedDict()[mac_str]}")
            cur_ip = self.leasetime_handler.getAllocatedDict()[mac_str][0]
            self.ip_allocator.update_ackknowledge_lease_time(mac_str, self.leasetime_handler.getAllocatedDict())

        else:
            logging.warning(f"TODO: error - need to send NAK message to {mac_str}")
            self.handle_NAK(packet,mac_str,mac)
            return

        if self.analyser.this_is_a_ack_msg(packet) == True:
            print(cur_ip)
            # send ack
            of_pack1=self.generate_ack(packet,cur_ip,mac_str,mac)
            sendp(of_pack1)
        else:
            # you're in blacklist
            pass

    def generate_ack(self,packet,cur_ip,mac_str,mac):
        '''

        :param cur_ip:
        :param mac_str:
        :param mac:
        :return: an ack packet
        '''
        #("server_id", cur_ip)
        ethernet = Ether(dst=mac_str, src=MAC_ADDRESS, type=0x800)
        ip = IP(dst=cur_ip, src="192.168.10.10")
        udp = UDP(sport=Constants.server_port, dport=Constants.client_port)
        bootp = BOOTP(xid=packet[BOOTP].xid, op=2, yiaddr=cur_ip, siaddr="192.168.10.10", chaddr=mac)
        dhcp = DHCP(
            options=[("message-type", Constants.ACK), ("server_id", IP_ADDRESS), ("broadcast_address", "255.255.255.255"),
                     ("router", "192.168"
                                ".255.254"), ("subnet_mask", "255.255.0.0"),
                     ("lease_time", Constants.LEASE_TIME)])  # router - gateway :"172.16.255.254"
        of_pack1 = ethernet / ip / udp / bootp / dhcp
        return of_pack1


    def handle_NAK(self,packet,mac_str, mac):
        '''

        :param packet:
        :param mac_str:
        :param mac:
        :return: doesn't return anything, just send a Nak packet.
        '''
        ethernet= Ether(src=MAC_ADDRESS,dst=mac_str)
        ip= IP(src="192.168.10.10",dst=packet[IP].dst)
        print(packet[BOOTP].ciaddr)
        udp= UDP(sport=Constants.server_port, dport=Constants.client_port)
        bootp=BOOTP(ciaddr=packet[IP].src,xid=packet[BOOTP].xid, op=2, siaddr=packet[IP].dst, chaddr=mac)
        dhcp= DHCP(options=[('server_id',"192.168.10.10"),('message-type', Constants.NAK),('end')])
        of_pack2= ethernet / ip / udp / bootp / dhcp
        of_pack2.show()
        sendp(of_pack2)

    @staticmethod
    def get_requested_address_option(packet) -> str:
        '''

        :param packet:
        :return: True if the packet from type message "discover", else return False
        '''
        for option in packet[DHCP].options:
            if option[0] == "requested_addr":
                return option[1]

        return ""

    @staticmethod
    def is_discover(packet) -> bool:
        '''

        :param packet:
        :return: True if the packet from type message "discover", else return False
        '''
        for option in packet[DHCP].options:
            if option[0]=="message-type":
                type_message = option[1]
                break

        #type_message = packet[DHCP].options[0][1]  # 1-discover, 3-request
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
        #type_message = packet[BOOTP][DHCP].options[0][1] # 1-discover, 3-request
        for option in packet[BOOTP][DHCP].options:
            if option[0]=="message-type":
                type_message = option[1]
                break
        if type_message == Constants.REQUEST:
            return True
        else:
            return False

    # @staticmethod
    # def is_decline(packet) -> bool:
    #     '''
    #     :param packet:
    #     :return: True if the packet from type message "decline", else return False
    #     '''
    #     for option in packet[BOOTP][DHCP].options:
    #         if option[0]=="message-type":
    #             type_message = option[1]
    #             break
    #     if type_message == Constants.DECLINE:
    #         return True
    #     else:
    #         return False
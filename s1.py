import ipaddress
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
import os
from file import Constants
from queue import Queue
from datetime import datetime, timedelta
import logging
from DBHandler import DBHandler
from DHCPHandler import DHCPHandler

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

class QueryMacExist:
    MAC = 0
    QUERY = "SELECT mac FROM dhcppro.discovertable where mac_address = "
    def __init__(self, mac):
        self.QUERY = QueryCountBlacklist.QUERY + mac

class QueryCountBlacklist:
    COUNT = 0
    BLACK_LIST = 1
    QUERY = "SELECT count ,black_list FROM dhcppro.discovertable where mac_address = "
    def __init__(self, mac):
        self.QUERY = QueryCountBlacklist.QUERY + mac


class Analyse:
    RETURN_OFFER = True
    DO_NOTHING = False
    def __init__(self, db_handler):
        self.mac_address = None
        self.count = 1
        self.black_list = False #check about the connection between the tinyint and the false/true , false -> this is not an attacker
        self.time_arrivel=None
        self.id=None
        self.under_attack=False #the regular state is that you are not under an attack, if you are ->self.under_attack=True
        self.db_handler = db_handler

    # connection = mysql.connector.connect(host=self.host, user=self.user, password=self.password, database=self.database)
    def __parse(self, discover_packet):
        '''
        :param discover_packet:
        :param connection:
        :return: an discover object in order to insert the details to the discover table
        '''
        self.mac_address = discover_packet[BOOTP].chaddr
        self.id = discover_packet[BOOTP].xid
        current_time = datetime.now()
        print(current_time)
        print("******************************")
        self.time_arrivel = current_time.strftime("%H:%M:%S")
        print("Current Time =", self.time_arrivel)

    def is_mac_exist(self):
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(QueryMacExist(self.mac_address).QUERY)
        for x in my_cursor:
            if x[QueryMacExist.MAC] == self.mac_address:
                return True
        return False


    def insert_mac(self,discover_packet):
        # do this if this is a new mac address that doesnt exist in table!!!!!!!!!!!! need to take care about it --- very important
        # if a discover table from the same mac address is recieved -> count++
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute("INSERT INTO `discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`)" +
                          " VALUES (" + self.mac_address + "," + self.id + "," + self.time_arrivel + "," + self.count + "," + self.black_list + ");")
        # INSERT INTO `dhcppro`.`discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`) VALUES ('\"AA:BB:CC:DD:FF', '309', '12:56:45', '0', 'false');
        if self.response_to_two_differ_states()==Analyse.RETURN_OFFER:
            #send offer
            self.dhcp_handler.handle(discover_packet)
        else:
            print("do nothing")

    def update_mac(self,discover_packet):
        my_cursor = self.db_handler.get_cursor()
        self.count += 1
        my_cursor.execute("INSERT INTO `discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`)" +
                          " VALUES (" + self.mac_address + "," + self.id + "," + self.time_arrivel + "," + self.count + "," + self.black_list + ");")
        if self.response_to_two_differ_states()==Analyse.RETURN_OFFER:
            #send offer
            self.dhcp_handler.handle(discover_packet)
        else:
            print("do nothing")
        #---------------------------------------------------------------------------------------

    def response_to_two_differ_states(self):
        # first time... till n__nice_time:(2 times) send offer... later mark as black_list
        if self.under_attack == False:  # if you are not under attack (regular state) :
            # if the mac is exist we want to check if count>=1
            my_cursor = self.db_handler.get_cursor()
            my_cursor.execute("SELECT count FROM `discovertable` WHERE `discovertable`.mac_adddress = " + self.mac_address)
            len = len(my_cursor)
            if len >= 1:  # mac address exist
                return True
                # now we need to send the offer message

        else:  # if you are under attack (attack state) :
            my_cursor = self.db_handler.get_cursor()
            my_cursor.execute(QueryCountBlacklist(self.mac_address).QUERY)
            for x in my_cursor:
                count = x[QueryCountBlacklist.COUNT]
                black_list = x[QueryCountBlacklist.BLACK_LIST]
                if count <=2:
                    if black_list == False:
                        return Analyse.RETURN_OFFER  # true
                        # now we need to send the offer message
                    # else:
                    #     return DO_NOTHING  # false
                    #     print("there is an attack")

                else:
                    my_cursor = self.db_handler.get_cursor()
                    my_cursor.execute("UPDATE 'discovertable' SET black_list = 1 WHERE mac_address = "+self.mac_address) #black_list=true
                    return Analyse.DO_NOTHING


        # if count>=2 and black list =false, send offer
        # if request was recieved -> this is not an intruder
        #   *create a delete function that will remove this user from the discover table
        #   return true
        # else if discover message was recieved -> this is an attacker
        #   *update the black list to be true
        #   return false
        # else if count>=2 and black list=true
        # return false
    def delete_from_table(self):
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute("DELETE * FROM 'discovertable' WHERE mac_address = "+self.mac_address)

    def analyse_discover(self, discover_packet):
        self.parse(discover_packet)
        if not self.is_mac_exist():
            return self.insert_mac(discover_packet)
        else:
            return self.update_mac(discover_packet)

#* first time... till n__nice_time:(2 times) send offer... later mark as black_list


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
        timeout = Constants.LEASE_TIME

        now = datetime.now()
        allocated_dict.update({mac: (ip, timeout, now)})
        return allocated_dict

    def add_2_bank(self, ip):
        self.ip_bank.put(ip)
        logging.info(f"!!!!!!!!!!!!! the number of ip addresses that was left: {self.ip_bank.qsize()} !!!!!!!!!!!!!!!!!!!")

# def filter(packet):
#     if UDP in packet:
#         if packet[UDP].dport == Constants.dest_port:
#             return True
#     return False


# def mac_to_bytes(mac_addr: str) -> bytes:
#     """ Converts a MAC address string to bytes.
#     """
#     return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


# def handle_packets(packet):
#     print("hello")
#     mac = packet[Ether].src
#     ip_obj=IP_allocator(SUBNET_MASK,IP_ADRESS)
#     type_message = packet[DHCP].options[0][1] #1-discover, 3-request
#     #build offer
#     #if type message = 1 , we will send an offer message
#     if type_message == 1:
#         ip_requested = ip_obj.offer_dictionary(mac)
#         ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
#         ip = IP(dst=ip_requested, src="172.16.20.211")#dest_addr
#         udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
#         bootp = BOOTP(op=2, yiaddr=ip_requested, siaddr="172.16.20.211", chaddr=mac)
#         dhcp = DHCP(options=[("message-type", "offer"), ("server_id", ip_requested), ("broadcast_address", "255.255.255.255"),
#                              ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"), ("lease_time", str(8267) + " s")]) #router - gateway :"172.16.255.254"
#         of_pack = ethernet / ip / udp / bootp / dhcp
#         sendp(of_pack)
#     elif type_message == 3:
#         #bulid acknolwedge
#         cur_ip = packet[DHCP].options[2][1]
#         alocated_dict = ip_obj.allocated_dict(cur_ip)
#         ethernet = Ether(dst=mac, src="18:60:24:8F:64:90", type=0x800)
#         #save_ip=get_requested_ip(IpQueue)
#         ip = IP(dst=cur_ip, src="172.16.20.211")  # dest_addr
#         udp = UDP(sport=Constants.src_port, dport=Constants.dest_port)
#         bootp = BOOTP(op=2, yiaddr=cur_ip, siaddr="172.16.20.211", chaddr=mac)
#         dhcp = DHCP(
#             options=[("message-type", "offer"), ("server_id", cur_ip), ("broadcast_address", "255.255.255.255"),
#                      ("router", "172.16.255.254"), ("subnet_mask", "255.255.0.0"),
#                      ("lease_time", str(8267) + " s")])  # router - gateway :"172.16.255.254"
#         of_pack1 = ethernet / ip / udp / bootp / dhcp
#         # send ack
#         sendp(of_pack1)
#
#     Index += 1
class LeaseTimeHandler:
    def __init__(self):
        self.__offer_dict__ = {}
        self.__allocated_dict__ = {}

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






def main():
    logging.basicConfig(format='%(created)f [%(levelname)s] - %(threadName)s - %(message)s')
    logging.getLogger().setLevel(logging.INFO)

    db_handler = DBHandler('localhost', "root", 'cyber', 'dhcppro')
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

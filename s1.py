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
import mysql.connector
from mysql.connector import Error

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
    RETURN_OFFER = 1
    DO_NOTHING = 0
    def __init__(self, connection):
        self.mac_address = None
        self.count = 1
        self.black_list = False #check about the connection between the tinyint and the false/true , false -> this is not an attacker
        self.time_arrivel=None
        self.id=None
        self.under_attack=False #the regular state is that you are not under an attack, if you are ->self.under_attack=True
        self.connection = connection

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

    def __is_mac_exist(self):
        my_cursor = self.connection.cursor()

        my_cursor.execute(QueryMacExist(self.mac).QUERY)
        for x in my_cursor:
            if x[QueryMacExist.MAC] == self.mac:
                return True

        return False


    def __insert_mac(self):
        # do this if this is a new mac address that doesnt exist in table!!!!!!!!!!!! need to take care about it --- very important
        # if a discover table from the same mac address is recieved -> count++
        my_cursor = self.connection.cursor()
        my_cursor.execute("INSERT INTO `discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`)" +
                          " VALUES (" + self.mac_address + "," + self.id + "," + self.time_arrivel + "," + self.count + "," + self.black_list + ");")
        # INSERT INTO `dhcppro`.`discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`) VALUES ('\"AA:BB:CC:DD:FF', '309', '12:56:45', '0', 'false');

    def __update_mac(self):
        if self.under_attack == False:  # if you are not under attack (regular state) :
            # if the mac is exist we want to check if count>=1
            my_cursor = self.connection.cursor()
            my_cursor.execute("SELECT count FROM `discovertable` WHERE `discovertable`.mac_adddress = " + mac + " ")
            if len(my_cursor) >= 1:  # mac address exist
                return True
                # now we need to send the offer message
            else:
                print("mac address does not exist in the table")
        else:  # if you are under attack (attack state) :
            my_cursor = self.connection.cursor()
            my_cursor.execute(QueryCountBlacklist(self.mac).QUERY)
            for x in my_cursor:
                count = x[QueryCountBlacklist.COUNT]
                black_list = x[QueryCountBlacklist.BLACK_LIST]
                if count >= 1:
                    if black_list == False:
                        return RETURN_OFFER  # true
                        # now we need to send the offer message
                    else:
                        return DO_NOTHING  # false
                        print("there is an attack")
        # if count>=2 and black list =false, send offer
        # if request was recieved -> this is not an intruder
        #   *create a delete function that will remove this user from the discover table
        #   return true
        # else if discover message was recieved -> this is an attacker
        #   *update the black list to be true
        #   return false
        # else if count>=2 and black list=true
        # return false

    def analyse_discover(self, discover_packet):
        self.parse(discover_packet)
        if not self.is_mac_exist():
            return self.insert_mac()
        else:
            return self.update_mac()

#* first time... till n__nice_time:(2 times) send offer... later mark as black_list


class DBHandler:
    def __init__(self, host, user, password, database):
        self.host=host
        self.user=user
        self.password=password
        self.database=database
        self.connection = None
        self.initialize()

    def initialize(self):
        self.connection = mysql.connector.connect(host=self.host, user=self.user, password=self.password)# host='localhost', user="root", password='cyber'
        my_cursor = self.connection.cursor()
        my_cursor.execute("SHOW DATABASES")
        if not 'dhcppro' in my_cursor:
            # create database and tables
            my_cursor = self.connection.cursor()
            my_cursor.execute("CREATE DATABASE dhcppro")
            my_cursor = self.connection.cursor()
            #mycursor.execute("CREATE TABLE `dhcppro`.`new_table`(`id` INT NOT NULL, `mac_address` VARCHAR(45) NULL, PRIMARY KEY(`id`));")
            #CREATE DISCOVER TABLE
            my_cursor.execute("CREATE TABLE `dhcppro`.`discovertable`(`mac_address` VARCHAR(17) NOT NULL"
                             + ",`id` INT NOT NULL,`time_arrivel` DATETIME NULL, `count` INT NULL"
                             + ",`black_list` TINYINT NULL, "
                             + "UNIQUE INDEX `mac_address_UNIQUE`(`mac_address` ASC) VISIBLE"
                             + ", UNIQUE INDEX `id_UNIQUE`(`id` ASC) VISIBLE, PRIMARY KEY(`mac_address`, `id`));")

        #reinitialize connector directly to specific db
        self.connection = mysql.connector.connect(host=self.host, user=self.user, password=self.password, database=self.database)



    def ubsert(self, discover_object):
        #insert if count=0 --> coonut=0+1=1 , update if count=1 --> count=1+1=2
        pass

    def select(self):
        pass

        # mycursor = connection.cursor()
        # mycursor.execute("SELECT * FROM dhcppro.customers")
        # myresult = mycursor.fetchall()
        #
        # for x in myresult:
        #     print(x)


        # if connection.is_connected():
        #     db_Info = connection.get_server_info()
        #     print("Connected to MySQL Server version ", db_Info)
        #     cursor = connection.cursor()
        #     cursor.execute("select database();")
        #     record = cursor.fetchone()
        #     print("You're connected to database: ", record)





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





class DHCPHandler:
    def __init__(self):
        #tables and database, and etc
        self.ip_allocator = IP_allocator(SUBNET_MASK, IP_ADRESS)
        self.leasetime_handler = LeaseTimeHandler()
        self.lease_thread = Thread(target=self.leasetime_handler.worker, args=(self.ip_allocator,))
        self.lease_thread.start()

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


def main():
    logging.basicConfig(format='%(created)f [%(levelname)s] - %(threadName)s - %(message)s')
    logging.getLogger().setLevel(logging.INFO)

    db_handler = DBHandler('localhost', "root", 'cyber', 'dhcppro')
    handler = DHCPHandler()
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

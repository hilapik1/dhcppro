import threading
from datetime import timedelta, datetime
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from file import Constants
from grafic import Creation
from threading import Thread
from DBHandler import QueryMacExist, QueryCountBlacklist, InsertToDiscoverTable


class Analyse:
    RETURN_OFFER = 0  # True
    DO_NOTHING = 1  # False
    RETURN_REQUEST = 2  # True
    RETURN_IP_TO_BANK = 3
    MARK_AS_BLACK_LIST = 4

    def __init__(self, db_handler):
        '''

               :param db_handler: that creates the connection with the database, and creates the db and its tables if don't exist.
               return: doesn't return anything, just initialize the Analayse object.
        '''
        self.mac_address = None
        self.count = 1
        self.black_list_bool = False  # check about the connection between the tinyint and the false/true , false -> this is not an attacker
        self.time_arrivel = None
        self.id = None
        self.under_attack = True  # the regular state is that you are not under an attack, if you are ->self.under_attack=True
        self.db_handler = db_handler
        self.lease_time = None
        self.subnet_mask = Constants.SUBNET_MASK
        self.expire = None
        self.ip_address = None


    def __parse(self, discover_packet):
        '''
        :param discover_packet:
        :param connection:
        :return: an discover object in order to insert the details to the discover table
        '''
        self.mac_address = self.bytes_to_str(discover_packet[BOOTP].chaddr)
        current_time = datetime.now()
        print(current_time)
        print("**********")
        # self.time_arrivel = current_time.strftime("%H:%M:%S")
        self.time_arrivel = current_time
        print("Current Time =", self.time_arrivel)

    def bytes_to_str(self, mac_addr: bytes) -> str:
        '''

        :param mac_address:
        :return: mac address in type string.
        '''
        mac_s = mac_addr[:6].hex()
        mac_addr = mac_s[:2]
        for i in range(2, len(mac_s), 2):
            mac_addr += ":"
            mac_addr += mac_s[i:i + 2]
        return mac_addr

    def is_mac_exist(self):
        '''

        :return: 0 if the mac doesn't exist in 'discovertable' in db, else return the amount of discover messages from this mac.
        '''
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(QueryMacExist(self.mac_address).QUERY)
        print("0000000000000000000")
        for x in my_cursor:
            print(x[QueryMacExist.MAC])
            print(x)
            if x[QueryMacExist.MAC] == self.mac_address:
                return x[QueryMacExist.COUNT]  # true
        print("0000000000000000000")
        return 0 #False, the mac does not exist

    def is_mac_exist_in_ack_table(self):
        '''

        :return: if the mac exists in ack table we will return True, else False.
        '''
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(f"SELECT mac_address FROM dhcppro.acktable where mac_address ='{self.mac_address}';")
        for x in my_cursor:
            print(x[0])  # x[MAC]
            print(x)
            if x[0] == self.mac_address:
                return True  # ]COUNT
        return False

    def insert_mac(self, discover_packet):
        '''

        :param discover_packet:
        :return: return 'return offer' or return 'do nothing'
        '''
        # do this if this is a new mac address that doesnt exist in table!!!!!!!!!!!! need to take care about it --- very important
        # if a discover table from the same mac address is recieved -> count++
        my_cursor = self.db_handler.get_cursor()
        query = f"INSERT INTO dhcppro.discovertable (mac_address, time_arrivel, count, black_list) VALUES ('{self.mac_address}','{self.time_arrivel}', {self.count} , {1 if self.black_list_bool else 0});"  #
        # print(query)
        # query2 = "INSERT INTO dhcppro.discovertable (mac_address, id, time_arrivel, count, black_list) VALUES ('{0}', {1}, '{2}', {3}, {4});".format(self.mac_address,self.id,self.time_arrivel,self.count,1 if self.black_list else 0)
        # query3 = "INSERT INTO dhcppro.discovertable (mac_address, id, time_arrivel, count, black_list) VALUES ('" + self.mac_address + "', " + str(self.id) + ", '" + self.time_arrivel._str_() + "', " + str(self.count) + ", " +str(1 if self.black_list else 0)
        black_list_int = 1 if self.black_list_bool else 0
        # my_cursor.execute(InsertToDiscoverTable(self.mac_address,self.time_arrivel,self.count,1 if self.black_list_bool else 0).Query)
        my_cursor.execute(query)
        connection = self.db_handler.get_connection()
        connection.commit()
        # INSERT INTO `dhcppro`.`discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`) VALUES ('\"AA:BB:CC:DD:FF', '309', '12:56:45', '0', 'false');
        if self.response_to_two_differ_states() == Analyse.RETURN_OFFER:
            # send offer
            # ------------------------------------------------------------------------------------|########################################dhcp_handler
            return Analyse.RETURN_OFFER

        else:
            return Analyse.DO_NOTHING

    # def calculate_the_range_time(self):
    #     current_time = datetime.now()
    #     # print(now)
    #     print("**********")
    #     # current_time = now.strftime("%H:%M:%S")
    #     my_cursor = self.db_handler.get_cursor()
    #     my_cursor.execute(
    #         "SELECT time_arrivel FROM `discovertable` WHERE `discovertable`.mac_adddress = " + self.mac_address)
    #     for x in my_cursor:
    #         time_arrivel = x[0]
    #     difference = (current_time - time_arrivel).total_seconds()
    #     half_lease_time = self.lease_time / 2
    #     if difference < half_lease_time:
    #         return Analyse.MARK_AS_BLACK_LIST
    #     else:
    #         return Analyse.DO_NOTHING

    # newwwwwwwwwwwww
    def response_to_two_differ_states(self):
        '''

        :return: "return offer" if this is not an attacker, else, "return ip to bank".
        '''
        # first time... till n__nice_time:(2 times) send offer... later mark as black_list
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(QueryCountBlacklist(self.mac_address).QUERY)
        for x in my_cursor:
            count = x[QueryCountBlacklist.COUNT]
            black_list = x[QueryCountBlacklist.BLACK_LIST]
            if count <= 2:
                # this is not an attacker
                # if count == 2:
                # result=self.calculate_the_range_time()
                # if result== Analyse.MARK_AS_BLACK_LIST:
                # self.mark_as_black_list()
                if black_list == 0:  # false
                    return Analyse.RETURN_OFFER  # true
                    # now we need to send the offer message
                # else:
                #     return DO_NOTHING  # false
                #     print("there is an attack")

            else:
                # this is an attacker
                my_cursor = self.db_handler.get_cursor()
                my_cursor.execute(f"UPDATE discovertable SET black_list = 1 WHERE mac_address = '{self.mac_address}'")  # black_list=true
                return Analyse.RETURN_IP_TO_BANK

        # if count>=2 and black list =false, send offer
        # if request was recieved -> this is not an intruder
        #   *create a delete function that will remove this user from the discover table
        #   return true
        # else if discover message was recieved -> this is an attacker
        #   *update the black list to be true
        #   return false
        # else if count>=2 and black list=true
        # return false

    def update_mac(self, discover_packet, count):
        '''

        :param discover_packet:
        :param count:
        :return: "return offer" or "return ip to bank"
        '''
        my_cursor = self.db_handler.get_cursor()
        count += 1
        if count <= 2:
            my_cursor.execute(f"UPDATE discovertable SET count ={count}  WHERE mac_address = '{self.mac_address}'")
            # my_cursor.execute("INSERT INTO `discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`)" +
            #                   " VALUES (" + self.mac_address + "," + self.id + "," + self.time_arrivel + "," + self.count + "," + self.black_list + ");")
        else:
            my_cursor.execute(
                f"UPDATE discovertable SET count ={count}, black_list=1  WHERE mac_address = '{self.mac_address}'")
        connection = self.db_handler.get_connection()
        connection.commit()
        return self.response_to_two_differ_states()
        # if self.response_to_two_differ_states() == Analyse.RETURN_OFFER:
        #     # send offer
        #     return Analyse.RETURN_OFFER
        # else:
        #     return Analyse.DO_NOTHING
        # ---------------------------------------------------------------------------------------

    def mark_as_black_list(self):
        '''

        :return: doesn't return anything, just mark the black list (to be 1= True) in this specific row.
        '''
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(
            f"UPDATE dhcppro.discovertable SET black_list = 1 WHERE mac_address = '{self.mac_address}';")  # black_list=true
        connection = self.db_handler.get_connection()
        connection.commit()

    def delete_from_table(self):
        '''

        :return: doesn't return anything, just delete the discover message from 'discovertable'.
        '''
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(f"DELETE FROM dhcppro.discovertable WHERE mac_address = '{self.mac_address}';")
        connection = self.db_handler.get_connection()
        connection.commit()


    def delete_from_ack_table(self, mac_address):
        '''

        :param mac_address:
        :return: doesn't return anything, just delete row from 'acktable'.
        '''
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(f"DELETE FROM dhcppro.acktable WHERE mac_address = '{mac_address}';")
        connection = self.db_handler.get_connection()
        connection.commit()

    def analyse_discover(self, discover_packet):
        '''

        :param discover_packet:
        :return: if mac doesn't exist, it will return or 'return offer', or 'do nothing'
                else, it will return or 'return offer', or 'return ip to bank'
        '''
        self.__parse(discover_packet)
        count = self.is_mac_exist()
        if count == 0: #mac doesn't exist
            return self.insert_mac(discover_packet)
        else:
            return self.update_mac(discover_packet, count)

    def analyse_request(self, request_packet):
        '''

        :param request_packet:
        :return: 'return request' if you will send a ack message, else, return "do nothing'
        '''
        self.__parse(request_packet)
        self.lease_time = Constants.LEASE_TIME
        self.ip_address = request_packet[DHCP].options[2][1]
        print(self.ip_address)
        current_time = datetime.now()
        print(current_time.time())
        self.expire = datetime.now() + timedelta(seconds=Constants.LEASE_TIME)
        print("updated time : ")
        print(self.expire)
        my_cursor = self.db_handler.get_cursor()
        print("%%%%%%%%%%%%%%%%%%%%%%%%%")
        print(self.mac_address)
        print(f"SELECT count FROM dhcppro.discovertable WHERE mac_address = '{self.mac_address}';")
        my_cursor.execute(f"SELECT count FROM dhcppro.discovertable WHERE mac_address = '{self.mac_address}';")
        print("problem!!!!!!!!!!!!!!!!!!####################################")
        for x in my_cursor:
            count = x[0]
            print("problem!!!!!!!!!!!!!!!!!!")
            print(count)
            if count <= 2: #10
                print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
                # delete from discover table, we know for sure that this is not an attacker/
                if self.is_mac_exist_in_ack_table() == False:
                    print("mac is not in table$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                    self.add_to_ack_table()
                    print("deleteeeeeeeeee")
                    self.delete_from_table()
                    print("deleteeeeeeeeee")
                else:
                    self.update_ack_table()
                # send ack
                return Analyse.RETURN_REQUEST
            else:
                print("blackkkkk listtttttttt")
                self.mark_as_black_list()
                return Analyse.DO_NOTHING

    def update_ack_table(self):
        '''

        :return: doesn't return anything, just update the ack message in 'acktable'.
        '''
        my_cursor = self.db_handler.get_cursor()
        current_time = datetime.now()
        self.expire = current_time + timedelta(seconds=Constants.LEASE_TIME)
        query = f"UPDATE acktable SET expire = '{self.expire}', time_given='{current_time}' WHERE mac_address = '{self.mac_address}';"
        my_cursor.execute(query)
        connection = self.db_handler.get_connection()
        connection.commit()
        print("##################PROBLEMMMMMMMMMM!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(query)


    def add_to_ack_table(self):
        '''

        :return: doesn't return anything, just add the ack message to 'acktable'.
        '''
        my_cursor = self.db_handler.get_cursor()
        current_time = datetime.now()
        print("macccccccccccccccccccccccccc")
        print(self.mac_address)
        print(self.subnet_mask)
        self.expire = datetime.now() + timedelta(seconds=Constants.LEASE_TIME)
        query = f"INSERT INTO dhcppro.acktable(mac_address, time_given, lease_time, ip_address, subnet_mask, expire) VALUES ('{self.mac_address}','{current_time}', {self.lease_time} , '{self.ip_address}','{self.subnet_mask}','{self.expire}');"
        # "ID", "MAC ADDRESS", "IP ADDRESS", "SUBNET MASK", "TIME GIVEN", "EXPIRE", "LEASE TIME"
        print(query)
        my_cursor.execute(query)
        connection = self.db_handler.get_connection()
        connection.commit()


# * first time... till n__nice_time:(2 times) send offer... later mark as black_list
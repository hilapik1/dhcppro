from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from s1 import QueryMacExist
from s1 import QueryCountBlacklist


class Analyse:
    RETURN_OFFER = True
    DO_NOTHING = False

    def __init__(self, db_handler):
        self.mac_address = None
        self.count = 1
        self.black_list = False  # check about the connection between the tinyint and the false/true , false -> this is not an attacker
        self.time_arrivel = None
        self.id = None
        self.under_attack = False  # the regular state is that you are not under an attack, if you are ->self.under_attack=True
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

    def insert_mac(self, discover_packet):
        # do this if this is a new mac address that doesnt exist in table!!!!!!!!!!!! need to take care about it --- very important
        # if a discover table from the same mac address is recieved -> count++
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute("INSERT INTO `discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`)" +
                          " VALUES (" + self.mac_address + "," + self.id + "," + self.time_arrivel + "," + self.count + "," + self.black_list + ");")
        # INSERT INTO `dhcppro`.`discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`) VALUES ('\"AA:BB:CC:DD:FF', '309', '12:56:45', '0', 'false');
        if self.response_to_two_differ_states() == Analyse.RETURN_OFFER:
            # send offer
            # ------------------------------------------------------------------------------------|########################################dhcp_handler
            self.dhcp_handler.handle(discover_packet)

        else:
            print("do nothing")

    def update_mac(self, discover_packet):
        my_cursor = self.db_handler.get_cursor()
        self.count += 1
        my_cursor.execute("INSERT INTO `discovertable` (`mac_address`, `id`, `time_arrivel`, `count`, `black_list`)" +
                          " VALUES (" + self.mac_address + "," + self.id + "," + self.time_arrivel + "," + self.count + "," + self.black_list + ");")
        if self.response_to_two_differ_states() == Analyse.RETURN_OFFER:
            # send offer
            self.dhcp_handler.handle(discover_packet)
        else:
            print("do nothing")
        # ---------------------------------------------------------------------------------------

    def response_to_two_differ_states(self):
        # first time... till n__nice_time:(2 times) send offer... later mark as black_list
        if self.under_attack == False:  # if you are not under attack (regular state) :
            # if the mac is exist we want to check if count>=1
            my_cursor = self.db_handler.get_cursor()
            my_cursor.execute(
                "SELECT count FROM `discovertable` WHERE `discovertable`.mac_adddress = " + self.mac_address)
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
                if count <= 2:
                    if black_list == False:
                        return Analyse.RETURN_OFFER  # true
                        # now we need to send the offer message
                    # else:
                    #     return DO_NOTHING  # false
                    #     print("there is an attack")

                else:
                    my_cursor = self.db_handler.get_cursor()
                    my_cursor.execute(
                        "UPDATE 'discovertable' SET black_list = 1 WHERE mac_address = " + self.mac_address)  # black_list=true
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

    def mark_as_black_list(self):
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute(
            "UPDATE 'discovertable' SET black_list = 1 WHERE mac_address = " + self.mac_address)  # black_list=true

    def delete_from_table(self):
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute("DELETE * FROM 'discovertable' WHERE mac_address = " + self.mac_address)

    def analyse_discover(self, discover_packet):
        self.parse(discover_packet)
        if not self.is_mac_exist():
            return self.insert_mac(discover_packet)
        else:
            return self.update_mac(discover_packet)

    def analyse_request(self,
                        request_packet):  # $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ NEW
        self.parse(request_packet)
        my_cursor = self.db_handler.get_cursor()
        my_cursor.execute("SELECT count FROM `discovertable` WHERE `discovertable`.mac_adddress = " + self.mac_address)
        for x in my_cursor:
            count = x[0]
            if count <= 2:
                # send ack
                self.dhcp_handler.handle(request_packet)
                # delete from table
                self.delete_from_table()
            else:
                self.mark_as_black_list()

# * first time... till n__nice_time:(2 times) send offer... later mark as black_list
import mysql.connector
from pip._internal.utils import logging
import configparser

class QueryMacExist:
    MAC = 0
    COUNT = 1
    QUERY = "SELECT mac_address, count FROM dhcppro.discovertable where mac_address = "

    def __init__(self, mac):
        self.QUERY = QueryMacExist.QUERY + f"'{mac}'"#"'"+mac+"'"
        print(self.QUERY)


class QueryCountBlacklist:
    COUNT = 0
    BLACK_LIST = 1
    QUERY = "SELECT count ,black_list FROM dhcppro.discovertable where mac_address = "

    def __init__(self, mac):
        self.QUERY = QueryCountBlacklist.QUERY + f"'{mac}'"


class QueryAckTableStatus:
    QUERY = "SELECT * FROM dhcppro.acktable"
    ID = 0
    MAC_ADDRESS = 1
    TIME_GIVEN = 2
    LEASE_TIME = 3
    IP_ADDRESS = 4
    SUBNET_MASK = 5
    EXPIRE = 6

    def __init__(self):
        self.QUERY = QueryAckTableStatus.QUERY



class InsertToDiscoverTable:
    #f"INSERT INTO discovertable (mac_address, time_arrivel, count, black_list) VALUES ('{self.mac_address}','{self.time_arrivel}', {self.count} , {1 if self.black_list else 0});
    QUERY="INSERT INTO discovertable (mac_address, time_arrivel, count, black_list) VALUES "#

    def __init__(self, mac_address, time_arrivel, count, black_list):
        self.QUERY = f"INSERT INTO dhcppro.discovertable (mac_address, time_arrivel, count, black_list) VALUES ('{mac_address}','{time_arrivel}', {count} , {black_list});"
        print(self.QUERY)


class DBHandler:
    def __init__(self): #, host, user, password, database
        '''

        :param host:
        :param user:
        :param password:
        :param database:
        :return does'nt return anything, initialize a DBHandler object
        '''
        config = configparser.ConfigParser()
        config.read('config.ini')
        section_proxy_items = config['Default'].items()
        list=[]
        for i in section_proxy_items:
            print (i)
            list.append(i)
        #print(section_proxy_items[0])
        self.host = list[0][1]#'hostname'
        self.user=list[1][1]#'username'
        self.password=list[2][1]#'password'
        self.database=list[3][1]#'database'
        print(self.host)
        #self.user = section_proxy_items['username']
        #self.password = section_proxy_items['password']
        #self.database = section_proxy_items['database']
        self.connection = None
        self.initialize()

    def initialize(self):
        '''

        :return: doesn't return anything, if the database we got as parameter doesn't exist in mysql, we will create one and create its tables.

        '''
        self.connection = mysql.connector.connect(host=self.host, user=self.user,
                                                  password=self.password)  # host='localhost', user="root", password='cyber'
        my_cursor = self.connection.cursor()
        my_cursor.execute("SHOW DATABASES")
        found = False
        for x in my_cursor:
            if self.database in x:
                found = True
                break

        if not found:
            # create database and tables
            my_cursor = self.connection.cursor()
            my_cursor.execute(f"CREATE DATABASE {self.database}")
            my_cursor = self.connection.cursor()
            # mycursor.execute("CREATE TABLE `dhcppro`.`new_table`(`id` INT NOT NULL, `mac_address` VARCHAR(45) NULL, PRIMARY KEY(`id`));")
            # CREATE DISCOVER TABLE
            my_cursor.execute(f"CREATE TABLE {self.database}.`discovertable`(`mac_address` VARCHAR(17) NOT NULL"
                              + ",`id` INT NOT NULL AUTO_INCREMENT,`time_arrivel` DATETIME NULL, `count` INT NULL"
                              + ",`black_list` TINYINT NULL, "
                              + "UNIQUE INDEX `mac_address_UNIQUE`(`mac_address` ASC) VISIBLE"
                              + ", UNIQUE INDEX `id_UNIQUE`(`id` ASC) VISIBLE, PRIMARY KEY(`id`));")
            print("problem")
            my_cursor = self.connection.cursor()
            my_cursor.execute(f"CREATE TABLE {self.database}.`acktable`(`id` INT NOT NULL AUTO_INCREMENT,`mac_address` VARCHAR(17) NOT NULL"
                              +",`time_given` DATETIME NULL, `lease_time` INT NULL, `ip_address` VARCHAR(12) NOT NULL"
                              +",`subnet_mask` VARCHAR(13) NOT NULL, `expire` DATETIME NULL, PRIMARY KEY (`id`), "
                              +"UNIQUE INDEX `mac_address_UNIQUE` (`mac_address` ASC) VISIBLE"
                              +", UNIQUE INDEX `ip_address_UNIQUE` (`ip_address` ASC) VISIBLE);")

        # reinitialize connector directly to specific db
        self.connection = mysql.connector.connect(host=self.host, user=self.user, password=self.password,
                                                  database=self.database)
    # def ubsert(self, discover_object):
    #     #insert if count=0 --> count=0+1=1 , update if count=1 --> count=1+1=2
    #     self.analyse.analyse_discover(discover_object)

    def clean_ack_table(self):
        # clean ack table:
        query = "delete FROM dhcppro.acktable where true;"
        my_cursor = self.connection.cursor()
        my_cursor.execute(query)
        self.connection.commit()

    def clean_discover_table(self):
        # clean discover table:
        query = "delete FROM dhcppro.discovertable where true;"
        my_cursor = self.connection.cursor()
        my_cursor.execute(query)
        self.connection.commit()

    def get_cursor(self):
        '''

        :return: the cursor of our connection
        '''
        return self.connection.cursor()

    def get_reconnect(self):
        self.connection = mysql.connector.connect(host=self.host, user=self.user, password=self.password,
                                                  database=self.database)

    def get_connection(self):
        '''

        :return: the connection between the server and mysql server
        '''
        return self.connection

    def select(self):
        pass